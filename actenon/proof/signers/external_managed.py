from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping, Protocol

from actenon.models.contracts import SignatureSpec

from .base import b64url_decode, b64url_encode


EXTERNAL_MANAGED_BACKEND = "external_managed"
DEVELOPMENT_LOCAL_HMAC_BACKEND = "development_local_hmac"
PILOT_LOCAL_EDDSA_BACKEND = "pilot_local_eddsa"

ACTENON_ENV_ENV = "ACTENON_ENV"
ACTENON_ALLOW_PILOT_EDDSA_IN_PRODUCTION_ENV = "ACTENON_ALLOW_PILOT_LOCAL_EDDSA_IN_PRODUCTION"

PROOF_ISSUANCE_PURPOSE = "proof_issuance"
OUTCOME_ATTESTATION_PURPOSE = "outcome_attestation"
ALLOWED_KEY_PURPOSES = frozenset({PROOF_ISSUANCE_PURPOSE, OUTCOME_ATTESTATION_PURPOSE})

ACTIVE_KEY_STATUS = "active"
BLOCKED_KEY_STATUSES = frozenset({"suspended", "revoked", "hard_revoked", "disabled", "deleted", "unknown"})
PRODUCTION_ENV_VALUES = frozenset({"prod", "production", "staging", "release", "ci", "non-dev", "nondev"})
PRODUCTION_FLAG_ENVS = (
    "ACTENON_PRODUCTION",
    "ACTENON_CI_RELEASE",
    "ACTENON_RELEASE_BUILD",
)


class ProductionSigningGuardError(RuntimeError):
    """Raised when a non-production signing backend is selected for production."""


class ExternalManagedSigningError(RuntimeError):
    """Raised when an external-managed signing operation cannot safely proceed."""


@dataclass(frozen=True)
class ManagedKeyReference:
    """Provider-neutral reference to a non-exportable managed signing key."""

    provider: str
    provider_key_ref: str
    key_id: str
    algorithm: str
    purpose: str
    tenant_id: str | None = None
    public_key_ref: str | None = None
    key_version: str | None = None
    status: str = ACTIVE_KEY_STATUS


@dataclass(frozen=True)
class ManagedSigningAuditMetadata:
    """Non-secret audit context for a managed signing operation."""

    operation_id: str
    purpose: str
    tenant_id: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    actor_id: str | None = None
    payload_digest: str | None = None
    extra: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation_id": self.operation_id,
            "purpose": self.purpose,
        }
        for key, value in (
            ("tenant_id", self.tenant_id),
            ("request_id", self.request_id),
            ("correlation_id", self.correlation_id),
            ("actor_id", self.actor_id),
            ("payload_digest", self.payload_digest),
        ):
            if value is not None:
                payload[key] = value
        if self.extra:
            payload["extra"] = dict(self.extra)
        return payload


@dataclass(frozen=True)
class ManagedSigningResult:
    """Provider-neutral result of signing canonical bytes with a managed key."""

    algorithm: str
    key_id: str
    signature: bytes
    public_key_ref: str
    provider_operation_id: str | None = None

    def to_signature_spec(self) -> SignatureSpec:
        return SignatureSpec(
            algorithm=self.algorithm,
            key_id=self.key_id,
            encoding="base64url",
            value=b64url_encode(self.signature),
        )


class ExternalManagedSigningBackend(Protocol):
    """Provider-neutral backend for non-exportable managed signing keys."""

    def get_key_status(self, *, key: ManagedKeyReference) -> str:
        """Return the current provider/local lifecycle status for the key."""

    def sign_canonical_bytes(
        self,
        *,
        key: ManagedKeyReference,
        payload: bytes,
        audit_metadata: Mapping[str, object],
    ) -> ManagedSigningResult:
        """Sign canonical bytes without exporting private key material."""

    def verify_canonical_bytes(
        self,
        *,
        key: ManagedKeyReference,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        """Return True when the managed public key verifies the signature."""


def _truthy(raw: str | None) -> bool:
    return raw is not None and raw.strip().lower() in {"1", "true", "yes", "on"}


def is_production_like_environment(environment: Mapping[str, str] | None = None) -> bool:
    env = environment if environment is not None else os.environ
    normalized = env.get(ACTENON_ENV_ENV, "").strip().lower()
    return normalized in PRODUCTION_ENV_VALUES or any(_truthy(env.get(name)) for name in PRODUCTION_FLAG_ENVS)


def _pilot_eddsa_override_enabled(environment: Mapping[str, str] | None = None) -> bool:
    env = environment if environment is not None else os.environ
    return _truthy(env.get(ACTENON_ALLOW_PILOT_EDDSA_IN_PRODUCTION_ENV))


def validate_signing_backend_for_environment(
    backend: str,
    *,
    environment: Mapping[str, str] | None = None,
    production: bool | None = None,
) -> None:
    """Fail closed when a non-production backend is selected for production."""

    backend_value = backend.strip().lower()
    production_mode = is_production_like_environment(environment) if production is None else production
    if not production_mode:
        return
    if backend_value == EXTERNAL_MANAGED_BACKEND:
        return
    if backend_value == DEVELOPMENT_LOCAL_HMAC_BACKEND:
        raise ProductionSigningGuardError(
            "development_local_hmac is disabled in production. "
            "Production proof issuance requires non-exportable asymmetric KMS/HSM custody through external_managed."
        )
    if backend_value == PILOT_LOCAL_EDDSA_BACKEND and not _pilot_eddsa_override_enabled(environment):
        raise ProductionSigningGuardError(
            "pilot_local_eddsa is disabled in production. "
            "Use external_managed KMS/HSM custody, or set "
            "ACTENON_ALLOW_PILOT_LOCAL_EDDSA_IN_PRODUCTION=1 only for an explicitly unsafe emergency/demo override."
        )
    if backend_value != PILOT_LOCAL_EDDSA_BACKEND:
        raise ProductionSigningGuardError(
            f"unknown signing backend {backend!r} cannot be used in production. "
            "Production proof issuance requires external_managed KMS/HSM custody."
        )


@dataclass(frozen=True)
class ExternalManagedSigner:
    """Signer adapter for provider-managed non-exportable asymmetric keys."""

    backend: ExternalManagedSigningBackend
    key: ManagedKeyReference
    required_purpose: str = PROOF_ISSUANCE_PURPOSE
    audit_metadata: ManagedSigningAuditMetadata | None = None

    @property
    def algorithm(self) -> str:
        return self.key.algorithm

    @property
    def key_id(self) -> str:
        return self.key.key_id

    @property
    def public_key_ref(self) -> str | None:
        return self.key.public_key_ref

    def _ensure_key_can_sign(self) -> None:
        if self.key.purpose not in ALLOWED_KEY_PURPOSES:
            raise ExternalManagedSigningError(f"unsupported managed signing key purpose: {self.key.purpose}")
        if self.key.purpose != self.required_purpose:
            raise ExternalManagedSigningError(
                f"managed signing key purpose mismatch: required {self.required_purpose}, got {self.key.purpose}"
            )
        local_status = self.key.status.strip().lower()
        provider_status = self.backend.get_key_status(key=self.key).strip().lower()
        if local_status != ACTIVE_KEY_STATUS:
            raise ExternalManagedSigningError(f"managed signing key is not active: {self.key.status}")
        if provider_status != ACTIVE_KEY_STATUS:
            raise ExternalManagedSigningError(
                f"managed signing provider reports non-active key status: {provider_status}"
            )
        if local_status in BLOCKED_KEY_STATUSES or provider_status in BLOCKED_KEY_STATUSES:
            raise ExternalManagedSigningError("managed signing key is suspended, revoked, or unavailable")

    def sign_managed(self, payload: bytes) -> ManagedSigningResult:
        self._ensure_key_can_sign()
        audit_metadata = self.audit_metadata or ManagedSigningAuditMetadata(
            operation_id="external-managed-signing-operation",
            purpose=self.required_purpose,
            tenant_id=self.key.tenant_id,
        )
        result = self.backend.sign_canonical_bytes(
            key=self.key,
            payload=payload,
            audit_metadata=audit_metadata.to_dict(),
        )
        if result.algorithm != self.algorithm or result.key_id != self.key_id:
            raise ExternalManagedSigningError("managed signing backend returned mismatched algorithm or key id")
        if not result.signature:
            raise ExternalManagedSigningError("managed signing backend returned an empty signature")
        if not result.public_key_ref:
            raise ExternalManagedSigningError("managed signing backend did not return a public key reference")
        return result

    def sign(self, payload: bytes) -> SignatureSpec:
        return self.sign_managed(payload).to_signature_spec()

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        if (
            signature.algorithm != self.algorithm
            or signature.key_id != self.key_id
            or signature.encoding != "base64url"
        ):
            return False
        try:
            raw_signature = b64url_decode(signature.value)
        except (TypeError, ValueError):
            return False
        return self.backend.verify_canonical_bytes(key=self.key, payload=payload, signature=raw_signature)
