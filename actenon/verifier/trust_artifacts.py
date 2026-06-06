"""Offline verification for issuer status and exact-action approval artifacts."""

from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Sequence

from actenon.models import ActionHashSpec, ActionIntent, PartyRef, SignatureSpec
from actenon.models.contracts import parse_timestamp
from actenon.proof import build_action_hash_input, canonicalize_bytes, sha256_hex

ISSUER_STATUS_CONTEXT = "actenon.issuer-status.v1"
ISSUER_STATUS_KEY_USE = "issuer_status"
ISSUER_STATUS_CONTRACT = {"name": "issuer_status", "version": "v1"}
APPROVAL_CONTEXT = "actenon.approval-artifact.v1"
APPROVAL_KEY_USE = "approval_artifact"
APPROVAL_CONTRACT = {"name": "approval_artifact", "version": "v1"}
DEFAULT_STATUS_FRESHNESS_SECONDS = 3600
_HEX_256_RE = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_LOGGER = logging.getLogger(__name__)


class TrustArtifactVerificationError(ValueError):
    """Raised when a public trust artifact cannot be verified."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerifiedIssuerStatus:
    issuer: PartyRef
    authority: PartyRef
    status: str
    issued_at: datetime
    expires_at: datetime
    key_id: str
    status_reference: str | None = None


@dataclass(frozen=True)
class VerifiedApprovalArtifact:
    approval_id: str
    approver: PartyRef
    approval_type: str
    decision: str
    action_hash: ActionHashSpec
    issued_at: datetime
    key_id: str


def _error(code: str, message: str) -> TrustArtifactVerificationError:
    return TrustArtifactVerificationError(code, message)


def _require_mapping(value: Any, field_name: str, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(code, f"{field_name} must be a JSON object")
    return value


def _require_string(value: Any, field_name: str, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise _error(code, f"{field_name} must be a non-empty string")
    return value


def _parse_timestamp(value: Any, field_name: str, code: str) -> tuple[str, datetime]:
    raw = _require_string(value, field_name, code)
    try:
        return raw, parse_timestamp(raw, field_name)
    except ValueError as exc:
        raise _error(code, f"{field_name} must be an RFC3339 timestamp") from exc


def _parse_party(value: Any, field_name: str, code: str) -> PartyRef:
    try:
        return PartyRef.from_dict(value, field_name)
    except ValueError as exc:
        raise _error(code, f"{field_name} must identify a party") from exc


def _parse_signature(value: Any, field_name: str, code: str) -> SignatureSpec:
    try:
        return SignatureSpec.from_dict(value)
    except ValueError as exc:
        raise _error(code, f"{field_name} is invalid") from exc


def _parse_uses(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        uses = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        uses = tuple(value)
    else:
        uses = ()
    if not uses or any(not isinstance(item, str) or not item for item in uses):
        raise _error(
            "TRUSTED_KEYS_INVALID",
            "trusted key use must be a non-empty string or array of strings",
        )
    return uses


def _decode_base64url(value: str, field_name: str, code: str) -> bytes:
    if not value or _BASE64URL_RE.fullmatch(value) is None:
        raise _error(code, f"{field_name} must be unpadded base64url")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value.translate(str.maketrans("-_", "+/")) + padding,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise _error(code, f"{field_name} must be unpadded base64url") from exc


def _select_key(
    trusted_keys: Mapping[str, Any],
    *,
    signer: PartyRef,
    signature: SignatureSpec,
    signed_at: datetime,
    required_use: str,
) -> Mapping[str, Any]:
    key_set = _require_mapping(trusted_keys, "trusted_keys", "TRUSTED_KEYS_INVALID")
    contract = _require_mapping(
        key_set.get("contract"),
        "trusted_keys.contract",
        "TRUSTED_KEYS_INVALID",
    )
    if contract.get("name") != "key_discovery" or contract.get("version") != "v1":
        raise _error(
            "TRUSTED_KEYS_INVALID",
            "trusted key set must declare key_discovery v1",
        )
    key_issuer = _parse_party(
        key_set.get("issuer"),
        "trusted_keys.issuer",
        "TRUSTED_KEYS_INVALID",
    )
    if (key_issuer.type, key_issuer.id) != (signer.type, signer.id):
        raise _error(
            "SIGNER_MISMATCH",
            "artifact signer does not match the trusted key-set issuer",
        )
    raw_keys = key_set.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise _error(
            "TRUSTED_KEYS_INVALID",
            "trusted key set must contain a non-empty keys array",
        )
    matches = [
        item
        for item in raw_keys
        if isinstance(item, Mapping) and item.get("key_id") == signature.key_id
    ]
    if not matches:
        raise _error(
            "UNKNOWN_KEY_ID",
            f"no trusted key matched key_id {signature.key_id!r}",
        )
    if len(matches) != 1:
        raise _error(
            "TRUSTED_KEYS_INVALID",
            f"trusted key set contains duplicate key_id {signature.key_id!r}",
        )
    key = matches[0]
    if key.get("algorithm") != signature.algorithm:
        raise _error(
            "SIGNATURE_INVALID",
            "trusted key algorithm does not match the artifact signature",
        )
    if required_use not in _parse_uses(key.get("use")):
        raise _error(
            "KEY_PURPOSE_MISMATCH",
            f"trusted key is not authorized for {required_use}",
        )
    if key.get("status") not in {"active", "retired"}:
        raise _error("KEY_NOT_VALID", "trusted key is not active or retired")
    for field_name, inclusive, message in (
        ("not_before", False, "trusted key was not valid at signing time"),
        ("expires_at", True, "trusted key was expired at signing time"),
        ("revoked_at", True, "trusted key was revoked at signing time"),
    ):
        if key.get(field_name) is None:
            continue
        _, bound = _parse_timestamp(
            key[field_name],
            f"keys[].{field_name}",
            "TRUSTED_KEYS_INVALID",
        )
        if (not inclusive and signed_at < bound) or (inclusive and signed_at >= bound):
            raise _error("KEY_NOT_VALID", message)
    return key


def _verify_ed25519(
    *,
    statement: Mapping[str, Any],
    signature: SignatureSpec,
    key: Mapping[str, Any],
) -> None:
    if signature.algorithm != "EdDSA" or signature.encoding != "base64url":
        raise _error(
            "UNSUPPORTED_ALGORITHM",
            "trust artifact v1 supports EdDSA/Ed25519 with base64url encoding",
        )
    jwk = _require_mapping(
        key.get("public_key_jwk"),
        "keys[].public_key_jwk",
        "TRUSTED_KEYS_INVALID",
    )
    if (
        jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or jwk.get("kid") not in (None, signature.key_id)
        or jwk.get("alg") not in (None, "EdDSA")
    ):
        raise _error(
            "TRUSTED_KEYS_INVALID",
            "trusted key must be an Ed25519 OKP JWK matching signature.key_id",
        )
    public_key_bytes = _decode_base64url(
        _require_string(
            jwk.get("x"),
            "public_key_jwk.x",
            "TRUSTED_KEYS_INVALID",
        ),
        "public_key_jwk.x",
        "TRUSTED_KEYS_INVALID",
    )
    signature_bytes = _decode_base64url(
        signature.value,
        "signature.value",
        "SIGNATURE_INVALID",
    )
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        raise _error(
            "SIGNATURE_INVALID",
            "trusted key or signature has an invalid Ed25519 length",
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise _error(
            "CRYPTO_BACKEND_UNAVAILABLE",
            "Ed25519 verification requires the optional 'asymmetric' package extra",
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes,
            canonicalize_bytes(dict(statement)),
        )
    except InvalidSignature as exc:
        raise _error("SIGNATURE_INVALID", "artifact signature could not be verified") from exc


def _resolve_issuer(value: PartyRef | Mapping[str, Any]) -> PartyRef:
    if isinstance(value, PartyRef):
        return value
    return _parse_party(value, "issuer", "INVALID_ISSUER_STATUS")


def verify_issuer_status(
    issuer: PartyRef | Mapping[str, Any],
    status_artifact: Mapping[str, Any] | None,
    trusted_keys: Mapping[str, Any] | None,
    now: datetime,
    *,
    max_age_seconds: int = DEFAULT_STATUS_FRESHNESS_SECONDS,
    status_policy: Literal["required", "disabled"] = "required",
) -> VerifiedIssuerStatus | None:
    """Verify current issuer standing. The default policy fails closed."""

    if status_policy not in {"required", "disabled"}:
        raise ValueError("status_policy must be 'required' or 'disabled'")
    if status_policy == "disabled":
        _LOGGER.warning(
            "Actenon: issuer-status verification DISABLED — revoked or stale issuers may be accepted."
        )
        return None
    if status_artifact is None or trusted_keys is None:
        raise _error(
            "ISSUER_STATUS_REQUIRED",
            "high-assurance verification requires a signed issuer-status artifact",
        )
    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be positive")
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)

    expected_issuer = _resolve_issuer(issuer)
    artifact = _require_mapping(
        status_artifact,
        "status_artifact",
        "INVALID_ISSUER_STATUS",
    )
    contract = _require_mapping(
        artifact.get("contract"),
        "status_artifact.contract",
        "INVALID_ISSUER_STATUS",
    )
    if dict(contract) != ISSUER_STATUS_CONTRACT:
        raise _error(
            "INVALID_ISSUER_STATUS",
            "contract must declare issuer_status v1",
        )
    observed_issuer = _parse_party(
        artifact.get("issuer"),
        "status_artifact.issuer",
        "INVALID_ISSUER_STATUS",
    )
    if (observed_issuer.type, observed_issuer.id) != (
        expected_issuer.type,
        expected_issuer.id,
    ):
        raise _error(
            "ISSUER_MISMATCH",
            "issuer-status artifact does not describe the expected issuer",
        )
    authority = _parse_party(
        artifact.get("authority"),
        "status_artifact.authority",
        "INVALID_ISSUER_STATUS",
    )
    status = _require_string(
        artifact.get("status"),
        "status_artifact.status",
        "INVALID_ISSUER_STATUS",
    )
    if status not in {"good_standing", "suspended", "revoked"}:
        raise _error(
            "INVALID_ISSUER_STATUS",
            "issuer status must be good_standing, suspended, or revoked",
        )
    issued_at_raw, issued_at = _parse_timestamp(
        artifact.get("issued_at"),
        "status_artifact.issued_at",
        "INVALID_ISSUER_STATUS",
    )
    expires_at_raw, expires_at = _parse_timestamp(
        artifact.get("expires_at"),
        "status_artifact.expires_at",
        "INVALID_ISSUER_STATUS",
    )
    if expires_at <= issued_at:
        raise _error(
            "INVALID_ISSUER_STATUS",
            "issuer-status expiry must be after issuance",
        )
    if now < issued_at:
        raise _error("ISSUER_STATUS_NOT_YET_VALID", "issuer status is not yet valid")
    if now >= expires_at:
        raise _error("ISSUER_STATUS_EXPIRED", "issuer status has expired")
    if (now - issued_at).total_seconds() > max_age_seconds:
        raise _error(
            "ISSUER_STATUS_STALE",
            "issuer status exceeds the configured freshness window",
        )
    status_reference = artifact.get("status_reference")
    if status_reference is not None:
        status_reference = _require_string(
            status_reference,
            "status_artifact.status_reference",
            "INVALID_ISSUER_STATUS",
        )
    signature = _parse_signature(
        artifact.get("signature"),
        "status_artifact.signature",
        "INVALID_ISSUER_STATUS",
    )
    key = _select_key(
        trusted_keys,
        signer=authority,
        signature=signature,
        signed_at=issued_at,
        required_use=ISSUER_STATUS_KEY_USE,
    )
    statement: dict[str, Any] = {
        "context": ISSUER_STATUS_CONTEXT,
        "issuer": observed_issuer.to_dict(),
        "authority": authority.to_dict(),
        "status": status,
        "issued_at": issued_at_raw,
        "expires_at": expires_at_raw,
    }
    if status_reference is not None:
        statement["status_reference"] = status_reference
    _verify_ed25519(statement=statement, signature=signature, key=key)
    if status == "revoked":
        raise _error("ISSUER_REVOKED", "issuer status is revoked")
    if status == "suspended":
        raise _error("ISSUER_SUSPENDED", "issuer status is suspended")
    return VerifiedIssuerStatus(
        issuer=observed_issuer,
        authority=authority,
        status=status,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=signature.key_id,
        status_reference=status_reference,
    )


def _parse_action_hash(value: Any) -> ActionHashSpec:
    try:
        action_hash = ActionHashSpec.from_dict(value)
    except ValueError as exc:
        raise _error(
            "INVALID_APPROVAL_ARTIFACT",
            "approval action_hash is invalid",
        ) from exc
    if (
        action_hash.algorithm != "sha-256"
        or action_hash.canonicalization != "RFC8785-JCS"
        or _HEX_256_RE.fullmatch(action_hash.value) is None
    ):
        raise _error(
            "INVALID_APPROVAL_ARTIFACT",
            "approval action_hash must declare sha-256, RFC8785-JCS, and lowercase hex",
        )
    return action_hash


def _resolve_expected_action_hash(
    value: ActionIntent | ActionHashSpec | Mapping[str, Any],
) -> ActionHashSpec:
    if isinstance(value, ActionHashSpec):
        return _parse_action_hash(value.to_dict())
    if isinstance(value, ActionIntent):
        return ActionHashSpec(
            algorithm="sha-256",
            canonicalization="RFC8785-JCS",
            value=sha256_hex(build_action_hash_input(value)),
        )
    if {"algorithm", "canonicalization", "value"}.issubset(value):
        return _parse_action_hash(value)
    try:
        intent = ActionIntent.from_dict(value)
    except ValueError as exc:
        raise _error(
            "INVALID_APPROVAL_ARTIFACT",
            "expected_action must be an Action Intent or action hash",
        ) from exc
    return _resolve_expected_action_hash(intent)


def verify_approval_artifact(
    approval: Mapping[str, Any],
    trusted_keys: Mapping[str, Any],
    *,
    expected_action: ActionIntent | ActionHashSpec | Mapping[str, Any] | None = None,
) -> VerifiedApprovalArtifact:
    """Verify an approver signature and optional exact-action binding."""

    artifact = _require_mapping(
        approval,
        "approval",
        "INVALID_APPROVAL_ARTIFACT",
    )
    contract = _require_mapping(
        artifact.get("contract"),
        "approval.contract",
        "INVALID_APPROVAL_ARTIFACT",
    )
    if dict(contract) != APPROVAL_CONTRACT:
        raise _error(
            "INVALID_APPROVAL_ARTIFACT",
            "contract must declare approval_artifact v1",
        )
    approval_id = _require_string(
        artifact.get("approval_id"),
        "approval.approval_id",
        "INVALID_APPROVAL_ARTIFACT",
    )
    approver = _parse_party(
        artifact.get("approver"),
        "approval.approver",
        "INVALID_APPROVAL_ARTIFACT",
    )
    approval_type = _require_string(
        artifact.get("approval_type"),
        "approval.approval_type",
        "INVALID_APPROVAL_ARTIFACT",
    )
    decision = _require_string(
        artifact.get("decision"),
        "approval.decision",
        "INVALID_APPROVAL_ARTIFACT",
    )
    if decision != "approved":
        raise _error(
            "APPROVAL_NOT_GRANTED",
            "approval artifact decision is not approved",
        )
    action_hash = _parse_action_hash(artifact.get("action_hash"))
    if expected_action is not None:
        expected_hash = _resolve_expected_action_hash(expected_action)
        if action_hash != expected_hash:
            raise _error(
                "APPROVAL_ACTION_MISMATCH",
                "approval artifact is not bound to the expected action",
            )
    issued_at_raw, issued_at = _parse_timestamp(
        artifact.get("issued_at"),
        "approval.issued_at",
        "INVALID_APPROVAL_ARTIFACT",
    )
    signature = _parse_signature(
        artifact.get("signature"),
        "approval.signature",
        "INVALID_APPROVAL_ARTIFACT",
    )
    key = _select_key(
        trusted_keys,
        signer=approver,
        signature=signature,
        signed_at=issued_at,
        required_use=APPROVAL_KEY_USE,
    )
    statement = {
        "context": APPROVAL_CONTEXT,
        "approval_id": approval_id,
        "approver": approver.to_dict(),
        "approval_type": approval_type,
        "decision": decision,
        "action_hash": action_hash.to_dict(),
        "issued_at": issued_at_raw,
    }
    _verify_ed25519(statement=statement, signature=signature, key=key)
    return VerifiedApprovalArtifact(
        approval_id=approval_id,
        approver=approver,
        approval_type=approval_type,
        decision=decision,
        action_hash=action_hash,
        issued_at=issued_at,
        key_id=signature.key_id,
    )


__all__ = [
    "APPROVAL_CONTEXT",
    "APPROVAL_CONTRACT",
    "APPROVAL_KEY_USE",
    "DEFAULT_STATUS_FRESHNESS_SECONDS",
    "ISSUER_STATUS_CONTEXT",
    "ISSUER_STATUS_CONTRACT",
    "ISSUER_STATUS_KEY_USE",
    "TrustArtifactVerificationError",
    "VerifiedApprovalArtifact",
    "VerifiedIssuerStatus",
    "verify_approval_artifact",
    "verify_issuer_status",
]
