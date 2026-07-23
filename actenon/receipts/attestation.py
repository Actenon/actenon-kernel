from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping
from uuid import uuid4

from actenon.anchors import ExternalAnchorVerificationError, ExternalAnchorVerifier
from actenon.models import (
    ARTIFACT_HASH_ALGORITHM,
    ARTIFACT_HASH_CANONICALIZATION,
    PartyRef,
    Receipt,
    Refusal,
    SignatureSpec,
    canonicalize_artifact_bytes,
)
from actenon.models.contracts import JsonScalar, expect_mapping, expect_string, format_timestamp, parse_timestamp, utc_now
from actenon.proof.signing import SignatureVerifier, Signer


ATTESTATION_DIGEST_ALGORITHM = ARTIFACT_HASH_ALGORITHM
ATTESTATION_CANONICALIZATION = ARTIFACT_HASH_CANONICALIZATION
RECEIPT_ATTESTATION_CONTRACT = {"name": "receipt_attestation", "version": "v2alpha1"}
REFUSAL_ATTESTATION_CONTRACT = {"name": "refusal_attestation", "version": "v2alpha1"}


class OutcomeAttestationError(ValueError):
    """Base error for optional outcome-attestation operations."""


class OutcomeAttestationVerificationError(OutcomeAttestationError):
    """Raised when a signed outcome attestation cannot be verified."""


def _build_digest(payload: Mapping[str, Any]) -> dict[str, str]:
    try:
        canonicalize_artifact_bytes(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise OutcomeAttestationError(
            "outcome attestation canonicalization failed; the embedded artifact contains values unsupported by the current canonicalizer"
        ) from exc
    from actenon.proof import sha256_hex

    return {
        "algorithm": ATTESTATION_DIGEST_ALGORITHM,
        "value": sha256_hex(payload),
    }


def _parse_artifact_digest(raw: Any) -> dict[str, str]:
    data = expect_mapping(raw, "artifact_digest")
    algorithm = expect_string(data.get("algorithm"), "artifact_digest.algorithm")
    value = expect_string(data.get("value"), "artifact_digest.value")
    canonicalization = data.get("canonicalization")
    if canonicalization is not None and canonicalization != ATTESTATION_CANONICALIZATION:
        raise OutcomeAttestationVerificationError("outcome attestation canonicalization metadata is not supported")
    return {"algorithm": algorithm, "value": value}


def _verify_digest(*, expected_payload: Mapping[str, Any], observed_digest: Mapping[str, Any]) -> None:
    digest = _parse_artifact_digest(observed_digest)
    if digest["algorithm"] != ATTESTATION_DIGEST_ALGORITHM:
        raise OutcomeAttestationVerificationError("outcome attestation digest algorithm is not supported")
    expected_digest = _build_digest(expected_payload)
    if digest["value"] != expected_digest["value"]:
        raise OutcomeAttestationVerificationError("embedded artifact digest does not match the signed attestation payload")


def _sign_unsigned_payload(*, signer: Signer, payload: Mapping[str, Any]) -> SignatureSpec:
    try:
        canonical_payload = canonicalize_artifact_bytes(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise OutcomeAttestationError(
            "outcome attestation canonicalization failed; the unsigned payload contains values unsupported by the current canonicalizer"
        ) from exc
    return signer.sign(canonical_payload)


def _verify_unsigned_payload(
    *,
    verifier: SignatureVerifier,
    payload: Mapping[str, Any],
    signature: SignatureSpec,
    issuer: PartyRef,
    issued_at: datetime,
    external_anchor_verified: bool = False,
    external_anchor_time: datetime | None = None,
) -> None:
    try:
        canonical_payload = canonicalize_artifact_bytes(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise OutcomeAttestationVerificationError(
            "outcome attestation canonicalization failed during verification; the signed payload contains unsupported values"
        ) from exc
    verify_with_metadata = getattr(verifier, "verify_with_metadata", None)
    if callable(verify_with_metadata):
        try:
            is_valid = verify_with_metadata(
                canonical_payload,
                signature,
                issuer=issuer,
                issued_at=issued_at,
                external_anchor_verified=external_anchor_verified,
                external_anchor_time=external_anchor_time,
            )
        except TypeError:
            is_valid = verify_with_metadata(
                canonical_payload,
                signature,
                issuer=issuer,
                issued_at=issued_at,
            )
    else:
        is_valid = verifier.verify(canonical_payload, signature)
    if not is_valid:
        raise OutcomeAttestationVerificationError("outcome attestation signature could not be verified")


def _parse_mapping_dict(raw: Any, field_name: str) -> dict[str, Any]:
    return dict(expect_mapping(raw, field_name))


def _parse_optional_metadata(raw: Any) -> dict[str, JsonScalar]:
    if raw is None:
        return {}
    return dict(expect_mapping(raw, "metadata"))


def _parse_external_anchors(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("external_anchors must be an array")
    anchors: list[dict[str, Any]] = []
    for index, anchor in enumerate(raw):
        anchors.append(dict(expect_mapping(anchor, f"external_anchors[{index}]")))
    return anchors


def _verify_external_anchors(
    *,
    anchors: list[dict[str, Any]],
    artifact_digest: Mapping[str, Any],
    verifier: ExternalAnchorVerifier | None,
) -> datetime | None:
    if not anchors:
        return None
    if verifier is None:
        return None
    earliest_anchor_time: datetime | None = None
    for anchor in anchors:
        try:
            result = verifier.verify_external_anchor(
                anchor,
                artifact_digest=artifact_digest,
            )
        except ExternalAnchorVerificationError as exc:
            raise OutcomeAttestationVerificationError(
                f"external anchor verification failed: {exc}"
            ) from exc
        except ValueError:
            continue
        if earliest_anchor_time is None or result.anchored_at < earliest_anchor_time:
            earliest_anchor_time = result.anchored_at
    return earliest_anchor_time


def _normalize_proof_binding(raw: Any) -> dict[str, str | None]:
    data = expect_mapping(raw, "proof_binding")
    normalized: dict[str, str | None] = {}
    for field_name in ("intent_id", "pccb_id", "action_hash"):
        value = data.get(field_name)
        if value is None:
            normalized[field_name] = None
        else:
            normalized[field_name] = expect_string(value, f"proof_binding.{field_name}")
    return {key: value for key, value in normalized.items() if value is not None}


def _action_hash_value(raw: Any) -> str | None:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, Mapping):
        value = raw.get("value")
        return value if isinstance(value, str) else None
    return None


def _derive_proof_binding(outcome_artifact: Mapping[str, Any]) -> dict[str, str]:
    embedded_binding = outcome_artifact.get("proof_binding")
    embedded_binding_map = embedded_binding if isinstance(embedded_binding, Mapping) else {}
    correlation = outcome_artifact.get("correlation")
    correlation_map = correlation if isinstance(correlation, Mapping) else {}

    intent_id = outcome_artifact.get("intent_id") or embedded_binding_map.get("intent_id")
    pccb_id = embedded_binding_map.get("pccb_id") or correlation_map.get("pccb_id")
    action_hash = embedded_binding_map.get("action_hash") or _action_hash_value(correlation_map.get("action_hash"))

    derived: dict[str, str] = {}
    for key, value in {
        "intent_id": intent_id,
        "pccb_id": pccb_id,
        "action_hash": action_hash,
    }.items():
        if isinstance(value, str) and value:
            derived[key] = value
    return derived


def _verify_proof_binding(*, outcome_artifact: Mapping[str, Any], proof_binding: Mapping[str, str | None]) -> None:
    expected = _derive_proof_binding(outcome_artifact)
    for key in ("intent_id", "pccb_id", "action_hash"):
        observed = proof_binding.get(key)
        expected_value = expected.get(key)
        if expected_value is not None and observed != expected_value:
            raise OutcomeAttestationVerificationError(
                f"proof_binding.{key} does not match the embedded outcome artifact"
            )
        if expected_value is None and observed is not None:
            raise OutcomeAttestationVerificationError(
                f"proof_binding.{key} is not present in the embedded outcome artifact and must not be invented"
            )


def _artifact_id(outcome_artifact: Mapping[str, Any], artifact_type: str) -> str:
    if artifact_type == "receipt":
        return str(outcome_artifact.get("receipt_id", "unknown-receipt"))
    return str(outcome_artifact.get("refusal_id", "unknown-refusal"))


@dataclass(frozen=True)
class ReceiptAttestationV2Alpha1:
    attestation_id: str
    issued_at: datetime
    issuer: PartyRef
    artifact_type: str
    outcome_artifact: dict[str, Any]
    artifact_digest: dict[str, str]
    proof_binding: dict[str, str | None]
    signature: SignatureSpec
    metadata: dict[str, JsonScalar] = field(default_factory=dict)
    external_anchors: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ReceiptAttestationV2Alpha1":
        data = expect_mapping(raw, "receipt_attestation")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != RECEIPT_ATTESTATION_CONTRACT["name"] or contract.get("version") != RECEIPT_ATTESTATION_CONTRACT["version"]:
            raise ValueError("contract must declare receipt_attestation v2alpha1")
        unsigned_payload = expect_mapping(data.get("unsigned_payload"), "unsigned_payload")
        if "external_anchors" in unsigned_payload:
            raise ValueError("external_anchors must sit beside signature and must not be inside unsigned_payload")
        artifact_type = expect_string(unsigned_payload.get("artifact_type"), "unsigned_payload.artifact_type")
        if artifact_type != "receipt":
            raise ValueError("receipt attestation artifact_type must be 'receipt'")
        return cls(
            attestation_id=expect_string(unsigned_payload.get("attestation_id"), "unsigned_payload.attestation_id"),
            issued_at=parse_timestamp(unsigned_payload.get("issued_at"), "unsigned_payload.issued_at"),
            issuer=PartyRef.from_dict(unsigned_payload.get("issuer"), "unsigned_payload.issuer"),
            artifact_type=artifact_type,
            outcome_artifact=_parse_mapping_dict(unsigned_payload.get("outcome_artifact"), "unsigned_payload.outcome_artifact"),
            artifact_digest=_parse_artifact_digest(unsigned_payload.get("artifact_digest")),
            proof_binding=_normalize_proof_binding(unsigned_payload.get("proof_binding")),
            signature=SignatureSpec.from_dict(data.get("signature")),
            metadata=_parse_optional_metadata(unsigned_payload.get("metadata")),
            external_anchors=_parse_external_anchors(data.get("external_anchors", [])),
        )

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "issued_at": format_timestamp(self.issued_at),
            "issuer": self.issuer.to_dict(),
            "artifact_type": self.artifact_type,
            "artifact_digest": dict(self.artifact_digest),
            "outcome_artifact": dict(self.outcome_artifact),
            "proof_binding": {key: value for key, value in self.proof_binding.items() if value is not None},
            "metadata": dict(self.metadata),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": dict(RECEIPT_ATTESTATION_CONTRACT),
            "unsigned_payload": self.unsigned_payload(),
            "signature": self.signature.to_dict(),
            "external_anchors": list(self.external_anchors),
        }

    @property
    def receipt(self) -> Receipt:
        return Receipt.from_dict(self.outcome_artifact)

    @property
    def artifact_id(self) -> str:
        return _artifact_id(self.outcome_artifact, "receipt")


@dataclass(frozen=True)
class RefusalAttestationV2Alpha1:
    attestation_id: str
    issued_at: datetime
    issuer: PartyRef
    artifact_type: str
    outcome_artifact: dict[str, Any]
    artifact_digest: dict[str, str]
    proof_binding: dict[str, str | None]
    signature: SignatureSpec
    metadata: dict[str, JsonScalar] = field(default_factory=dict)
    external_anchors: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "RefusalAttestationV2Alpha1":
        data = expect_mapping(raw, "refusal_attestation")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != REFUSAL_ATTESTATION_CONTRACT["name"] or contract.get("version") != REFUSAL_ATTESTATION_CONTRACT["version"]:
            raise ValueError("contract must declare refusal_attestation v2alpha1")
        unsigned_payload = expect_mapping(data.get("unsigned_payload"), "unsigned_payload")
        if "external_anchors" in unsigned_payload:
            raise ValueError("external_anchors must sit beside signature and must not be inside unsigned_payload")
        artifact_type = expect_string(unsigned_payload.get("artifact_type"), "unsigned_payload.artifact_type")
        if artifact_type != "refusal":
            raise ValueError("refusal attestation artifact_type must be 'refusal'")
        return cls(
            attestation_id=expect_string(unsigned_payload.get("attestation_id"), "unsigned_payload.attestation_id"),
            issued_at=parse_timestamp(unsigned_payload.get("issued_at"), "unsigned_payload.issued_at"),
            issuer=PartyRef.from_dict(unsigned_payload.get("issuer"), "unsigned_payload.issuer"),
            artifact_type=artifact_type,
            outcome_artifact=_parse_mapping_dict(unsigned_payload.get("outcome_artifact"), "unsigned_payload.outcome_artifact"),
            artifact_digest=_parse_artifact_digest(unsigned_payload.get("artifact_digest")),
            proof_binding=_normalize_proof_binding(unsigned_payload.get("proof_binding")),
            signature=SignatureSpec.from_dict(data.get("signature")),
            metadata=_parse_optional_metadata(unsigned_payload.get("metadata")),
            external_anchors=_parse_external_anchors(data.get("external_anchors", [])),
        )

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "issued_at": format_timestamp(self.issued_at),
            "issuer": self.issuer.to_dict(),
            "artifact_type": self.artifact_type,
            "artifact_digest": dict(self.artifact_digest),
            "outcome_artifact": dict(self.outcome_artifact),
            "proof_binding": {key: value for key, value in self.proof_binding.items() if value is not None},
            "metadata": dict(self.metadata),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": dict(REFUSAL_ATTESTATION_CONTRACT),
            "unsigned_payload": self.unsigned_payload(),
            "signature": self.signature.to_dict(),
            "external_anchors": list(self.external_anchors),
        }

    @property
    def refusal(self) -> Refusal:
        return Refusal.from_dict(self.outcome_artifact)

    @property
    def artifact_id(self) -> str:
        return _artifact_id(self.outcome_artifact, "refusal")


@dataclass
class OutcomeAttestationService:
    signer: Signer
    issuer: PartyRef
    attestation_id_factory: Callable[[], str] = field(default=lambda: f"att_{uuid4().hex}")
    external_anchor_verifier: ExternalAnchorVerifier | None = None

    def attest_receipt(
        self,
        receipt: Receipt,
        *,
        issued_at: datetime | None = None,
        metadata: dict[str, JsonScalar] | None = None,
        proof_binding: dict[str, str | None] | None = None,
        external_anchors: list[dict[str, Any]] | None = None,
    ) -> ReceiptAttestationV2Alpha1:
        outcome_artifact = receipt.to_dict()
        attestation = ReceiptAttestationV2Alpha1(
            attestation_id=self.attestation_id_factory(),
            issued_at=issued_at or utc_now(),
            issuer=self.issuer,
            artifact_type="receipt",
            outcome_artifact=outcome_artifact,
            artifact_digest=_build_digest(outcome_artifact),
            proof_binding=proof_binding or _derive_proof_binding(outcome_artifact),
            signature=SignatureSpec(algorithm=self.signer.algorithm, key_id=self.signer.key_id, encoding="base64url", value="pending"),
            metadata=metadata or {},
            external_anchors=external_anchors or [],
        )
        signature = _sign_unsigned_payload(signer=self.signer, payload=attestation.unsigned_payload())
        return ReceiptAttestationV2Alpha1(
            attestation_id=attestation.attestation_id,
            issued_at=attestation.issued_at,
            issuer=attestation.issuer,
            artifact_type=attestation.artifact_type,
            outcome_artifact=attestation.outcome_artifact,
            artifact_digest=attestation.artifact_digest,
            proof_binding=attestation.proof_binding,
            signature=signature,
            metadata=attestation.metadata,
            external_anchors=attestation.external_anchors,
        )

    def attest_refusal(
        self,
        refusal: Refusal,
        *,
        issued_at: datetime | None = None,
        metadata: dict[str, JsonScalar] | None = None,
        proof_binding: dict[str, str | None] | None = None,
        external_anchors: list[dict[str, Any]] | None = None,
    ) -> RefusalAttestationV2Alpha1:
        outcome_artifact = refusal.to_dict()
        attestation = RefusalAttestationV2Alpha1(
            attestation_id=self.attestation_id_factory(),
            issued_at=issued_at or utc_now(),
            issuer=self.issuer,
            artifact_type="refusal",
            outcome_artifact=outcome_artifact,
            artifact_digest=_build_digest(outcome_artifact),
            proof_binding=proof_binding or _derive_proof_binding(outcome_artifact),
            signature=SignatureSpec(algorithm=self.signer.algorithm, key_id=self.signer.key_id, encoding="base64url", value="pending"),
            metadata=metadata or {},
            external_anchors=external_anchors or [],
        )
        signature = _sign_unsigned_payload(signer=self.signer, payload=attestation.unsigned_payload())
        return RefusalAttestationV2Alpha1(
            attestation_id=attestation.attestation_id,
            issued_at=attestation.issued_at,
            issuer=attestation.issuer,
            artifact_type=attestation.artifact_type,
            outcome_artifact=attestation.outcome_artifact,
            artifact_digest=attestation.artifact_digest,
            proof_binding=attestation.proof_binding,
            signature=signature,
            metadata=attestation.metadata,
            external_anchors=attestation.external_anchors,
        )

    def verify_receipt_attestation(
        self,
        attestation: ReceiptAttestationV2Alpha1 | Mapping[str, Any],
        *,
        verifier: SignatureVerifier | None = None,
    ) -> Receipt | dict[str, Any]:
        resolved = attestation if isinstance(attestation, ReceiptAttestationV2Alpha1) else ReceiptAttestationV2Alpha1.from_dict(attestation)
        _verify_digest(expected_payload=resolved.outcome_artifact, observed_digest=resolved.artifact_digest)
        _verify_proof_binding(outcome_artifact=resolved.outcome_artifact, proof_binding=resolved.proof_binding)
        external_anchor_time = _verify_external_anchors(
            anchors=resolved.external_anchors,
            artifact_digest=resolved.artifact_digest,
            verifier=self.external_anchor_verifier,
        )
        _verify_unsigned_payload(
            verifier=verifier or self.signer,
            payload=resolved.unsigned_payload(),
            signature=resolved.signature,
            issuer=resolved.issuer,
            issued_at=resolved.issued_at,
            external_anchor_verified=external_anchor_time is not None,
            external_anchor_time=external_anchor_time,
        )
        try:
            return resolved.receipt
        except Exception:
            return dict(resolved.outcome_artifact)

    def verify_refusal_attestation(
        self,
        attestation: RefusalAttestationV2Alpha1 | Mapping[str, Any],
        *,
        verifier: SignatureVerifier | None = None,
    ) -> Refusal | dict[str, Any]:
        resolved = attestation if isinstance(attestation, RefusalAttestationV2Alpha1) else RefusalAttestationV2Alpha1.from_dict(attestation)
        _verify_digest(expected_payload=resolved.outcome_artifact, observed_digest=resolved.artifact_digest)
        _verify_proof_binding(outcome_artifact=resolved.outcome_artifact, proof_binding=resolved.proof_binding)
        external_anchor_time = _verify_external_anchors(
            anchors=resolved.external_anchors,
            artifact_digest=resolved.artifact_digest,
            verifier=self.external_anchor_verifier,
        )
        _verify_unsigned_payload(
            verifier=verifier or self.signer,
            payload=resolved.unsigned_payload(),
            signature=resolved.signature,
            issuer=resolved.issuer,
            issued_at=resolved.issued_at,
            external_anchor_verified=external_anchor_time is not None,
            external_anchor_time=external_anchor_time,
        )
        try:
            return resolved.refusal
        except Exception:
            return dict(resolved.outcome_artifact)
