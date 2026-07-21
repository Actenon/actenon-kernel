"""Offline verification for receipt counter-signatures."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from actenon.models import (
    ARTIFACT_HASH_ALGORITHM,
    ARTIFACT_HASH_CANONICALIZATION,
    DigestSpec,
    PartyRef,
    SignatureSpec,
    build_artifact_digest,
)
from actenon.models.contracts import parse_timestamp
from actenon.proof.canonical import ACCEPTED_CANONICALIZATION_PROFILES, canonicalize_bytes


COUNTERSIGNATURE_CONTRACT = {
    "name": "receipt_countersignature",
    "version": "v1",
}
COUNTERSIGNATURE_CONTEXT = "actenon.receipt-countersignature.v1"
COUNTERSIGNATURE_KEY_USE = "receipt_countersignature"
_HEX_256_RE = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class CounterSignatureVerificationError(ValueError):
    """Raised when an offline receipt counter-signature cannot be verified."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerifiedCounterSignature:
    receipt_digest: DigestSpec
    witness: PartyRef
    signed_at: datetime
    key_id: str
    anchor_reference: dict[str, Any] | None = None


def _require_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CounterSignatureVerificationError(
            "INVALID_COUNTERSIGNATURE",
            f"{field_name} must be a JSON object",
        )
    return value


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise CounterSignatureVerificationError(
            "INVALID_COUNTERSIGNATURE",
            f"{field_name} must be a non-empty string",
        )
    return value


def _decode_base64url(value: str, field_name: str) -> bytes:
    if not value or _BASE64URL_RE.fullmatch(value) is None:
        raise CounterSignatureVerificationError(
            "INVALID_COUNTERSIGNATURE",
            f"{field_name} must be unpadded base64url",
        )
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value.translate(str.maketrans("-_", "+/")) + padding,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise CounterSignatureVerificationError(
            "INVALID_COUNTERSIGNATURE",
            f"{field_name} must be unpadded base64url",
        ) from exc


def _parse_digest(value: Any, field_name: str) -> DigestSpec:
    data = _require_mapping(value, field_name)
    algorithm = _require_string(data.get("algorithm"), f"{field_name}.algorithm")
    canonicalization = _require_string(
        data.get("canonicalization"),
        f"{field_name}.canonicalization",
    )
    digest_value = _require_string(data.get("value"), f"{field_name}.value")
    if (
        algorithm != ARTIFACT_HASH_ALGORITHM
        or canonicalization not in ACCEPTED_CANONICALIZATION_PROFILES
        or _HEX_256_RE.fullmatch(digest_value) is None
    ):
        raise CounterSignatureVerificationError(
            "INVALID_RECEIPT_DIGEST",
            "receipt digest must declare sha-256, a known canonicalization profile, and a lowercase 64-character hex value",
        )
    return DigestSpec(
        algorithm=algorithm,
        canonicalization=canonicalization,
        value=digest_value,
    )


def _resolve_receipt_digest(receipt_or_digest: Any) -> DigestSpec:
    if isinstance(receipt_or_digest, DigestSpec):
        return _parse_digest(receipt_or_digest.to_dict(), "receipt_or_digest")
    if hasattr(receipt_or_digest, "to_dict"):
        receipt_or_digest = receipt_or_digest.to_dict()
    data = _require_mapping(receipt_or_digest, "receipt_or_digest")
    if {"algorithm", "canonicalization", "value"}.issubset(data):
        return _parse_digest(data, "receipt_or_digest")
    contract = data.get("contract")
    if (
        not isinstance(contract, Mapping)
        or contract.get("name") != "receipt"
        or contract.get("version") != "v1"
    ):
        raise CounterSignatureVerificationError(
            "INVALID_RECEIPT_DIGEST",
            "receipt_or_digest must be a Receipt v1 artifact or a complete digest object",
        )
    try:
        return build_artifact_digest(data)
    except (TypeError, ValueError, RecursionError) as exc:
        raise CounterSignatureVerificationError(
            "INVALID_RECEIPT_DIGEST",
            "receipt could not be canonicalized for digest verification",
        ) from exc


def _parse_uses(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        uses = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        uses = tuple(value)
    else:
        uses = ()
    if not uses or any(not isinstance(item, str) or not item for item in uses):
        raise CounterSignatureVerificationError(
            "TRUSTED_KEYS_INVALID",
            "trusted key use must be a non-empty string or array of strings",
        )
    return uses


def _parse_timestamp(value: Any, field_name: str, code: str) -> datetime:
    try:
        return parse_timestamp(value, field_name)
    except ValueError as exc:
        raise CounterSignatureVerificationError(
            code,
            f"{field_name} must be an RFC3339 timestamp",
        ) from exc


def _signed_statement(
    *,
    receipt_digest: DigestSpec,
    witness: PartyRef,
    signed_at_raw: str,
    anchor_reference: Mapping[str, Any] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "context": COUNTERSIGNATURE_CONTEXT,
        "receipt_digest": receipt_digest.to_dict(),
        "witness": witness.to_dict(),
        "signed_at": signed_at_raw,
    }
    if anchor_reference is not None:
        payload["anchor_reference"] = dict(anchor_reference)
    return payload


def _select_trusted_key(
    trusted_keys: Mapping[str, Any],
    *,
    witness: PartyRef,
    signature: SignatureSpec,
    signed_at: datetime,
) -> Mapping[str, Any]:
    contract = _require_mapping(trusted_keys.get("contract"), "trusted_keys.contract")
    if contract.get("name") != "key_discovery" or contract.get("version") != "v1":
        raise CounterSignatureVerificationError(
            "TRUSTED_KEYS_INVALID",
            "trusted key set must declare key_discovery v1",
        )
    try:
        issuer = PartyRef.from_dict(trusted_keys.get("issuer"), "trusted_keys.issuer")
    except ValueError as exc:
        raise CounterSignatureVerificationError(
            "TRUSTED_KEYS_INVALID",
            "trusted key set issuer is invalid",
        ) from exc
    if (issuer.type, issuer.id) != (witness.type, witness.id):
        raise CounterSignatureVerificationError(
            "WITNESS_MISMATCH",
            "counter-signature witness does not match the trusted key-set issuer",
        )
    raw_keys = trusted_keys.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise CounterSignatureVerificationError(
            "TRUSTED_KEYS_INVALID",
            "trusted key set must contain a non-empty keys array",
        )
    matching = [
        item
        for item in raw_keys
        if isinstance(item, Mapping) and item.get("key_id") == signature.key_id
    ]
    if not matching:
        raise CounterSignatureVerificationError(
            "UNKNOWN_KEY_ID",
            f"no trusted counter-signing key matched key_id {signature.key_id!r}",
        )
    if len(matching) != 1:
        raise CounterSignatureVerificationError(
            "TRUSTED_KEYS_INVALID",
            f"trusted key set contains duplicate key_id {signature.key_id!r}",
        )
    key = matching[0]
    if key.get("algorithm") != signature.algorithm:
        raise CounterSignatureVerificationError(
            "SIGNATURE_INVALID",
            "trusted key algorithm does not match the counter-signature",
        )
    if COUNTERSIGNATURE_KEY_USE not in _parse_uses(key.get("use")):
        raise CounterSignatureVerificationError(
            "KEY_PURPOSE_MISMATCH",
            "trusted key is not authorized for receipt counter-signatures",
        )
    status = key.get("status")
    if status not in {"active", "retired"}:
        raise CounterSignatureVerificationError(
            "KEY_NOT_VALID",
            "trusted counter-signing key is not active or retired",
        )
    if key.get("not_before") is not None and signed_at < _parse_timestamp(
        key["not_before"],
        "keys[].not_before",
        "TRUSTED_KEYS_INVALID",
    ):
        raise CounterSignatureVerificationError(
            "KEY_NOT_VALID",
            "trusted counter-signing key was not valid at signing time",
        )
    if key.get("expires_at") is not None and signed_at >= _parse_timestamp(
        key["expires_at"],
        "keys[].expires_at",
        "TRUSTED_KEYS_INVALID",
    ):
        raise CounterSignatureVerificationError(
            "KEY_NOT_VALID",
            "trusted counter-signing key was expired at signing time",
        )
    if key.get("revoked_at") is not None and signed_at >= _parse_timestamp(
        key["revoked_at"],
        "keys[].revoked_at",
        "TRUSTED_KEYS_INVALID",
    ):
        raise CounterSignatureVerificationError(
            "KEY_NOT_VALID",
            "trusted counter-signing key was revoked at signing time",
        )
    return key


def _verify_ed25519(
    *,
    statement: Mapping[str, Any],
    signature: SignatureSpec,
    key: Mapping[str, Any],
) -> None:
    if signature.algorithm != "EdDSA" or signature.encoding != "base64url":
        raise CounterSignatureVerificationError(
            "UNSUPPORTED_ALGORITHM",
            "receipt counter-signature v1 verification supports EdDSA/Ed25519 with base64url encoding",
        )
    jwk = _require_mapping(key.get("public_key_jwk"), "keys[].public_key_jwk")
    if (
        jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or jwk.get("kid") not in (None, signature.key_id)
        or jwk.get("alg") not in (None, "EdDSA")
    ):
        raise CounterSignatureVerificationError(
            "TRUSTED_KEYS_INVALID",
            "counter-signing key must be an Ed25519 OKP JWK matching signature.key_id",
        )
    public_key_bytes = _decode_base64url(
        _require_string(jwk.get("x"), "public_key_jwk.x"),
        "public_key_jwk.x",
    )
    signature_bytes = _decode_base64url(signature.value, "signature.value")
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        raise CounterSignatureVerificationError(
            "SIGNATURE_INVALID",
            "counter-signature key or signature has an invalid Ed25519 length",
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise CounterSignatureVerificationError(
            "CRYPTO_BACKEND_UNAVAILABLE",
            "Ed25519 verification requires the optional 'asymmetric' package extra",
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes,
            canonicalize_bytes(dict(statement)),
        )
    except InvalidSignature as exc:
        raise CounterSignatureVerificationError(
            "SIGNATURE_INVALID",
            "receipt counter-signature could not be verified",
        ) from exc


def verify_countersignature(
    receipt_or_digest: Any,
    countersignature: Mapping[str, Any],
    trusted_keys: Mapping[str, Any],
) -> VerifiedCounterSignature:
    """Verify a receipt counter-signature offline against a pinned public key set."""

    expected_digest = _resolve_receipt_digest(receipt_or_digest)
    artifact = _require_mapping(countersignature, "countersignature")
    contract = _require_mapping(artifact.get("contract"), "countersignature.contract")
    if contract != COUNTERSIGNATURE_CONTRACT:
        raise CounterSignatureVerificationError(
            "INVALID_COUNTERSIGNATURE",
            "contract must declare receipt_countersignature v1",
        )
    observed_digest = _parse_digest(
        artifact.get("receipt_digest"),
        "countersignature.receipt_digest",
    )
    if observed_digest.value != expected_digest.value:
        raise CounterSignatureVerificationError(
            "RECEIPT_DIGEST_MISMATCH",
            "counter-signature receipt digest does not match the supplied receipt or digest",
        )
    try:
        witness = PartyRef.from_dict(artifact.get("witness"), "countersignature.witness")
        signature = SignatureSpec.from_dict(artifact.get("signature"))
    except ValueError as exc:
        raise CounterSignatureVerificationError(
            "INVALID_COUNTERSIGNATURE",
            "counter-signature witness or signature is invalid",
        ) from exc
    signed_at_raw = _require_string(
        artifact.get("signed_at"),
        "countersignature.signed_at",
    )
    signed_at = _parse_timestamp(
        signed_at_raw,
        "countersignature.signed_at",
        "INVALID_COUNTERSIGNATURE",
    )
    raw_anchor = artifact.get("anchor_reference")
    anchor_reference = (
        dict(_require_mapping(raw_anchor, "countersignature.anchor_reference"))
        if raw_anchor is not None
        else None
    )
    key = _select_trusted_key(
        _require_mapping(trusted_keys, "trusted_keys"),
        witness=witness,
        signature=signature,
        signed_at=signed_at,
    )
    statement = _signed_statement(
        receipt_digest=observed_digest,
        witness=witness,
        signed_at_raw=signed_at_raw,
        anchor_reference=anchor_reference,
    )
    _verify_ed25519(statement=statement, signature=signature, key=key)
    return VerifiedCounterSignature(
        receipt_digest=observed_digest,
        witness=witness,
        signed_at=signed_at,
        key_id=signature.key_id,
        anchor_reference=anchor_reference,
    )


__all__ = [
    "COUNTERSIGNATURE_CONTEXT",
    "COUNTERSIGNATURE_CONTRACT",
    "COUNTERSIGNATURE_KEY_USE",
    "CounterSignatureVerificationError",
    "VerifiedCounterSignature",
    "verify_countersignature",
]
