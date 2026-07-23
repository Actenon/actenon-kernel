"""Offline verification for transparency-log proofs and checkpoints."""

from __future__ import annotations

import base64
import binascii
import hashlib
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
)
from actenon.models.contracts import parse_timestamp
from actenon.proof.canonical import ACCEPTED_CANONICALIZATION_PROFILES, canonicalize_bytes


CHECKPOINT_CONTEXT = "actenon.transparency-checkpoint.v1"
CHECKPOINT_KEY_USE = "transparency_checkpoint"
CHECKPOINT_CONTRACT = {"name": "transparency_checkpoint", "version": "v1"}
INCLUSION_PROOF_CONTRACT = {
    "name": "transparency_inclusion_proof",
    "version": "v1",
}
CONSISTENCY_PROOF_CONTRACT = {
    "name": "transparency_consistency_proof",
    "version": "v1",
}
_HEX_256_RE = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class TransparencyVerificationError(ValueError):
    """Raised when an offline transparency-log verification fails."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerifiedCheckpoint:
    log: PartyRef
    tree_size: int
    root_hash: str
    issued_at: datetime
    key_id: str


@dataclass(frozen=True)
class VerifiedInclusion:
    log_id: str
    tree_size: int
    leaf_index: int
    leaf_digest: DigestSpec
    checkpoint: VerifiedCheckpoint | None = None


@dataclass(frozen=True)
class VerifiedConsistency:
    log_id: str
    old_tree_size: int
    new_tree_size: int


@dataclass(frozen=True)
class VerifiedMonitorUpdate:
    previous: VerifiedCheckpoint
    current: VerifiedCheckpoint
    consistency: VerifiedConsistency


def _error(code: str, message: str) -> TransparencyVerificationError:
    return TransparencyVerificationError(code, message)


def _require_mapping(value: Any, field_name: str, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(code, f"{field_name} must be a JSON object")
    return value


def _require_string(value: Any, field_name: str, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise _error(code, f"{field_name} must be a non-empty string")
    return value


def _require_nonnegative_int(value: Any, field_name: str, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _error(code, f"{field_name} must be a non-negative integer")
    return value


def _parse_hex_hash(value: Any, field_name: str, code: str) -> bytes:
    raw = _require_string(value, field_name, code)
    if _HEX_256_RE.fullmatch(raw) is None:
        raise _error(code, f"{field_name} must be a lowercase 64-character SHA-256 hex value")
    return bytes.fromhex(raw)


def _parse_digest(value: Any, field_name: str) -> DigestSpec:
    data = _require_mapping(value, field_name, "INVALID_LEAF_DIGEST")
    algorithm = _require_string(
        data.get("algorithm"),
        f"{field_name}.algorithm",
        "INVALID_LEAF_DIGEST",
    )
    canonicalization = _require_string(
        data.get("canonicalization"),
        f"{field_name}.canonicalization",
        "INVALID_LEAF_DIGEST",
    )
    digest_value = _require_string(
        data.get("value"),
        f"{field_name}.value",
        "INVALID_LEAF_DIGEST",
    )
    if (
        algorithm != ARTIFACT_HASH_ALGORITHM
        or canonicalization not in ACCEPTED_CANONICALIZATION_PROFILES
        or _HEX_256_RE.fullmatch(digest_value) is None
    ):
        raise _error(
            "INVALID_LEAF_DIGEST",
            "leaf digest must declare sha-256, a known canonicalization profile, and a lowercase 64-character hex value",
        )
    return DigestSpec(
        algorithm=algorithm,
        canonicalization=canonicalization,
        value=digest_value,
    )


def _resolve_digest(value: Any) -> DigestSpec:
    if isinstance(value, DigestSpec):
        return _parse_digest(value.to_dict(), "digest")
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return _parse_digest(value, "digest")


def _parse_hash_spec(value: Any, field_name: str, code: str) -> bytes:
    data = _require_mapping(value, field_name, code)
    if data.get("algorithm") != "sha-256" or data.get("encoding") != "hex":
        raise _error(code, f"{field_name} must declare sha-256 with hex encoding")
    return _parse_hex_hash(data.get("value"), f"{field_name}.value", code)


def _parse_hash_path(value: Any, field_name: str, code: str) -> tuple[bytes, ...]:
    if not isinstance(value, list):
        raise _error(code, f"{field_name} must be an array")
    return tuple(
        _parse_hex_hash(item, f"{field_name}[{index}]", code)
        for index, item in enumerate(value)
    )


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


def _parse_timestamp(value: Any, field_name: str, code: str) -> datetime:
    try:
        return parse_timestamp(value, field_name)
    except ValueError as exc:
        raise _error(code, f"{field_name} must be an RFC3339 timestamp") from exc


def _leaf_hash(digest: DigestSpec) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(digest.value)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _parse_checkpoint(
    checkpoint: Mapping[str, Any],
) -> tuple[PartyRef, int, bytes, str, datetime, SignatureSpec]:
    contract = _require_mapping(
        checkpoint.get("contract"),
        "checkpoint.contract",
        "INVALID_CHECKPOINT",
    )
    if dict(contract) != CHECKPOINT_CONTRACT:
        raise _error(
            "INVALID_CHECKPOINT",
            "checkpoint contract must declare transparency_checkpoint v1",
        )
    try:
        log = PartyRef.from_dict(checkpoint.get("log"), "checkpoint.log")
        signature = SignatureSpec.from_dict(checkpoint.get("signature"))
    except ValueError as exc:
        raise _error(
            "INVALID_CHECKPOINT",
            "checkpoint log or signature is invalid",
        ) from exc
    tree_size = _require_nonnegative_int(
        checkpoint.get("tree_size"),
        "checkpoint.tree_size",
        "INVALID_CHECKPOINT",
    )
    root_hash = _parse_hash_spec(
        checkpoint.get("root_hash"),
        "checkpoint.root_hash",
        "INVALID_CHECKPOINT",
    )
    issued_at_raw = _require_string(
        checkpoint.get("issued_at"),
        "checkpoint.issued_at",
        "INVALID_CHECKPOINT",
    )
    issued_at = _parse_timestamp(
        issued_at_raw,
        "checkpoint.issued_at",
        "INVALID_CHECKPOINT",
    )
    return log, tree_size, root_hash, issued_at_raw, issued_at, signature


def _checkpoint_statement(
    *,
    log: PartyRef,
    tree_size: int,
    root_hash: bytes,
    issued_at_raw: str,
) -> dict[str, Any]:
    return {
        "context": CHECKPOINT_CONTEXT,
        "log": log.to_dict(),
        "tree_size": tree_size,
        "root_hash": {
            "algorithm": "sha-256",
            "encoding": "hex",
            "value": root_hash.hex(),
        },
        "issued_at": issued_at_raw,
    }


def _select_checkpoint_key(
    trusted_keys: Mapping[str, Any],
    *,
    log: PartyRef,
    signature: SignatureSpec,
    issued_at: datetime,
) -> Mapping[str, Any]:
    contract = _require_mapping(
        trusted_keys.get("contract"),
        "trusted_keys.contract",
        "TRUSTED_KEYS_INVALID",
    )
    if contract.get("name") != "key_discovery" or contract.get("version") != "v1":
        raise _error(
            "TRUSTED_KEYS_INVALID",
            "trusted key set must declare key_discovery v1",
        )
    try:
        issuer = PartyRef.from_dict(trusted_keys.get("issuer"), "trusted_keys.issuer")
    except ValueError as exc:
        raise _error("TRUSTED_KEYS_INVALID", "trusted key-set issuer is invalid") from exc
    if (issuer.type, issuer.id) != (log.type, log.id):
        raise _error(
            "LOG_IDENTITY_MISMATCH",
            "checkpoint log identity does not match the trusted key-set issuer",
        )
    raw_keys = trusted_keys.get("keys")
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
            f"no trusted checkpoint key matched key_id {signature.key_id!r}",
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
            "trusted key algorithm does not match the checkpoint signature",
        )
    if CHECKPOINT_KEY_USE not in _parse_uses(key.get("use")):
        raise _error(
            "KEY_PURPOSE_MISMATCH",
            "trusted key is not authorized for transparency checkpoints",
        )
    if key.get("status") not in {"active", "retired"}:
        raise _error(
            "KEY_NOT_VALID",
            "trusted checkpoint key is not active or retired",
        )
    for field_name, inclusive, message in (
        ("not_before", False, "trusted checkpoint key was not valid at signing time"),
        ("expires_at", True, "trusted checkpoint key was expired at signing time"),
        ("revoked_at", True, "trusted checkpoint key was revoked at signing time"),
    ):
        if key.get(field_name) is None:
            continue
        bound = _parse_timestamp(
            key[field_name],
            f"keys[].{field_name}",
            "TRUSTED_KEYS_INVALID",
        )
        if (not inclusive and issued_at < bound) or (inclusive and issued_at >= bound):
            raise _error("KEY_NOT_VALID", message)
    return key


def verify_checkpoint_signature(
    checkpoint: Mapping[str, Any],
    trusted_keys: Mapping[str, Any],
) -> VerifiedCheckpoint:
    """Verify a signed transparency checkpoint against pinned public keys."""

    log, tree_size, root_hash, issued_at_raw, issued_at, signature = _parse_checkpoint(
        checkpoint
    )
    if signature.algorithm != "EdDSA" or signature.encoding != "base64url":
        raise _error(
            "UNSUPPORTED_ALGORITHM",
            "transparency checkpoint v1 supports EdDSA/Ed25519 with base64url encoding",
        )
    key = _select_checkpoint_key(
        trusted_keys,
        log=log,
        signature=signature,
        issued_at=issued_at,
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
            "checkpoint key must be an Ed25519 OKP JWK matching signature.key_id",
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
        "checkpoint.signature.value",
        "SIGNATURE_INVALID",
    )
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        raise _error(
            "SIGNATURE_INVALID",
            "checkpoint key or signature has an invalid Ed25519 length",
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise _error(
            "CRYPTO_BACKEND_UNAVAILABLE",
            "Ed25519 verification requires the optional 'asymmetric' package extra",
        ) from exc
    statement = _checkpoint_statement(
        log=log,
        tree_size=tree_size,
        root_hash=root_hash,
        issued_at_raw=issued_at_raw,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes,
            canonicalize_bytes(statement),
        )
    except InvalidSignature as exc:
        raise _error(
            "SIGNATURE_INVALID",
            "transparency checkpoint signature could not be verified",
        ) from exc
    return VerifiedCheckpoint(
        log=log,
        tree_size=tree_size,
        root_hash=root_hash.hex(),
        issued_at=issued_at,
        key_id=signature.key_id,
    )


def verify_inclusion(
    digest: Any,
    inclusion_proof: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
) -> VerifiedInclusion:
    """Verify RFC 6962-style inclusion of an artifact digest in a checkpoint."""

    expected_digest = _resolve_digest(digest)
    proof = _require_mapping(
        inclusion_proof,
        "inclusion_proof",
        "INVALID_INCLUSION_PROOF",
    )
    contract = _require_mapping(
        proof.get("contract"),
        "inclusion_proof.contract",
        "INVALID_INCLUSION_PROOF",
    )
    if dict(contract) != INCLUSION_PROOF_CONTRACT:
        raise _error(
            "INVALID_INCLUSION_PROOF",
            "proof contract must declare transparency_inclusion_proof v1",
        )
    if proof.get("hash_algorithm") != "sha-256":
        raise _error(
            "INVALID_INCLUSION_PROOF",
            "inclusion proof hash_algorithm must be sha-256",
        )
    observed_digest = _parse_digest(
        proof.get("leaf_digest"),
        "inclusion_proof.leaf_digest",
    )
    if observed_digest != expected_digest:
        raise _error(
            "LEAF_DIGEST_MISMATCH",
            "inclusion proof leaf digest does not match the supplied digest",
        )
    log_id = _require_string(
        proof.get("log_id"),
        "inclusion_proof.log_id",
        "INVALID_INCLUSION_PROOF",
    )
    tree_size = _require_nonnegative_int(
        proof.get("tree_size"),
        "inclusion_proof.tree_size",
        "INVALID_INCLUSION_PROOF",
    )
    leaf_index = _require_nonnegative_int(
        proof.get("leaf_index"),
        "inclusion_proof.leaf_index",
        "INVALID_INCLUSION_PROOF",
    )
    if tree_size == 0 or leaf_index >= tree_size:
        raise _error(
            "INVALID_INCLUSION_PROOF",
            "leaf_index must identify a leaf within the non-empty proof tree",
        )
    audit_path = _parse_hash_path(
        proof.get("audit_path"),
        "inclusion_proof.audit_path",
        "INVALID_INCLUSION_PROOF",
    )
    checkpoint_log, checkpoint_size, checkpoint_root, _, _, _ = _parse_checkpoint(
        checkpoint
    )
    if checkpoint_log.id != log_id or checkpoint_size != tree_size:
        raise _error(
            "CHECKPOINT_MISMATCH",
            "inclusion proof log or tree size does not match the checkpoint",
        )

    node = _leaf_hash(expected_digest)
    fn = leaf_index
    sn = tree_size - 1
    for sibling in audit_path:
        if fn & 1 or fn == sn:
            node = _node_hash(sibling, node)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            node = _node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0 or node != checkpoint_root:
        raise _error(
            "INCLUSION_PROOF_INVALID",
            "digest is not included in the supplied checkpoint",
        )
    return VerifiedInclusion(
        log_id=log_id,
        tree_size=tree_size,
        leaf_index=leaf_index,
        leaf_digest=expected_digest,
    )


def verify_consistency(
    old_checkpoint: Mapping[str, Any],
    new_checkpoint: Mapping[str, Any],
    consistency_proof: Mapping[str, Any],
) -> VerifiedConsistency:
    """Verify append-only consistency between two transparency checkpoints."""

    old_log, old_size, old_root, _, _, _ = _parse_checkpoint(old_checkpoint)
    new_log, new_size, new_root, _, _, _ = _parse_checkpoint(new_checkpoint)
    if (old_log.type, old_log.id) != (new_log.type, new_log.id):
        raise _error(
            "LOG_IDENTITY_MISMATCH",
            "consistency checkpoints identify different logs",
        )
    if new_size < old_size:
        raise _error(
            "REWIND_DETECTED",
            "new checkpoint tree size is smaller than the previous checkpoint",
        )
    proof = _require_mapping(
        consistency_proof,
        "consistency_proof",
        "INVALID_CONSISTENCY_PROOF",
    )
    contract = _require_mapping(
        proof.get("contract"),
        "consistency_proof.contract",
        "INVALID_CONSISTENCY_PROOF",
    )
    if dict(contract) != CONSISTENCY_PROOF_CONTRACT:
        raise _error(
            "INVALID_CONSISTENCY_PROOF",
            "proof contract must declare transparency_consistency_proof v1",
        )
    if proof.get("hash_algorithm") != "sha-256":
        raise _error(
            "INVALID_CONSISTENCY_PROOF",
            "consistency proof hash_algorithm must be sha-256",
        )
    log_id = _require_string(
        proof.get("log_id"),
        "consistency_proof.log_id",
        "INVALID_CONSISTENCY_PROOF",
    )
    proof_old_size = _require_nonnegative_int(
        proof.get("old_tree_size"),
        "consistency_proof.old_tree_size",
        "INVALID_CONSISTENCY_PROOF",
    )
    proof_new_size = _require_nonnegative_int(
        proof.get("new_tree_size"),
        "consistency_proof.new_tree_size",
        "INVALID_CONSISTENCY_PROOF",
    )
    if (
        log_id != old_log.id
        or proof_old_size != old_size
        or proof_new_size != new_size
    ):
        raise _error(
            "CHECKPOINT_MISMATCH",
            "consistency proof does not match the supplied checkpoints",
        )
    path = _parse_hash_path(
        proof.get("consistency_path"),
        "consistency_proof.consistency_path",
        "INVALID_CONSISTENCY_PROOF",
    )

    if old_size == 0:
        if path:
            raise _error(
                "CONSISTENCY_PROOF_INVALID",
                "empty-tree consistency proof must have an empty path",
            )
    elif old_size == new_size:
        if path or old_root != new_root:
            raise _error(
                "EQUIVOCATION_DETECTED",
                "same-size checkpoints have different roots or a non-empty proof",
            )
    else:
        fn = old_size - 1
        sn = new_size - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1
        if fn == 0:
            first = old_root
            second = old_root
            proof_index = 0
        else:
            if not path:
                raise _error(
                    "CONSISTENCY_PROOF_INVALID",
                    "consistency proof path is incomplete",
                )
            first = path[0]
            second = path[0]
            proof_index = 1
        while proof_index < len(path):
            sibling = path[proof_index]
            if sn == 0:
                raise _error(
                    "CONSISTENCY_PROOF_INVALID",
                    "consistency proof path contains extra hashes",
                )
            if fn & 1 or fn == sn:
                first = _node_hash(sibling, first)
                second = _node_hash(sibling, second)
                while fn and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
            else:
                second = _node_hash(second, sibling)
            fn >>= 1
            sn >>= 1
            proof_index += 1
        if sn != 0 or first != old_root or second != new_root:
            raise _error(
                "CONSISTENCY_PROOF_INVALID",
                "checkpoints are not append-only consistent",
            )
    return VerifiedConsistency(
        log_id=log_id,
        old_tree_size=old_size,
        new_tree_size=new_size,
    )


def verify_countersignature_inclusion(
    countersignature: Mapping[str, Any],
    inclusion_proof: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    trusted_keys: Mapping[str, Any],
) -> VerifiedInclusion:
    """Verify that a counter-signed digest is anchored in a signed checkpoint."""

    artifact = _require_mapping(
        countersignature,
        "countersignature",
        "INVALID_COUNTERSIGNATURE",
    )
    contract = _require_mapping(
        artifact.get("contract"),
        "countersignature.contract",
        "INVALID_COUNTERSIGNATURE",
    )
    if contract.get("name") != "receipt_countersignature" or contract.get("version") != "v1":
        raise _error(
            "INVALID_COUNTERSIGNATURE",
            "contract must declare receipt_countersignature v1",
        )
    digest = _parse_digest(
        artifact.get("receipt_digest"),
        "countersignature.receipt_digest",
    )
    anchor = _require_mapping(
        artifact.get("anchor_reference"),
        "countersignature.anchor_reference",
        "ORPHAN_COUNTERSIGNATURE",
    )
    if anchor.get("type") != "transparency_log":
        raise _error(
            "ORPHAN_COUNTERSIGNATURE",
            "counter-signature is not anchored to a transparency log",
        )
    anchor_log_id = _require_string(
        anchor.get("id"),
        "countersignature.anchor_reference.id",
        "ORPHAN_COUNTERSIGNATURE",
    )
    anchor_leaf_index = _require_nonnegative_int(
        anchor.get("leaf_index"),
        "countersignature.anchor_reference.leaf_index",
        "ORPHAN_COUNTERSIGNATURE",
    )
    verified_checkpoint = verify_checkpoint_signature(checkpoint, trusted_keys)
    try:
        verified_inclusion = verify_inclusion(digest, inclusion_proof, checkpoint)
    except TransparencyVerificationError as exc:
        if exc.code == "LEAF_DIGEST_MISMATCH":
            raise _error(
                "ORPHAN_COUNTERSIGNATURE",
                "counter-signature digest is not the digest proven at the declared log leaf",
            ) from exc
        raise
    if (
        anchor_log_id != verified_inclusion.log_id
        or anchor_leaf_index != verified_inclusion.leaf_index
    ):
        raise _error(
            "ORPHAN_COUNTERSIGNATURE",
            "counter-signature anchor does not match the verified inclusion proof",
        )
    return VerifiedInclusion(
        log_id=verified_inclusion.log_id,
        tree_size=verified_inclusion.tree_size,
        leaf_index=verified_inclusion.leaf_index,
        leaf_digest=verified_inclusion.leaf_digest,
        checkpoint=verified_checkpoint,
    )


def verify_monitor_update(
    previous_checkpoint: Mapping[str, Any],
    current_checkpoint: Mapping[str, Any],
    consistency_proof: Mapping[str, Any],
    trusted_keys: Mapping[str, Any],
) -> VerifiedMonitorUpdate:
    """Verify a monitor update and detect rewind or split-view evidence."""

    previous = verify_checkpoint_signature(previous_checkpoint, trusted_keys)
    current = verify_checkpoint_signature(current_checkpoint, trusted_keys)
    consistency = verify_consistency(
        previous_checkpoint,
        current_checkpoint,
        consistency_proof,
    )
    return VerifiedMonitorUpdate(
        previous=previous,
        current=current,
        consistency=consistency,
    )


__all__ = [
    "CHECKPOINT_CONTEXT",
    "CHECKPOINT_KEY_USE",
    "CONSISTENCY_PROOF_CONTRACT",
    "INCLUSION_PROOF_CONTRACT",
    "TransparencyVerificationError",
    "VerifiedCheckpoint",
    "VerifiedConsistency",
    "VerifiedInclusion",
    "VerifiedMonitorUpdate",
    "verify_checkpoint_signature",
    "verify_consistency",
    "verify_countersignature_inclusion",
    "verify_inclusion",
    "verify_monitor_update",
]
