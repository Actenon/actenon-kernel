from __future__ import annotations

from types import MappingProxyType


PUBLIC_PROOF_REFUSAL_MESSAGES = MappingProxyType(
    {
        "PROOF_NOT_YET_VALID": "The proof is not yet valid.",
        "PROOF_EXPIRED": "The proof has expired.",
        "AUDIENCE_MISMATCH": "The proof audience does not match this endpoint.",
        "SCOPE_MODE_INVALID": "The proof scope mode is not supported.",
        "SCOPE_CAPABILITY_MISMATCH": "The proof scope does not allow this capability.",
        "INTENT_MISMATCH": "The proof does not match the supplied action intent.",
        "TENANT_MISMATCH": "The proof tenant does not match the action intent.",
        "SUBJECT_MISMATCH": "The proof subject does not match the action intent.",
        "ACTION_MISMATCH": "The proof action does not exactly match the action intent.",
        "TARGET_MISMATCH": "The proof target does not exactly match the action intent.",
        "ACTION_HASH_INVALID": "The action hash could not be recomputed safely.",
        "ACTION_HASH_ALGORITHM_INVALID": "The proof action hash metadata is invalid.",
        "ACTION_HASH_MISMATCH": "The proof action hash does not match the action intent.",
        "PROOF_PAYLOAD_INVALID": "The proof payload could not be canonicalized safely.",
        "SIGNATURE_INVALID": "The proof signature could not be verified.",
    }
)


def public_proof_refusal_message(reason_code: str) -> str:
    try:
        return PUBLIC_PROOF_REFUSAL_MESSAGES[reason_code]
    except KeyError as exc:
        raise ValueError(f"unknown public proof refusal reason code: {reason_code}") from exc


__all__ = [
    "PUBLIC_PROOF_REFUSAL_MESSAGES",
    "public_proof_refusal_message",
]
