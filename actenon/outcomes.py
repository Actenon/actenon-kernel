"""Actenon Kernel — structured failure taxonomy.

Single source of truth for all failure codes across the system:
  - policy-decision failures (emitted by permit's PDP)
  - proof-verification failures (emitted by the kernel's edge verifier)

Every code is a stable string value (== its enum name). Adding codes
requires a taxonomy_version bump documented in SPEC.md.

The kernel's ProofVerificationError maps its granular refusal_code strings
onto these enum members via ``refusal_code_to_failure_code()``.
Permit imports ``FailureCode`` from here — it must NOT define its own copy.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

TAXONOMY_VERSION = "1"


class FailureCode(StrEnum):
    """Versioned, stable failure taxonomy spanning policy + proof failures.

    taxonomy_version = "1"
    """

    # allow / pending
    ALLOWED = "ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

    # policy-decision failures (emitted by permit PDP)
    NOT_ACTIVE = "NOT_ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    SCOPE_DENIED = "SCOPE_DENIED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    ENGINE_ERROR = "ENGINE_ERROR"

    # proof-verification failures (emitted by kernel edge verifier)
    PCCB_REQUIRED = "PCCB_REQUIRED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    PCCB_EXPIRED = "PCCB_EXPIRED"
    DUPLICATE_REPLAY = "DUPLICATE_REPLAY"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"


_REFUSAL_CODE_MAP: Mapping[str, FailureCode] = {
    "ACTION_MISMATCH": FailureCode.ACTION_MISMATCH,
    "AUDIENCE_MISMATCH": FailureCode.AUDIENCE_MISMATCH,
    "SIGNATURE_INVALID": FailureCode.SIGNATURE_INVALID,
    "PROOF_EXPIRED": FailureCode.PCCB_EXPIRED,
    "PROOF_NOT_YET_VALID": FailureCode.PCCB_EXPIRED,
    "INTENT_MISMATCH": FailureCode.ACTION_MISMATCH,
    "TARGET_MISMATCH": FailureCode.ACTION_MISMATCH,
    "ACTION_HASH_MISMATCH": FailureCode.ACTION_MISMATCH,
    "ACTION_HASH_ALGORITHM_INVALID": FailureCode.ACTION_MISMATCH,
    "ACTION_HASH_INVALID": FailureCode.ACTION_MISMATCH,
    "SCOPE_MODE_INVALID": FailureCode.ACTION_MISMATCH,
    "SCOPE_CAPABILITY_MISMATCH": FailureCode.ACTION_MISMATCH,
    "TENANT_MISMATCH": FailureCode.ACTION_MISMATCH,
    "SUBJECT_MISMATCH": FailureCode.ACTION_MISMATCH,
    "PROOF_PAYLOAD_INVALID": FailureCode.SIGNATURE_INVALID,
}


def refusal_code_to_failure_code(refusal_code: str) -> FailureCode:
    """Map a kernel ProofVerificationError.refusal_code string to the
    canonical FailureCode enum member.
    """
    try:
        return FailureCode(refusal_code)
    except ValueError:
        pass
    if refusal_code not in _REFUSAL_CODE_MAP:
        raise KeyError(
            f"refusal_code {refusal_code!r} has no FailureCode mapping. "
            f"If this is a new code, add it to _REFUSAL_CODE_MAP and bump "
            f"taxonomy_version."
        ) from None
    return _REFUSAL_CODE_MAP[refusal_code]


__all__ = [
    "TAXONOMY_VERSION",
    "FailureCode",
    "refusal_code_to_failure_code",
]
