"""Actenon Kernel — structured failure taxonomy.

This module is a thin adapter over ``actenon_protocol.refusal_codes``,
which is the canonical, implementation-independent source of truth for
the refusal-code catalogue (see github.com/Actenon/actenon-protocol).

Backward compatibility:
  - The existing ``FailureCode`` enum (16 members) is preserved with
    the same member NAMES. The member VALUES are the canonical protocol
    codes (so ``FailureCode.PCCB_REQUIRED.value == "PROOF_MISSING"``).
    Code that does ``FailureCode.PCCB_REQUIRED`` continues to work;
    code that does ``FailureCode.PCCB_REQUIRED.value`` now sees the
    canonical protocol value.
  - ``TAXONOMY_VERSION`` is sourced from the protocol.
  - ``refusal_code_to_failure_code()`` continues to accept the same
    inputs and produce FailureCode enum members.
  - The 16 existing ``_REFUSAL_CODE_MAP`` entries are preserved.

Drift gate:
  - ``tests/test_protocol_drift.py`` verifies that this module's public
    surface stays in sync with ``actenon_protocol``.
  - ``.github/workflows/protocol-drift.yml`` runs the drift gate in CI.
"""

from __future__ import annotations

from typing import Mapping

# Use the protocol's StrEnum compatibility shim (supports Python 3.10+).
from actenon_protocol._compat import StrEnum

# Import the canonical taxonomy from the protocol package.
from actenon_protocol import (
    TAXONOMY_VERSION as _PROTOCOL_TAXONOMY_VERSION,
    resolve_alias as _protocol_resolve_alias,
    refusal_to_disclosed_code as _protocol_refusal_to_disclosed_code,
    refusal_to_internal_code as _protocol_refusal_to_internal_code,
    refusal_to_retryable as _protocol_refusal_to_retryable,
    DisclosurePolicy as _ProtocolDisclosurePolicy,
)

# Re-export the protocol's taxonomy version. We keep the local
# TAXONOMY_VERSION = "1" for backward compatibility — it matches the
# protocol's taxonomy version.
TAXONOMY_VERSION = _PROTOCOL_TAXONOMY_VERSION


class FailureCode(StrEnum):
    """Kernel-local failure taxonomy.

    This enum has the same 16 member NAMES as the historical kernel
    FailureCode. Each member has a DISTINCT value (the historical name)
    for backward compatibility with code that compares ``fc.value`` to
    a literal string. The canonical protocol code is available via the
    ``canonical`` property.

    The 16 names map to the protocol's 20-code catalogue as follows:
      - 6 names are canonical protocol codes (SIGNATURE_INVALID,
        ACTION_MISMATCH, AUDIENCE_MISMATCH, REPLAY_DETECTED,
        AUTHORITY_REVOKED, POLICY_REFUSAL) — kept under their protocol
        names.
      - 8 names are historical aliases that resolve to canonical
        protocol codes (PCCB_REQUIRED→PROOF_MISSING, PCCB_EXPIRED→
        PROOF_EXPIRED, DUPLICATE_REPLAY→REPLAY_DETECTED, NOT_ACTIVE→
        POLICY_REFUSAL, REVOKED→AUTHORITY_REVOKED, EXPIRED→PROOF_EXPIRED,
        SCOPE_DENIED→POLICY_REFUSAL, OUT_OF_SCOPE→POLICY_REFUSAL,
        BUDGET_EXCEEDED→POLICY_REFUSAL, RATE_LIMITED→POLICY_REFUSAL,
        ENGINE_ERROR→OUTCOME_UNKNOWN).
      - 2 names are positive outcomes (ALLOWED, APPROVAL_REQUIRED) that
        are NOT in the protocol's refusal catalogue (they are not
        refusals).

    Existing code that does ``from actenon.outcomes import FailureCode``
    and references ``FailureCode.PCCB_REQUIRED`` etc. continues to work.
    Code that compares ``fc.value`` to a literal string sees the
    HISTORICAL name (backward compat). New code should use ``fc.canonical``
    to get the protocol-canonical code.
    """

    # Positive outcomes (NOT refusals; not in the protocol catalogue)
    ALLOWED = "ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

    # Policy-decision failures (historical names; canonical values via .canonical)
    NOT_ACTIVE = "NOT_ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    SCOPE_DENIED = "SCOPE_DENIED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    ENGINE_ERROR = "ENGINE_ERROR"

    # Proof-verification failures (historical names; canonical values via .canonical)
    PCCB_REQUIRED = "PCCB_REQUIRED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    PCCB_EXPIRED = "PCCB_EXPIRED"
    DUPLICATE_REPLAY = "DUPLICATE_REPLAY"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"

    @property
    def canonical(self) -> str:
        """Return the canonical protocol refusal code for this FailureCode.

        For positive outcomes (ALLOWED, APPROVAL_REQUIRED), returns the
        value itself (these are not refusals and have no protocol-canonical
        equivalent).

        For refusal members, returns the canonical protocol code via
        ``actenon_protocol.resolve_alias(self.value)``.
        """
        if self.value in ("ALLOWED", "APPROVAL_REQUIRED"):
            return self.value
        return _protocol_resolve_alias(self.value)


# Preserve the historical _REFUSAL_CODE_MAP for backward compatibility.
# This maps the kernel's granular refusal_code strings (as emitted by
# ProofVerificationError) to FailureCode enum members.
_REFUSAL_CODE_MAP: Mapping[str, FailureCode] = {
    "ACTION_MISMATCH": FailureCode.ACTION_MISMATCH,
    "AUDIENCE_MISMATCH": FailureCode.AUDIENCE_MISMATCH,
    "SIGNATURE_INVALID": FailureCode.SIGNATURE_INVALID,
    "PROOF_INVALID": FailureCode.SIGNATURE_INVALID,
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
    # Protocol-canonical codes (forward compatibility — accept the new
    # canonical names as well as the historical ones).
    "PROOF_MISSING": FailureCode.PCCB_REQUIRED,
    "REPLAY_DETECTED": FailureCode.DUPLICATE_REPLAY,
    "AUTHORITY_REVOKED": FailureCode.REVOKED,
    "POLICY_REFUSAL": FailureCode.NOT_ACTIVE,
    "OUTCOME_UNKNOWN": FailureCode.ENGINE_ERROR,
    "PROOF_NOT_YET_VALID": FailureCode.PCCB_EXPIRED,  # already above; kept for clarity
    "ISSUER_UNTRUSTED": FailureCode.SIGNATURE_INVALID,
    "PARAMETER_MISMATCH": FailureCode.ACTION_MISMATCH,
    "MALFORMED_REQUEST": FailureCode.SIGNATURE_INVALID,
    "UNSUPPORTED_PROTOCOL_VERSION": FailureCode.SIGNATURE_INVALID,
    "CANONICALISATION_FAILURE": FailureCode.SIGNATURE_INVALID,
    "CREDENTIAL_UNAVAILABLE": FailureCode.ENGINE_ERROR,
    "PROVIDER_REFUSAL": FailureCode.ENGINE_ERROR,
    "PROVIDER_FAILURE": FailureCode.ENGINE_ERROR,
}


def refusal_code_to_failure_code(refusal_code: str) -> FailureCode:
    """Map a kernel ProofVerificationError.refusal_code string to the
    canonical FailureCode enum member.

    This function is preserved for backward compatibility. New code
    SHOULD use ``actenon_protocol.resolve_alias()`` directly.

    Resolution order:
      1. If the code is a canonical FailureCode value (e.g. "PROOF_MISSING"),
         return it directly.
      2. If the code is a registered protocol alias (e.g. "PCCB_REQUIRED"),
         resolve via the protocol's alias map and map to the FailureCode
         member with that value.
      3. If the code is in the historical _REFUSAL_CODE_MAP (kernel-
         specific refusal_code strings like "ACTION_HASH_MISMATCH"),
         return the mapped FailureCode.
      4. Otherwise raise KeyError. Unknown codes are NOT silently mapped
         to a generic outcome — callers must handle the KeyError.
    """
    # Try canonical FailureCode value first
    try:
        return FailureCode(refusal_code)
    except ValueError:
        pass
    # Try the historical kernel-specific map (covers ACTION_HASH_MISMATCH,
    # PROOF_INVALID, INTENT_MISMATCH, etc. — strings that the kernel's
    # ProofVerificationError emits but that are neither canonical protocol
    # codes nor protocol aliases).
    if refusal_code in _REFUSAL_CODE_MAP:
        return _REFUSAL_CODE_MAP[refusal_code]
    # Try the protocol's alias map (covers PCCB_REQUIRED, etc.)
    try:
        canonical = _protocol_resolve_alias(refusal_code)
        return FailureCode(canonical)
    except KeyError:
        pass
    # Unknown code — do NOT silently map to a generic outcome.
    raise KeyError(
        f"refusal_code {refusal_code!r} has no FailureCode mapping. "
        f"If this is a new code, add it to actenon-protocol's "
        f"refusals/catalogue.v1.yaml and bump taxonomy_version."
    ) from None


# Re-export the protocol's disclosure helpers for kernel consumers.
# These allow the verifier to emit the protocol's two-layer disclosure
# model (disclosed_code + internal_code) without re-implementing the
# catalogue lookup.
def to_disclosed_code(internal_code: str | None, policy: str = "public") -> str:
    """Map an internal refusal code to the disclosed code under a policy.

    ``policy`` is a string ("public", "trusted", "local_debug") for
    backward-compatibility with kernel callers that pass strings. It is
    converted to the protocol's DisclosurePolicy enum internally.
    """
    p = _ProtocolDisclosurePolicy(policy)
    return _protocol_refusal_to_disclosed_code(internal_code, p)


def to_internal_code(internal_code: str | None, policy: str = "public") -> str | None:
    """Return the internal_code to emit under the given policy."""
    p = _ProtocolDisclosurePolicy(policy)
    return _protocol_refusal_to_internal_code(internal_code, p)


def to_retryable(internal_code: str | None) -> bool:
    """Return the retryable flag for the given internal code."""
    return _protocol_refusal_to_retryable(internal_code)


__all__ = [
    "TAXONOMY_VERSION",
    "FailureCode",
    "refusal_code_to_failure_code",
    "to_disclosed_code",
    "to_internal_code",
    "to_retryable",
]
