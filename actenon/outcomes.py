"""Actenon Kernel — structured failure taxonomy.

This module is a thin adapter over ``actenon_protocol.refusal_codes``,
which is the canonical, implementation-independent source of truth for
the refusal-code catalogue (see github.com/Actenon/actenon-protocol).

Backward compatibility:
  - The existing ``FailureCode`` enum (16 members) is preserved as an
    alias for the protocol's ``RefusalCode`` enum (20 members). The 4
    new protocol codes are NOT added to ``FailureCode`` to avoid
    surprising existing consumers; they are accessible via
    ``actenon_protocol.RefusalCode``.
  - The existing ``TAXONOMY_VERSION = "1"`` is preserved.
  - ``refusal_code_to_failure_code()`` continues to accept the same
    inputs and produce the same outputs.
  - The 16 existing ``_REFUSAL_CODE_MAP`` aliases are preserved.

Drift gate:
  - ``tests/test_protocol_drift.py`` verifies that this module's public
    surface stays in sync with ``actenon_protocol``.
  - ``.github/workflows/protocol-drift.yml`` runs the drift gate in CI.
"""

from __future__ import annotations

from typing import Mapping

# Import the canonical taxonomy from the protocol package.
from actenon_protocol import (
    RefusalCode as _ProtocolRefusalCode,
    TAXONOMY_VERSION as _PROTOCOL_TAXONOMY_VERSION,
    resolve_alias as _protocol_resolve_alias,
    refusal_to_disclosed_code as _protocol_refusal_to_disclosed_code,
    refusal_to_internal_code as _protocol_refusal_to_internal_code,
    refusal_to_retryable as _protocol_refusal_to_retryable,
    DisclosurePolicy as _ProtocolDisclosurePolicy,
    PUBLIC_SAFE_CODES as _PROTOCOL_PUBLIC_SAFE_CODES,
    DETAILED_CODES as _PROTOCOL_DETAILED_CODES,
    COMPATIBILITY_ALIASES as _PROTOCOL_COMPATIBILITY_ALIASES,
)

# Re-export the protocol's taxonomy version. We keep the local
# TAXONOMY_VERSION = "1" for backward compatibility — it matches the
# protocol's taxonomy version.
TAXONOMY_VERSION = _PROTOCOL_TAXONOMY_VERSION

# FailureCode is now an alias for the protocol's RefusalCode enum.
# We do NOT subclass (Python enums cannot be subclassed once they have
# members). Existing code that does ``from actenon.outcomes import
# FailureCode`` continues to work — FailureCode IS RefusalCode.
FailureCode = _ProtocolRefusalCode

# Historical alias attributes — allow ``FailureCode.PCCB_REQUIRED`` etc.
# to resolve to the canonical protocol code. Since FailureCode IS the
# protocol enum, we look up via the protocol's resolve_alias for any
# code not directly on the enum.
PCCB_REQUIRED: FailureCode = FailureCode(_protocol_resolve_alias("PCCB_REQUIRED"))
PCCB_EXPIRED: FailureCode = FailureCode(_protocol_resolve_alias("PCCB_EXPIRED"))
DUPLICATE_REPLAY: FailureCode = FailureCode(_protocol_resolve_alias("DUPLICATE_REPLAY"))
NOT_ACTIVE: FailureCode = FailureCode(_protocol_resolve_alias("NOT_ACTIVE"))
REVOKED: FailureCode = FailureCode(_protocol_resolve_alias("REVOKED"))
EXPIRED: FailureCode = FailureCode(_protocol_resolve_alias("EXPIRED"))
SCOPE_DENIED: FailureCode = FailureCode(_protocol_resolve_alias("SCOPE_DENIED"))
OUT_OF_SCOPE: FailureCode = FailureCode(_protocol_resolve_alias("OUT_OF_SCOPE"))
BUDGET_EXCEEDED: FailureCode = FailureCode(_protocol_resolve_alias("BUDGET_EXCEEDED"))
RATE_LIMITED: FailureCode = FailureCode(_protocol_resolve_alias("RATE_LIMITED"))
ENGINE_ERROR: FailureCode = FailureCode(_protocol_resolve_alias("ENGINE_ERROR"))


# Preserve the historical _REFUSAL_CODE_MAP for backward compatibility.
# This maps the kernel's granular refusal_code strings (as emitted by
# ProofVerificationError) to FailureCode enum members. New entries are
# sourced from the protocol's COMPATIBILITY_ALIASES.
#
# Note: the values use the module-level alias constants (PCCB_EXPIRED etc.)
# rather than FailureCode.PCCB_EXPIRED because StrEnum does not allow
# setting extra class attributes.
_REFUSAL_CODE_MAP: Mapping[str, FailureCode] = {
    "ACTION_MISMATCH": FailureCode.ACTION_MISMATCH,
    "AUDIENCE_MISMATCH": FailureCode.AUDIENCE_MISMATCH,
    "SIGNATURE_INVALID": FailureCode.SIGNATURE_INVALID,
    "PROOF_INVALID": FailureCode.SIGNATURE_INVALID,
    "PROOF_EXPIRED": PCCB_EXPIRED,
    "PROOF_NOT_YET_VALID": PCCB_EXPIRED,
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

    This function is preserved for backward compatibility. New code
    SHOULD use ``actenon_protocol.resolve_alias()`` directly.

    Resolution order:
      1. If the code is a canonical protocol code (e.g. "PROOF_MISSING"),
         return it directly.
      2. If the code is a registered compatibility alias (e.g.
         "PCCB_REQUIRED"), resolve via the protocol's alias map.
      3. If the code is in the historical _REFUSAL_CODE_MAP (kernel-
         specific refusal_code strings like "ACTION_HASH_MISMATCH"),
         return the mapped FailureCode.
      4. Otherwise raise KeyError. Unknown codes are NOT silently mapped
         to a generic outcome — callers must handle the KeyError.
    """
    # Try canonical protocol code first
    try:
        return FailureCode(refusal_code)
    except ValueError:
        pass
    # Try the protocol's alias map (covers PCCB_REQUIRED, etc.)
    try:
        canonical = _protocol_resolve_alias(refusal_code)
        return FailureCode(canonical)
    except KeyError:
        pass
    # Try the historical kernel-specific map
    if refusal_code in _REFUSAL_CODE_MAP:
        return _REFUSAL_CODE_MAP[refusal_code]
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
    # Historical aliases (preserved for backward compatibility)
    "PCCB_REQUIRED",
    "PCCB_EXPIRED",
    "DUPLICATE_REPLAY",
    "NOT_ACTIVE",
    "REVOKED",
    "EXPIRED",
    "SCOPE_DENIED",
    "OUT_OF_SCOPE",
    "BUDGET_EXCEEDED",
    "RATE_LIMITED",
    "ENGINE_ERROR",
]
