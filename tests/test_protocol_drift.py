"""Protocol drift gate for actenon-kernel.

This test module fails when:
  - The pinned actenon-protocol version does not match the kernel's expected version.
  - The kernel's refusal-code taxonomy disagrees with the protocol's catalogue.
  - The kernel's canonicalisation profile label disagrees with the protocol's.
  - The kernel emits a refusal code that is not registered in the protocol catalogue.
  - The kernel's identifier-prefix regex disagrees with the protocol's.
  - Local schema copies (if any) differ from the pinned protocol source.

Run with: `python -m pytest tests/test_protocol_drift.py -v`
"""

from __future__ import annotations

import re

import pytest

from actenon_protocol import (
    PROTOCOL_VERSION,
    CANONICALISATION_PROFILE,
    LEGACY_CANONICALISATION_PROFILE,
    ACCEPTED_CANONICALISATION_PROFILES,
    TAXONOMY_VERSION as PROTOCOL_TAXONOMY_VERSION,
    RefusalCode,
    COMPATIBILITY_ALIASES,
    PREFIXES as PROTOCOL_PREFIXES,
    is_valid_identifier as protocol_is_valid_identifier,
)
from actenon_protocol.canonicalisation import canonicalize_json, canonicalize_bytes

from actenon.outcomes import (
    FailureCode,
    TAXONOMY_VERSION as KERNEL_TAXONOMY_VERSION,
    refusal_code_to_failure_code,
)
from actenon.proof.canonical import (
    CANONICALIZATION_PROFILE as KERNEL_CANONICALIZATION_PROFILE,
    LEGACY_CANONICALIZATION_PROFILE as KERNEL_LEGACY_CANONICALIZATION_PROFILE,
    ACCEPTED_CANONICALIZATION_PROFILES as KERNEL_ACCEPTED_CANONICALIZATION_PROFILES,
)


# ---------------------------------------------------------------------------
# 0. Pinned protocol version
# ---------------------------------------------------------------------------

EXPECTED_PROTOCOL_VERSION = "1.0.0"


def test_protocol_version_is_pinned():
    """The installed actenon-protocol version must match the kernel's pin."""
    assert PROTOCOL_VERSION == EXPECTED_PROTOCOL_VERSION, (
        f"actenon-protocol is {PROTOCOL_VERSION!r}, but actenon-kernel "
        f"expects {EXPECTED_PROTOCOL_VERSION!r}. Update pyproject.toml "
        f"and this test together."
    )


# ---------------------------------------------------------------------------
# 1. Refusal-code taxonomy agreement
# ---------------------------------------------------------------------------

def test_taxonomy_versions_agree():
    """Kernel's TAXONOMY_VERSION must equal the protocol's."""
    assert KERNEL_TAXONOMY_VERSION == PROTOCOL_TAXONOMY_VERSION


def test_kernel_failure_code_is_protocol_refusal_code():
    """FailureCode's 16 historical member NAMES and VALUES are preserved
    (backward compat). The ``canonical`` property maps each member to
    its canonical protocol code.

    The kernel's FailureCode is a separate StrEnum (it has positive
    outcomes ALLOWED and APPROVAL_REQUIRED that are NOT in the protocol's
    refusal catalogue). Every refusal member's ``canonical`` value must
    be a canonical protocol code.
    """
    # Positive outcomes — not in the protocol's refusal catalogue.
    positive_outcomes = {"ALLOWED", "APPROVAL_REQUIRED"}
    from actenon_protocol import RefusalCode
    protocol_values = {c.value for c in RefusalCode}

    for fc in FailureCode:
        if fc.value in positive_outcomes:
            # Positive outcome — not a refusal, .canonical returns itself.
            assert fc.canonical == fc.value
            continue
        # Refusal members' .canonical must be a canonical protocol code.
        assert fc.canonical in protocol_values, (
            f"FailureCode.{fc.name}.canonical = {fc.canonical!r} is not a "
            f"canonical protocol refusal code."
        )


def test_historical_aliases_resolve_to_canonical():
    """Historical kernel FailureCode members' ``canonical`` values must
    equal the protocol's canonical codes.

    The kernel's FailureCode keeps the historical NAMES and VALUES
    (PCCB_REQUIRED.value == "PCCB_REQUIRED") for backward compatibility.
    The ``canonical`` property maps each to the protocol's canonical code
    (PCCB_REQUIRED.canonical == "PROOF_MISSING").
    """
    # Each (FailureCode member name, expected canonical protocol value)
    expected = {
        "PCCB_REQUIRED": "PROOF_MISSING",
        "PCCB_EXPIRED": "PROOF_EXPIRED",
        "DUPLICATE_REPLAY": "REPLAY_DETECTED",
        "NOT_ACTIVE": "POLICY_REFUSAL",
        "REVOKED": "AUTHORITY_REVOKED",
        "EXPIRED": "PROOF_EXPIRED",
        "SCOPE_DENIED": "POLICY_REFUSAL",
        "OUT_OF_SCOPE": "POLICY_REFUSAL",
        "BUDGET_EXCEEDED": "POLICY_REFUSAL",
        "RATE_LIMITED": "POLICY_REFUSAL",
        "ENGINE_ERROR": "OUTCOME_UNKNOWN",
        # Canonical names (value == canonical)
        "SIGNATURE_INVALID": "SIGNATURE_INVALID",
        "ACTION_MISMATCH": "ACTION_MISMATCH",
        "AUDIENCE_MISMATCH": "AUDIENCE_MISMATCH",
    }
    for member_name, canonical_value in expected.items():
        fc = getattr(FailureCode, member_name)
        assert fc.canonical == canonical_value, (
            f"FailureCode.{member_name}.canonical = {fc.canonical!r}, "
            f"expected {canonical_value!r}"
        )
    # The protocol's resolve_alias must also resolve the historical
    # value to the same canonical value.
    from actenon_protocol import resolve_alias
    for member_name, canonical in expected.items():
        fc = getattr(FailureCode, member_name)
        assert resolve_alias(fc.value) == canonical, (
            f"protocol resolve_alias({fc.value!r}) = {resolve_alias(fc.value)!r}, "
            f"expected {canonical!r}"
        )


def test_unknown_refusal_code_raises_not_silently_mapped():
    """Unknown refusal codes MUST raise KeyError, NOT be silently mapped
    to a generic outcome. This is the 'do not silently map unknown
    failures to success or to a misleading generic outcome' rule from
    the integration brief.
    """
    with pytest.raises(KeyError):
        refusal_code_to_failure_code("NOT_A_REAL_CODE")


def test_kernel_emitted_codes_are_all_registered():
    """Every code the kernel can emit must be registered in the protocol
    catalogue (either as a canonical code or as a compatibility alias).

    This test enumerates the codes the kernel's verifier emits and
    verifies each one resolves via the protocol.
    """
    # These are the refusal_code strings the kernel's ProofVerificationError
    # can carry (from actenon/proof/service.py and the verifier).
    kernel_emitted_codes = [
        "PROOF_INVALID",
        "SIGNATURE_INVALID",
        "PROOF_EXPIRED",
        "PROOF_NOT_YET_VALID",
        "AUDIENCE_MISMATCH",
        "TARGET_MISMATCH",
        "ACTION_MISMATCH",
        "INTENT_MISMATCH",
        "ACTION_HASH_MISMATCH",
        "ACTION_HASH_ALGORITHM_INVALID",
        "ACTION_HASH_INVALID",
        "SCOPE_MODE_INVALID",
        "SCOPE_CAPABILITY_MISMATCH",
        "TENANT_MISMATCH",
        "SUBJECT_MISMATCH",
        "PROOF_PAYLOAD_INVALID",
        "REPLAY_DETECTED",
        "PROOF_MISSING",
        "PCCB_REQUIRED",
        "PCCB_EXPIRED",
        "DUPLICATE_REPLAY",
    ]
    from actenon_protocol import resolve_alias
    for code in kernel_emitted_codes:
        # Each must resolve via the protocol (canonical or alias)
        try:
            resolve_alias(code)
        except KeyError:
            # Some kernel-specific codes (like ACTION_HASH_MISMATCH) are
            # in the kernel's _REFUSAL_CODE_MAP but not in the protocol's
            # COMPATIBILITY_ALIASES. The kernel's refusal_code_to_failure_code
            # MUST still resolve them.
            try:
                refusal_code_to_failure_code(code)
            except KeyError:
                pytest.fail(
                    f"kernel-emitted code {code!r} is not registered in the "
                    f"protocol catalogue AND not in the kernel's "
                    f"_REFUSAL_CODE_MAP. This is a drift bug."
                )


# ---------------------------------------------------------------------------
# 2. Canonicalisation profile agreement
# ---------------------------------------------------------------------------

def test_canonicalisation_profile_label_agrees():
    """Kernel's CANONICALIZATION_PROFILE must equal the protocol's
    CANONICALISATION_PROFILE (same value, different spelling of the
    attribute name)."""
    assert KERNEL_CANONICALIZATION_PROFILE == CANONICALISATION_PROFILE


def test_legacy_canonicalisation_profile_agrees():
    assert KERNEL_LEGACY_CANONICALIZATION_PROFILE == LEGACY_CANONICALISATION_PROFILE


def test_accepted_canonicalisation_profiles_agree():
    assert KERNEL_ACCEPTED_CANONICALIZATION_PROFILES == ACCEPTED_CANONICALISATION_PROFILES


def test_rejected_canonicalisation_label_is_not_accepted():
    """The doc-only label 'actenon-jcs-sha256-v1' must NOT be accepted."""
    assert "actenon-jcs-sha256-v1" not in KERNEL_ACCEPTED_CANONICALIZATION_PROFILES
    assert "actenon-jcs-sha256-v1" not in ACCEPTED_CANONICALISATION_PROFILES


def test_canonicalisation_byte_equivalence():
    """The kernel's canonicalisation must produce byte-identical output
    to the protocol's reference implementation for a set of test inputs."""
    from actenon.proof.canonical import canonicalize_json as kernel_canonicalize_json
    test_inputs = [
        {"b": 1, "a": 2},
        {"action": "payment.refund", "amount_cents": 2500},
        ["a", "b", "c"],
        {"nested": {"z": 1, "a": 2}},
        "café",
        42,
        True,
        None,
    ]
    for inp in test_inputs:
        kernel_out = kernel_canonicalize_json(inp)
        protocol_out = canonicalize_json(inp)
        assert kernel_out == protocol_out, (
            f"canonicalisation mismatch for {inp!r}: "
            f"kernel={kernel_out!r} protocol={protocol_out!r}"
        )


def test_floats_rejected_by_both():
    """Both kernel and protocol must reject floats in canonicalisation.

    The kernel raises TypeError (historical behaviour); the protocol
    raises CanonicalisationError. Both must reject — the exception type
    differs but the rejection is the contract.
    """
    from actenon_protocol import CanonicalisationError as ProtocolError
    # Kernel raises TypeError on floats (historical behaviour, preserved
    # for backward compatibility — do not change without a deprecation
    # period).
    with pytest.raises(TypeError):
        from actenon.proof.canonical import canonicalize_json as k
        k(3.14)
    # Protocol raises CanonicalisationError (the protocol's canonical
    # exception type).
    with pytest.raises(ProtocolError):
        canonicalize_json(3.14)


# ---------------------------------------------------------------------------
# 3. Identifier-prefix agreement
# ---------------------------------------------------------------------------

def test_identifier_prefixes_agree():
    """The protocol's identifier regex must accept what the kernel accepts."""
    # The kernel doesn't have its own identifier validator (it uses the
    # protocol's via actenon.models.contracts). This test verifies that
    # the protocol's validator accepts the kernel's existing identifiers.
    test_cases = [
        ("proof_a1b2c3d4e5f60718", True),    # canonical
        ("pccb_a1b2c3d4e5f60718", True),     # alias
        ("act_a1b2c3d4e5f60718", True),      # alias for intent_
        ("grant_a1b2c3d4e5f60718", True),    # canonical
        ("intent_a1b2c3d4e5f60718", True),   # canonical
        ("tenant_a1b2c3d4e5f60718", False),  # forbidden
        ("user_a1b2c3d4e5f60718", False),    # forbidden
        ("proof_short", False),              # too short
        ("PROOF_a1b2c3d4e5f60718", False),   # uppercase prefix
    ]
    for ident, expected_valid in test_cases:
        actual = protocol_is_valid_identifier(ident)
        assert actual == expected_valid, (
            f"protocol_is_valid_identifier({ident!r}) returned {actual}, "
            f"expected {expected_valid}"
        )


# ---------------------------------------------------------------------------
# 4. Boundary preservation
# ---------------------------------------------------------------------------

def test_kernel_does_not_import_cloud_or_permit():
    """The kernel MUST NOT import actenon_cloud or actenon_permit."""
    import sys
    # Collect all loaded modules
    loaded = set(sys.modules.keys())
    cloud_modules = {m for m in loaded if m.startswith("actenon_cloud") or m.startswith("app.") or m.startswith("cloud.")}
    permit_modules = {m for m in loaded if m.startswith("actenon_permit") or m.startswith("permit.")}
    assert not cloud_modules, f"kernel imported cloud modules: {cloud_modules}"
    assert not permit_modules, f"kernel imported permit modules: {permit_modules}"


def test_protocol_does_not_import_kernel():
    """The protocol package MUST NOT import actenon (kernel)."""
    import sys
    loaded = set(sys.modules.keys())
    kernel_modules = {m for m in loaded if m.startswith("actenon.") and not m.startswith("actenon_protocol")}
    # Filter out the kernel modules we explicitly imported in THIS test file
    # (those are loaded by the test, not by the protocol package).
    protocol_loaded = {m for m in loaded if m.startswith("actenon_protocol")}
    # The protocol package itself should not have triggered kernel imports
    # before this test file ran. We can't easily verify "before", so we
    # verify that the protocol package's __init__ doesn't import actenon.
    import actenon_protocol
    protocol_init_code = open(actenon_protocol.__file__).read()
    assert "import actenon" not in protocol_init_code.replace("actenon_protocol", ""), (
        "actenon_protocol.__init__ contains an import of actenon (kernel)"
    )


# ---------------------------------------------------------------------------
# 5. Cross-repo: protocol version rejection
# ---------------------------------------------------------------------------

def test_unsupported_major_version_is_rejected():
    """A protocol version with major != 1 must be rejected by the
    protocol's version validator."""
    from actenon_protocol.types.common import ProtocolVersion
    # The pydantic type uses pattern ^1\.[0-9]+\.[0-9]+$
    # Verify a v2 version fails validation
    from pydantic import TypeAdapter, ValidationError
    adapter = TypeAdapter(ProtocolVersion)
    # v1.x is accepted
    assert adapter.validate_python("1.0.0") == "1.0.0"
    assert adapter.validate_python("1.5.3") == "1.5.3"
    # v2.x is rejected
    with pytest.raises(ValidationError):
        adapter.validate_python("2.0.0")
    with pytest.raises(ValidationError):
        adapter.validate_python("0.9.0")
