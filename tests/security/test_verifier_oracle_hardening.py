"""Phase 2A regression tests for verifier oracle-hardening.

These tests define the non-oracular verifier behaviour required by
PHASE 2A. They are expected to FAIL until Phase 2B implements the
hardening described in docs/internal/verifier-oracle-hardening.md.

Security objective:
  Unauthenticated or invalidly-signed forged proofs must not use
  detailed public refusal codes as a field-by-field semantic oracle.

Tests 1-5 and 9-11 cover the new behaviour (expected to FAIL).
Tests 6-8 cover preserved post-authentication semantics (expected to PASS).
"""

from __future__ import annotations

import json
import os
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from actenon.core.errors import ProofVerificationError
from actenon.models import (
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
)
from actenon.proof import PCCBVerifier, VerifierDisclosureMode, build_action_hash_input, sha256_hex
from actenon.proof.canonical import canonicalize_bytes
from actenon.proof.signers import HmacSha256Signer
from actenon.proof.signers.base import b64url_decode, b64url_encode

from .helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
    resign_pccb,
    security_signer,
)


# ---------------------------------------------------------------------------
# Helpers for forged (invalidly-signed) proofs
# ---------------------------------------------------------------------------


def _forge_pccb_with_replacement(pccb: PCCB, **kwargs: Any) -> PCCB:
    """Return a copy of pccb with the given fields replaced, WITHOUT
    re-signing. The resulting PCCB carries a stale signature over the
    original fields - i.e., it is invalidly signed.

    This is the attacker's tool: change a field, keep the old signature,
    probe the verifier to see which refusal code comes back.
    """
    return replace(pccb, **kwargs)


def _forge_with_wrong_audience(pccb: PCCB) -> PCCB:
    return _forge_pccb_with_replacement(
        pccb,
        audience=AudienceRef(type="service", id="wrong-audience"),
    )


def _forge_with_wrong_tenant(pccb: PCCB) -> PCCB:
    return _forge_pccb_with_replacement(
        pccb,
        tenant=TenantRef(tenant_id="wrong-tenant"),
    )


def _forge_with_wrong_target(pccb: PCCB) -> PCCB:
    return _forge_pccb_with_replacement(
        pccb,
        target=TargetRef(resource_type="payment", resource_id="wrong-target"),
    )


def _forge_with_expired_timestamp(pccb: PCCB) -> PCCB:
    expired = NOW - timedelta(hours=1)
    return _forge_pccb_with_replacement(
        pccb,
        expires_at=expired,
        not_before=expired - timedelta(minutes=5),
    )


def _forge_with_several_changed_fields(pccb: PCCB) -> PCCB:
    """Change audience, tenant, target, and action_hash all at once."""
    return _forge_pccb_with_replacement(
        pccb,
        audience=AudienceRef(type="service", id="wrong-audience"),
        tenant=TenantRef(tenant_id="wrong-tenant"),
        target=TargetRef(resource_type="payment", resource_id="wrong-target"),
        action_hash=ActionHashSpec(
            algorithm="sha-256",
            canonicalization="RFC8785-JCS",
            value="0" * 64,
        ),
    )


# ---------------------------------------------------------------------------
# Helpers for validly-signed proofs with post-authentication mismatches
# ---------------------------------------------------------------------------


def _validly_signed_with_wrong_audience(
    intent: ActionIntent, context: DynamicContextInput, signer: HmacSha256Signer
) -> tuple[PCCB, ActionIntent, DynamicContextInput]:
    """Mint a validly-signed PCCB for a DIFFERENT audience than the
    verification context, then verify against the original context.
    The signature is valid (signed by the real signer) but the audience
    doesn't match - this is a post-authentication mismatch.
    """
    # Build an intent/context pair with a different audience
    forged_intent = build_security_intent()
    forged_context = replace(
        build_security_context(),
        audience=AudienceRef(type="service", id="different-audience"),
    )
    pccb = mint_security_pccb(intent=forged_intent, context=forged_context, signer=signer)
    # Now verify against the ORIGINAL context (mismatched audience)
    return pccb, forged_intent, context


def _validly_signed_with_wrong_action(
    intent: ActionIntent, context: DynamicContextInput, signer: HmacSha256Signer
) -> tuple[PCCB, ActionIntent, DynamicContextInput]:
    """Mint a validly-signed PCCB for intent A, then verify it against
    intent B (same capability, different action parameters). The
    signature is valid (signed by the real signer over intent A's
    fields), but intent B's action parameters don't match the PCCB's
    bound action. This should return ACTION_MISMATCH (post-authentication).
    """
    # Mint the PCCB for the ORIGINAL intent (valid signature)
    pccb = mint_security_pccb(intent=intent, context=context, signer=signer)
    # Build a DIFFERENT intent with the SAME capability but DIFFERENT
    # amount_minor (a parameter change, not a capability change).
    # This ensures the scope check passes but the action equality check
    # fails with ACTION_MISMATCH.
    verify_intent = build_security_intent(
        capability=intent.action.capability,  # same capability
        amount_minor=intent.action.parameters["amount_minor"] + 1,  # different amount
        target_id=intent.target.resource_id,  # same target
    )
    return pccb, verify_intent, context


def _validly_signed_with_wrong_target(
    intent: ActionIntent, context: DynamicContextInput, signer: HmacSha256Signer
) -> tuple[PCCB, ActionIntent, DynamicContextInput]:
    """Mint a validly-signed PCCB for intent A, then verify it against
    intent B (different target). The signature is valid but the target
    doesn't match.
    """
    # Mint the PCCB for the ORIGINAL intent (valid signature)
    pccb = mint_security_pccb(intent=intent, context=context, signer=signer)
    # Build a DIFFERENT intent with a different target to verify against
    verify_intent = build_security_intent(target_id="different-target")
    return pccb, verify_intent, context


# ===========================================================================
# FORGED PROOF TESTS - expected to FAIL until Phase 2B
# ===========================================================================


class ForgedProofOracleTests(unittest.TestCase):
    """Tests 1-5: forged (invalidly-signed) proofs must NOT reveal which
    field is wrong. They must all return PROOF_INVALID.

    These tests are EXPECTED TO FAIL against the current verifier because
    the current verifier checks semantic fields BEFORE the signature,
    leaking which field was forged.
    """

    def setUp(self) -> None:
        self.signer = security_signer()
        self.intent = build_security_intent()
        self.context = build_security_context()
        self.pccb = mint_security_pccb(
            intent=self.intent, context=self.context, signer=self.signer
        )
        # Use public_generic mode — the production-safe default that
        # collapses all pre-auth failures to PROOF_INVALID.
        self.verifier = PCCBVerifier(
            signer=self.signer,
            disclosure_mode=VerifierDisclosureMode.PUBLIC_GENERIC,
        )

    def test_1_forged_wrong_audience_returns_proof_invalid(self) -> None:
        """A forged proof with the wrong audience must NOT return
        AUDIENCE_MISMATCH. It must return PROOF_INVALID (or another
        generic pre-authentication code).

        Currently FAILS: the verifier checks audience (line 128) before
        the signature (line 203), so it returns AUDIENCE_MISMATCH even
        though the signature is now stale.
        """
        forged = _forge_with_wrong_audience(self.pccb)
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        code = cm.exception.refusal_code
        self.assertEqual(
            code,
            "PROOF_INVALID",
            f"Forged proof with wrong audience must return PROOF_INVALID, "
            f"not {code!r}. The current code leaks that the audience is "
            f"the wrong field, which lets an attacker probe field-by-field.",
        )

    def test_2_forged_wrong_tenant_returns_proof_invalid(self) -> None:
        """A forged proof with the wrong tenant must NOT return
        TENANT_MISMATCH. It must return PROOF_INVALID.

        Currently FAILS: tenant is checked at line 148 before signature.
        """
        forged = _forge_with_wrong_tenant(self.pccb)
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        code = cm.exception.refusal_code
        self.assertEqual(
            code,
            "PROOF_INVALID",
            f"Forged proof with wrong tenant must return PROOF_INVALID, "
            f"not {code!r}.",
        )

    def test_3_forged_wrong_target_returns_proof_invalid(self) -> None:
        """A forged proof with the wrong target must NOT return
        TARGET_MISMATCH. It must return PROOF_INVALID.

        Currently FAILS: target is checked at line 163 before signature.
        """
        forged = _forge_with_wrong_target(self.pccb)
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        code = cm.exception.refusal_code
        self.assertEqual(
            code,
            "PROOF_INVALID",
            f"Forged proof with wrong target must return PROOF_INVALID, "
            f"not {code!r}.",
        )

    def test_4_forged_expired_timestamp_returns_proof_invalid(self) -> None:
        """A forged proof with an expired timestamp must NOT return
        PROOF_EXPIRED. It must return PROOF_INVALID.

        Currently FAILS: not_before/expires_at are checked at lines
        118-123 before the signature.
        """
        forged = _forge_with_expired_timestamp(self.pccb)
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        code = cm.exception.refusal_code
        self.assertEqual(
            code,
            "PROOF_INVALID",
            f"Forged proof with expired timestamp must return "
            f"PROOF_INVALID, not {code!r}.",
        )

    def test_5_forged_several_fields_same_generic_result(self) -> None:
        """A forged proof with several changed fields must return the
        SAME generic PROOF_INVALID code as the single-field forgeries.

        This ensures the attacker cannot distinguish "many fields wrong"
        from "one field wrong" - both are PROOF_INVALID.

        Currently FAILS: the verifier returns whichever semantic check
        fails first (e.g., AUDIENCE_MISMATCH if audience is wrong,
        TENANT_MISMATCH if only tenant is wrong, etc.).
        """
        forged_single = _forge_with_wrong_audience(self.pccb)
        forged_many = _forge_with_several_changed_fields(self.pccb)
        with self.assertRaises(ProofVerificationError) as cm_single:
            self.verifier.verify(self.intent, forged_single, self.context)
        with self.assertRaises(ProofVerificationError) as cm_many:
            self.verifier.verify(self.intent, forged_many, self.context)
        self.assertEqual(
            cm_single.exception.refusal_code,
            cm_many.exception.refusal_code,
            "Single-field and multi-field forgeries must return the same "
            "generic code so the attacker cannot distinguish them.",
        )
        self.assertEqual(
            cm_single.exception.refusal_code,
            "PROOF_INVALID",
            "Both forgeries must return PROOF_INVALID.",
        )


# ===========================================================================
# VALIDLY-SIGNED POST-AUTHENTICATION TESTS - expected to PASS
# ===========================================================================


class ValidlySignedPostAuthTests(unittest.TestCase):
    """Tests 6-8: validly-signed proofs with post-authentication
    semantic mismatches must still return the existing detailed codes.

    These tests verify the preserved semantic distinction:
      - AUDIENCE_MISMATCH (test 6)
      - ACTION_MISMATCH (test 7)
      - TARGET_MISMATCH (test 8)

    These tests are EXPECTED TO PASS against the current verifier
    because the current verifier already returns these codes for
    validly-signed proofs (the signature verifies, then the semantic
    check fails).
    """

    def setUp(self) -> None:
        self.signer = security_signer()
        self.intent = build_security_intent()
        self.context = build_security_context()
        # Use trusted_detailed mode so validly-signed proofs with
        # post-authentication mismatches return the detailed code
        # (not PROOF_INVALID).
        self.verifier = PCCBVerifier(
            signer=self.signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )

    def test_6_validly_signed_audience_mismatch_returns_audience_mismatch(self) -> None:
        """A validly-signed proof with the wrong audience must return
        AUDIENCE_MISMATCH (not PROOF_INVALID). The signature is
        authentic, so the operator is allowed to know which policy
        check failed.
        """
        pccb, wrong_intent, original_context = _validly_signed_with_wrong_audience(
            self.intent, self.context, self.signer
        )
        # Verify the wrong-audience PCCB against the original context.
        # The signature will verify (it's signed by the real signer),
        # but the audience won't match.
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(wrong_intent, pccb, original_context)
        self.assertEqual(
            cm.exception.refusal_code,
            "AUDIENCE_MISMATCH",
            "Validly-signed proof with wrong audience must preserve "
            "AUDIENCE_MISMATCH (post-authentication semantic check).",
        )

    def test_7_validly_signed_action_mismatch_returns_action_mismatch(self) -> None:
        """A validly-signed proof with the wrong action must return
        ACTION_MISMATCH (not PROOF_INVALID).
        """
        pccb, wrong_intent, original_context = _validly_signed_with_wrong_action(
            self.intent, self.context, self.signer
        )
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(wrong_intent, pccb, original_context)
        # ACTION_MISMATCH or INTENT_MISMATCH - both are acceptable because
        # the action parameters differ. The point is that it's a
        # post-authentication detailed code, not PROOF_INVALID.
        code = cm.exception.refusal_code
        self.assertIn(
            code,
            ("ACTION_MISMATCH", "INTENT_MISMATCH"),
            f"Validly-signed proof with wrong action must preserve a "
            f"detailed post-authentication code, not PROOF_INVALID. "
            f"Got {code!r}.",
        )

    def test_8_validly_signed_target_mismatch_returns_target_mismatch(self) -> None:
        """A validly-signed proof with the wrong target must return
        TARGET_MISMATCH (not PROOF_INVALID).
        """
        pccb, wrong_intent, original_context = _validly_signed_with_wrong_target(
            self.intent, self.context, self.signer
        )
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(wrong_intent, pccb, original_context)
        code = cm.exception.refusal_code
        self.assertIn(
            code,
            ("TARGET_MISMATCH", "ACTION_MISMATCH"),
            f"Validly-signed proof with wrong target must preserve a "
            f"detailed post-authentication code, not PROOF_INVALID. "
            f"Got {code!r}.",
        )


# ===========================================================================
# DIAGNOSTICS + RECEIPT REDACTION + ENVIRONMENT GUARD - expected to FAIL
# ===========================================================================


class LocalDebugAndRedactionTests(unittest.TestCase):
    """Tests 9-11: local-debug diagnostics, receipt redaction, and
    environment-guarded disclosure modes.

    These tests are EXPECTED TO FAIL until Phase 2B adds:
      - VerifierDisclosureMode enum
      - PCCBVerifier(disclosure_mode=...) parameter
      - local_debug mode with environment guard
      - RefusalFactory redaction of forged field values
    """

    def test_9_local_debug_retains_precise_reasons(self) -> None:
        """In local_debug mode, the verifier emits granular pre-signature
        refusal codes for debugging. A forged PCCB with a stale signature
        returns SIGNATURE_INVALID (the pre-auth granular code), not
        PROOF_INVALID (the public_generic collapse).
        """
        verifier = PCCBVerifier(
            signer=security_signer(),
            disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG,
        )
        intent = build_security_intent()
        context = build_security_context()
        pccb = mint_security_pccb(intent=intent, context=context)
        forged = _forge_with_wrong_audience(pccb)
        with self.assertRaises(ProofVerificationError) as cm:
            verifier.verify(intent, forged, context)
        # In local_debug mode, pre-auth failures return the granular code
        # (SIGNATURE_INVALID for a stale-signature PCCB), not PROOF_INVALID.
        self.assertEqual(
            cm.exception.refusal_code,
            "SIGNATURE_INVALID",
            "local_debug mode must retain granular pre-signature refusal "
            "codes for debugging. Expected SIGNATURE_INVALID for a forged "
            f"PCCB with stale signature, got {cm.exception.refusal_code!r}.",
        )

    def test_10_public_receipt_excludes_forged_field_values(self) -> None:
        """A receipt emitted for a forged-proof refusal must NOT include
        the attacker-supplied forged field values. Only the structural
        refusal reason (PROOF_INVALID) is recorded.
        """
        from actenon.receipts import RefusalFactory

        signer = security_signer()
        intent = build_security_intent()
        context = build_security_context()
        pccb = mint_security_pccb(intent=intent, context=context, signer=signer)
        forged = _forge_with_wrong_audience(pccb)

        # Use public_generic mode so forged proofs return PROOF_INVALID
        # instead of the detailed AUDIENCE_MISMATCH.
        verifier = PCCBVerifier(
            signer=signer,
            disclosure_mode=VerifierDisclosureMode.PUBLIC_GENERIC,
        )
        try:
            verifier.verify(intent, forged, context)
        except ProofVerificationError as exc:
            refusal = RefusalFactory().create_from_exception(
                exc,
                occurred_at=NOW,
                intent=intent,
                context=context,
                pccb_id=forged.pccb_id,
            )
            # The receipt's reason_code must be PROOF_INVALID, not
            # AUDIENCE_MISMATCH.
            self.assertEqual(
                refusal.reason_code,
                "PROOF_INVALID",
                f"Receipt for forged proof must record PROOF_INVALID, "
                f"not {refusal.reason_code!r}.",
            )
            # The receipt's message must NOT contain the forged audience.
            forged_audience = "wrong-audience"
            self.assertNotIn(
                forged_audience,
                refusal.message,
                "Receipt message must not echo the attacker-supplied "
                "forged field value.",
            )
            return
        self.fail("Forged proof should have raised ProofVerificationError.")

    def test_11_local_debug_refused_in_production_like_env(self) -> None:
        """local_debug mode must be impossible to enable accidentally
        in a production-like environment. Setting ACTENON_ENV=production
        and attempting to construct a local_debug verifier must raise
        ValueError (fail-closed).
        """
        # Create the signer BEFORE setting ACTENON_ENV=production,
        # because the HMAC signer itself has a production guard.
        signer = security_signer()

        # Save and restore the environment.
        original_env = os.environ.get("ACTENON_ENV")
        os.environ["ACTENON_ENV"] = "production"
        try:
            with self.assertRaises(ValueError):
                PCCBVerifier(
                    signer=signer,
                    disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG,
                )
        finally:
            if original_env is None:
                os.environ.pop("ACTENON_ENV", None)
            else:
                os.environ["ACTENON_ENV"] = original_env


if __name__ == "__main__":
    unittest.main()
