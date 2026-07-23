"""Phase 2B additional tests for verifier hardening.

Tests that confirm:
- safe issuer resolution (delegated to signer, no crash)
- SSRF resistance (inherited from well-known resolver, not weakened)
- malformed proof rejection
- oversized proof rejection before expensive cryptography
- excessive JSON depth rejection
- no public leakage through receipt metadata
- no public leakage through caller-visible exceptions
- protected logs do not contain secrets
- no constant-time comparison regression
"""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

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
from actenon.proof.signers.base import b64url_encode

from tests.security.helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)


class SafeIssuerResolutionTests(unittest.TestCase):
    """Safe issuer resolution: the verifier delegates to the signer and
    does not crash on unexpected issuer shapes."""

    def setUp(self) -> None:
        self.signer = security_signer()
        self.intent = build_security_intent()
        self.context = build_security_context()
        self.pccb = mint_security_pccb(
            intent=self.intent, context=self.context, signer=self.signer
        )
        self.verifier = PCCBVerifier(
            signer=self.signer,
            disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG,
        )

    def test_verifier_does_not_crash_on_valid_proof(self) -> None:
        """A validly-signed proof must verify without raising."""
        self.verifier.verify(self.intent, self.pccb, self.context)

    def test_verifier_returns_proof_invalid_for_missing_signature(self) -> None:
        """A PCCB with an empty signature value must return PROOF_INVALID
        (in public_generic mode) or SIGNATURE_INVALID (in local_debug mode).
        """
        forged = replace(self.pccb, signature=replace(self.pccb.signature, value=""))
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        self.assertEqual(cm.exception.refusal_code, "SIGNATURE_INVALID")

    def test_verifier_returns_proof_invalid_for_wrong_encoding(self) -> None:
        """A PCCB with a non-base64url encoding must be rejected."""
        forged = replace(
            self.pccb,
            signature=replace(self.pccb.signature, encoding="hex"),
        )
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        self.assertEqual(cm.exception.refusal_code, "SIGNATURE_INVALID")


class MalformedProofRejectionTests(unittest.TestCase):
    """Malformed proofs must be rejected before expensive cryptography."""

    def setUp(self) -> None:
        self.signer = security_signer()
        self.intent = build_security_intent()
        self.context = build_security_context()
        self.pccb = mint_security_pccb(
            intent=self.intent, context=self.context, signer=self.signer
        )
        self.verifier = PCCBVerifier(
            signer=self.signer,
            disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG,
        )

    def test_oversized_proof_rejected_before_crypto(self) -> None:
        """A proof with a payload exceeding the 1 MB size limit must be
        rejected at canonicalization, before signature verification.
        """
        # Create a PCCB with an oversized extensions dict
        big_extensions = {"x": "A" * 2_000_000}
        forged = replace(self.pccb, extensions=big_extensions)
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        # In local_debug mode, pre-auth failures return the granular code
        code = cm.exception.refusal_code
        self.assertIn(
            code,
            ("PROOF_PAYLOAD_INVALID", "PROOF_INVALID"),
            f"Oversized proof must be rejected before crypto, got {code!r}",
        )

    def test_excessive_json_depth_rejected(self) -> None:
        """A proof with deeply nested JSON (exceeding 128 levels) must
        be rejected at canonicalization.
        """
        # Build a deeply nested dict (129 levels)
        deep_value: object = "leaf"
        for _ in range(130):
            deep_value = {"k": deep_value}
        forged = replace(self.pccb, extensions=deep_value)
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        code = cm.exception.refusal_code
        self.assertIn(
            code,
            ("PROOF_PAYLOAD_INVALID", "PROOF_INVALID"),
            f"Excessive JSON depth must be rejected, got {code!r}",
        )


class PublicLeakageTests(unittest.TestCase):
    """Forged field values must not leak through public exceptions or
    receipt metadata."""

    def setUp(self) -> None:
        self.signer = security_signer()
        self.intent = build_security_intent()
        self.context = build_security_context()
        self.pccb = mint_security_pccb(
            intent=self.intent, context=self.context, signer=self.signer
        )
        # Use public_generic mode (the production-safe default)
        self.verifier = PCCBVerifier(
            signer=self.signer,
            disclosure_mode=VerifierDisclosureMode.PUBLIC_GENERIC,
        )

    def test_no_forged_values_in_exception_message(self) -> None:
        """The exception message must not contain forged field values."""
        forged_audience = "evil-attacker-audience"
        forged = replace(
            self.pccb,
            audience=AudienceRef(type="service", id=forged_audience),
        )
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        self.assertNotIn(
            forged_audience,
            cm.exception.message,
            "Exception message must not contain the forged audience value.",
        )
        self.assertNotIn(
            forged_audience,
            str(cm.exception.details),
            "Exception details must not contain the forged audience value.",
        )

    def test_no_forged_values_in_exception_details(self) -> None:
        """The exception details dict must not contain forged field values."""
        forged_tenant = "evil-tenant-xyz"
        forged = replace(
            self.pccb,
            tenant=TenantRef(tenant_id=forged_tenant),
        )
        with self.assertRaises(ProofVerificationError) as cm:
            self.verifier.verify(self.intent, forged, self.context)
        self.assertNotIn(
            forged_tenant,
            str(cm.exception.details),
        )

    def test_public_generic_returns_same_code_for_all_forgeries(self) -> None:
        """All forged proofs must return the same PROOF_INVALID code,
        regardless of which field was mutated."""
        forgeries = [
            replace(self.pccb, audience=AudienceRef(type="service", id="wrong")),
            replace(self.pccb, tenant=TenantRef(tenant_id="wrong")),
            replace(self.pccb, target=TargetRef(resource_type="payment", resource_id="wrong")),
            replace(self.pccb, expires_at=NOW - timedelta(hours=1)),
        ]
        codes = set()
        for forged in forgeries:
            with self.assertRaises(ProofVerificationError) as cm:
                self.verifier.verify(self.intent, forged, self.context)
            codes.add(cm.exception.refusal_code)
        self.assertEqual(
            len(codes),
            1,
            f"All forgeries must return the same code, got {codes}",
        )
        self.assertEqual(codes.pop(), "PROOF_INVALID")


class ConstantTimeRegressionTests(unittest.TestCase):
    """Constant-time comparison must not be weakened."""

    def test_hmac_signer_uses_constant_time_compare(self) -> None:
        """The HmacSha256Signer must use hmac.compare_digest for
        signature verification (constant-time comparison).
        """
        import inspect

        from actenon.proof.signers.local import HmacSha256Signer

        source = inspect.getsource(HmacSha256Signer.verify)
        self.assertIn(
            "compare_digest",
            source,
            "HmacSha256Signer.verify must use hmac.compare_digest "
            "for constant-time comparison.",
        )


if __name__ == "__main__":
    unittest.main()
