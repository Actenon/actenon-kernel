from __future__ import annotations

import unittest
from datetime import timedelta

from actenon.api.intake import ActionIntentIntakeService
from actenon.core import ProofVerificationError
from actenon.demo.portable_local_proof import FIXED_BASE_TIME, build_hello_world_action_intent_payload
from actenon.models import AudienceRef, PolicyDecision
from actenon.proof import PCCBMinter, build_local_proof_signer
from actenon.verifier import VerifierSDK


class ClockSkewToleranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = build_local_proof_signer()
        self.intake = ActionIntentIntakeService()
        self.intent_payload = build_hello_world_action_intent_payload()
        self.intent = self.intake.parse(self.intent_payload)
        self.audience = AudienceRef(type="service", id="portable-hello-world-endpoint")
        self.scope_capabilities = ("protected_resource.read",)
        self.parameter_constraints = {"exact_message": "portable hello world"}
        self.resource_selectors = ({"resource_id": "hello_resource_demo_001"},)

        minting_sdk = VerifierSDK(self.signer)
        minting_context = self._context(minting_sdk, now=FIXED_BASE_TIME, request_id="req_clock_skew_mint")
        self.pccb = PCCBMinter(
            signer=self.signer,
            issuer=self.intent.requester,
            pccb_id_factory=lambda: "pccb_clock_skew_001",
            nonce_factory=lambda: "nonce-clock-skew-00000001",
        ).mint(
            self.intent,
            decision=PolicyDecision(
                outcome="allow",
                summary="Clock skew test allow.",
                rule_evaluations=(),
                reason_codes=("LOCAL_PROOF_ALLOW",),
            ),
            context=minting_context,
        )

    def _context(self, sdk: VerifierSDK, *, now, request_id: str):
        return sdk.build_context(
            request_id=request_id,
            audience=self.audience,
            now=now,
            scope_capabilities=self.scope_capabilities,
            parameter_constraints=self.parameter_constraints,
            resource_selectors=self.resource_selectors,
        )

    def test_zero_tolerance_default_keeps_strict_boundary_behavior(self) -> None:
        sdk = VerifierSDK(self.signer)

        with self.assertRaises(ProofVerificationError) as not_yet_valid:
            sdk.verify(
                intent=self.intent,
                pccb=self.pccb,
                context=self._context(
                    sdk,
                    now=self.pccb.not_before - timedelta(seconds=1),
                    request_id="req_clock_skew_strict_early",
                ),
            )
        self.assertEqual("PROOF_NOT_YET_VALID", not_yet_valid.exception.refusal_code)

        with self.assertRaises(ProofVerificationError) as expired:
            sdk.verify(
                intent=self.intent,
                pccb=self.pccb,
                context=self._context(
                    sdk,
                    now=self.pccb.expires_at + timedelta(seconds=1),
                    request_id="req_clock_skew_strict_late",
                ),
            )
        self.assertEqual("PROOF_EXPIRED", expired.exception.refusal_code)

    def test_tolerance_accepts_small_early_or_late_clock_drift(self) -> None:
        sdk = VerifierSDK(self.signer, clock_skew_tolerance=timedelta(seconds=2))

        early = sdk.verify(
            intent=self.intent,
            pccb=self.pccb,
            context=self._context(
                sdk,
                now=self.pccb.not_before - timedelta(seconds=1),
                request_id="req_clock_skew_tolerant_early",
            ),
        )
        self.assertEqual(self.pccb.pccb_id, early.pccb.pccb_id)

        late = sdk.verify(
            intent=self.intent,
            pccb=self.pccb,
            context=self._context(
                sdk,
                now=self.pccb.expires_at + timedelta(seconds=1),
                request_id="req_clock_skew_tolerant_late",
            ),
        )
        self.assertEqual(self.pccb.pccb_id, late.pccb.pccb_id)

    def test_tolerance_refuses_clock_drift_beyond_configured_limit(self) -> None:
        sdk = VerifierSDK(self.signer, clock_skew_tolerance=timedelta(seconds=2))

        with self.assertRaises(ProofVerificationError) as not_yet_valid:
            sdk.verify(
                intent=self.intent,
                pccb=self.pccb,
                context=self._context(
                    sdk,
                    now=self.pccb.not_before - timedelta(seconds=3),
                    request_id="req_clock_skew_beyond_early",
                ),
            )
        self.assertEqual("PROOF_NOT_YET_VALID", not_yet_valid.exception.refusal_code)

        with self.assertRaises(ProofVerificationError) as expired:
            sdk.verify(
                intent=self.intent,
                pccb=self.pccb,
                context=self._context(
                    sdk,
                    now=self.pccb.expires_at + timedelta(seconds=3),
                    request_id="req_clock_skew_beyond_late",
                ),
            )
        self.assertEqual("PROOF_EXPIRED", expired.exception.refusal_code)

    def test_negative_tolerance_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            VerifierSDK(self.signer, clock_skew_tolerance=timedelta(seconds=-1))


if __name__ == "__main__":
    unittest.main()
