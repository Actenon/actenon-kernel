"""Verifier SDK checks for the packaged conformance suite."""

from __future__ import annotations

import unittest
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.api.intake import ActionIntentIntakeService
from actenon.core import ProofVerificationError
from actenon.demo.portable_local_proof import (
    FIXED_BASE_TIME,
    build_hello_world_action_intent_payload,
    run_portable_local_proof_demo,
)
from actenon.models import AudienceRef, PolicyDecision
from actenon.proof import PCCBMinter, build_local_proof_signer
from actenon.verifier import VerifierSDK


class VerifierSdkConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = build_local_proof_signer()
        self.sdk = VerifierSDK(self.signer)
        self.intake = ActionIntentIntakeService()

    def _build_verified_materials(self):
        payload = build_hello_world_action_intent_payload()
        intent = self.intake.parse(payload)
        context = self.sdk.build_context(
            request_id="req_conformance_001",
            audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
            now=FIXED_BASE_TIME,
            scope_capabilities=("protected_resource.read",),
            parameter_constraints={"exact_message": "portable hello world"},
            resource_selectors=({"resource_id": "hello_resource_demo_001"},),
        )
        pccb = PCCBMinter(
            signer=self.signer,
            issuer=intent.requester,
            pccb_id_factory=lambda: "pccb_conformance_001",
            nonce_factory=lambda: "nonce-conformance-00000001",
        ).mint(
            intent,
            decision=PolicyDecision(
                outcome="allow",
                summary="Conformance test allow.",
                rule_evaluations=(),
                reason_codes=("LOCAL_PROOF_ALLOW",),
            ),
            context=context,
        )
        return payload, pccb.to_dict(), context

    def test_portable_local_proof_demo_runs(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            manifest = run_portable_local_proof_demo(artifact_root)
            self.assertTrue((artifact_root / "manifest.json").exists())
            self.assertEqual(artifact_root.resolve(), Path(manifest["artifact_root"]).resolve())

    def test_verifier_sdk_accepts_valid_local_proof(self) -> None:
        payload, pccb_payload, context = self._build_verified_materials()
        verified = self.sdk.verify(intent=payload, pccb=pccb_payload, context=context)
        self.assertEqual("hello_world.read", verified.intent.action.name)
        self.assertEqual("portable-hello-world-endpoint", verified.context.audience.id)

    def test_verifier_sdk_refuses_audience_mismatch(self) -> None:
        payload, pccb_payload, _ = self._build_verified_materials()
        wrong_context = self.sdk.build_context(
            request_id="req_conformance_wrong_audience",
            audience=AudienceRef(type="service", id="wrong-endpoint"),
            now=FIXED_BASE_TIME,
            scope_capabilities=("protected_resource.read",),
        )
        with self.assertRaises(ProofVerificationError):
            self.sdk.verify(intent=payload, pccb=pccb_payload, context=wrong_context)

    def test_verifier_sdk_refuses_action_mutation(self) -> None:
        payload, pccb_payload, context = self._build_verified_materials()
        mutated_payload = deepcopy(payload)
        mutated_payload["action"]["parameters"]["message"] = "tampered hello world"
        with self.assertRaises(ProofVerificationError):
            self.sdk.verify(intent=mutated_payload, pccb=pccb_payload, context=context)

    def test_verifier_sdk_refuses_expired_proof(self) -> None:
        payload, pccb_payload, _ = self._build_verified_materials()
        expired_context = self.sdk.build_context(
            request_id="req_conformance_expired",
            audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
            now=FIXED_BASE_TIME + timedelta(minutes=6),
            scope_capabilities=("protected_resource.read",),
        )
        with self.assertRaises(ProofVerificationError):
            self.sdk.verify(intent=payload, pccb=pccb_payload, context=expired_context)


if __name__ == "__main__":
    unittest.main()
