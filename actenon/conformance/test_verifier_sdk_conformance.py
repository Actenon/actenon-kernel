"""Verifier SDK checks for the packaged conformance suite."""

from __future__ import annotations

import json
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
from actenon.models.contracts import parse_timestamp
from actenon.proof import PCCBMinter, VerifierDisclosureMode, build_local_proof_signer
from actenon.verifier import VerifierSDK


VECTOR_ROOT = Path(__file__).resolve().parent / "vectors" / "verifier_sdk_v1"


def _load_vector(relative_path: str):
    return json.loads((VECTOR_ROOT / relative_path).read_text(encoding="utf-8"))


def _set_path(document: dict[str, object], path: list[str], value: object) -> None:
    current = document
    for segment in path[:-1]:
        child = current.get(segment)
        if not isinstance(child, dict):
            raise AssertionError(f"vector path does not resolve to an object: {path}")
        current = child
    current[path[-1]] = value


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

    def test_shared_cross_sdk_conformance_vectors(self) -> None:
        manifest = _load_vector("cases.json")
        base = manifest["base"]
        base_intent = _load_vector(base["intent"])
        base_pccb = _load_vector(base["pccb"])

        for case in manifest["cases"]:
            with self.subTest(case=case["id"]):
                intent = deepcopy(base_intent)
                pccb = deepcopy(base_pccb)
                context_payload = deepcopy(base["context"])
                mutation = case.get("mutation")
                if mutation is not None:
                    document = {
                        "intent": intent,
                        "pccb": pccb,
                        "context": context_payload,
                    }[mutation["document"]]
                    _set_path(document, mutation["path"], mutation["value"])

                sdk = VerifierSDK(
                    self.signer,
                    clock_skew_tolerance=timedelta(
                        milliseconds=case["clock_skew_tolerance_ms"]
                    ),
                    # Conformance vectors test granular refusal codes
                    # including pre-authentication failures (e.g.,
                    # SIGNATURE_INVALID, SCOPE_CAPABILITY_MISMATCH on
                    # mutated PCCBs). Use local_debug mode to preserve
                    # the pre-2B granular diagnostic codes the vectors
                    # expect. Production deployments use public_generic.
                    disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG,
                )
                context = sdk.build_context(
                    request_id=context_payload["request_id"],
                    audience=AudienceRef.from_dict(
                        context_payload["audience"],
                        "context.audience",
                    ),
                    now=parse_timestamp(context_payload["now"], "context.now"),
                    scope_capabilities=tuple(
                        context_payload["scope_capabilities"]
                    ),
                    parameter_constraints=dict(
                        context_payload["parameter_constraints"]
                    ),
                    resource_selectors=tuple(
                        context_payload["resource_selectors"]
                    ),
                )
                expected = case["expected"]
                if expected["outcome"] == "verified":
                    verified = sdk.verify(
                        intent=intent,
                        pccb=pccb,
                        context=context,
                    )
                    self.assertEqual(
                        "pccb_portable_hello_world_001",
                        verified.pccb.pccb_id,
                    )
                    continue

                with self.assertRaises(ProofVerificationError) as raised:
                    sdk.verify(intent=intent, pccb=pccb, context=context)
                self.assertEqual(
                    expected["reason_code"],
                    raised.exception.refusal_code,
                )
                self.assertEqual(expected["message"], raised.exception.message)


if __name__ == "__main__":
    unittest.main()
