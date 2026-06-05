from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from actenon.api import ActionIntentIntakeService
from actenon.core import ProtectedExecutionKernel
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.evidence.stores import InMemoryPCCBStore
from actenon.models import AudienceRef, DynamicContextInput, PCCB, PartyRef, PolicyDecision
from actenon.policy import (
    CapabilityScopeHardRule,
    HardRuleEngine,
    IntentChronologyHardRule,
    IntentTtlHardRule,
    PolicyEngine,
    TenantWorkflowRule,
    TenantWorkflowRuleLayer,
)
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier
from actenon.proof.canonical import canonicalize_bytes
from actenon.proof.signers import HttpProofSealClient, NoOpProofSealClient, ProofSealError
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.verifier import ProtectedEndpointMiddleware


class _FailingProofSealClient:
    def seal(self, *, intent, decision, context, pccb):
        raise ProofSealError("PROOF_SEAL_FAILED", "seal service unavailable", retryable=True)


class _StaticProofSealClient:
    def __init__(self, sealed_pccb: PCCB) -> None:
        self.sealed_pccb = sealed_pccb

    def seal(self, *, intent, decision, context, pccb):
        return self.sealed_pccb


class ProofSealKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 4, 11, 11, 0, tzinfo=timezone.utc)
        self.payload = {
            "contract": {"name": "action_intent", "version": "v1"},
            "intent_id": "intent_proof_seal_001",
            "issued_at": self.now.isoformat().replace("+00:00", "Z"),
            "expires_at": (self.now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "tenant": {"tenant_id": "tenant_alpha"},
            "requester": {"type": "service", "id": "actor_123"},
            "action": {
                "name": "refund.create",
                "capability": "refund.execute",
                "parameters": {"amount_minor": 1000, "currency": "USD"},
            },
            "target": {"resource_type": "payment", "resource_id": "pay_001"},
        }
        self.context = DynamicContextInput(
            request_id="req_proof_seal_001",
            audience=AudienceRef(type="service", id="protected-endpoint"),
            scope_capabilities=("refund.execute",),
            now=self.now,
            facts={"risk_level": "normal"},
        )
        self.signer = HmacSha256Signer(secret=b"proof-seal-secret", key_id="proof-seal-local")

    def _build_kernel(self, *, proof_seal_client=None, require_proof_seal: bool = False, pccb_store=None):
        writer = InMemoryOutcomeWriter()
        receipt_factory = ReceiptFactory(receipt_id_factory=lambda: "rcpt_proof_seal")
        refusal_factory = RefusalFactory(refusal_id_factory=lambda: "rfsl_proof_seal")
        escrow = InMemoryCapabilityEscrow()
        policy = PolicyEngine(
            hard_rules=HardRuleEngine((IntentChronologyHardRule(), IntentTtlHardRule(), CapabilityScopeHardRule())),
            tenant_workflow_rules=TenantWorkflowRuleLayer(
                tenant_rules={
                    "tenant_alpha": (
                        TenantWorkflowRule(
                            rule_id="tenant_alpha.refund.allow",
                            outcome="allow",
                            summary="The tenant workflow authorizes this action.",
                            reason_code="WORKFLOW_ALLOW",
                            capabilities=("refund.execute",),
                            required_fact_values={"risk_level": "normal"},
                        ),
                    )
                }
            ),
        )
        middleware = ProtectedEndpointMiddleware(
            proof_verifier=PCCBVerifier(self.signer),
            escrow=escrow,
            receipt_factory=receipt_factory,
            refusal_factory=refusal_factory,
            outcome_writer=writer,
        )
        kernel = ProtectedExecutionKernel(
            intake=ActionIntentIntakeService(),
            policy_engine=policy,
            pccb_minter=PCCBMinter(
                signer=self.signer,
                issuer=PartyRef(type="service", id="kernel"),
                pccb_id_factory=lambda: "pccb_local_001",
                nonce_factory=lambda: "nonce-local-0001",
            ),
            escrow=escrow,
            middleware=middleware,
            receipt_factory=receipt_factory,
            refusal_factory=refusal_factory,
            outcome_writer=writer,
            pccb_store=pccb_store,
            escrow_id_factory=lambda: "esc_proof_seal_001",
            proof_seal_client=proof_seal_client,
            require_proof_seal=require_proof_seal,
        )
        return kernel, writer, escrow

    def _sealed_pccb(self, local_pccb: PCCB) -> PCCB:
        sealed = replace(
            local_pccb,
            pccb_id="pccb_sealed_001",
            issuer=PartyRef(type="service", id="trust-seal"),
            nonce="nonce-sealed-0001",
        )
        signature = self.signer.sign(canonicalize_bytes(sealed.unsigned_payload()))
        return replace(sealed, signature=signature)

    def test_noop_mode_preserves_local_pccb(self) -> None:
        kernel, writer, escrow = self._build_kernel(proof_seal_client=NoOpProofSealClient())

        admission = kernel.submit_intent(self.payload, self.context)

        self.assertIsNone(admission.refusal)
        self.assertEqual("pccb_local_001", admission.pccb.pccb_id)
        self.assertEqual("pccb_local_001", escrow.inspect("esc_proof_seal_001").pccb_id)
        self.assertEqual("pccb_local_001", writer.receipts[0].correlation.pccb_id)

    def test_successful_sealing_path_uses_substituted_pccb(self) -> None:
        intake = ActionIntentIntakeService()
        intent = intake.parse(self.payload)
        decision = self._build_kernel()[0].policy_engine.evaluate(intent, self.context)
        local_pccb = PCCBMinter(
            signer=self.signer,
            issuer=PartyRef(type="service", id="kernel"),
            pccb_id_factory=lambda: "pccb_local_001",
            nonce_factory=lambda: "nonce-local-0001",
        ).mint(intent, decision, self.context, escrow_id="esc_proof_seal_001")
        sealed_pccb = self._sealed_pccb(local_pccb)
        pccb_store = InMemoryPCCBStore()
        kernel, writer, escrow = self._build_kernel(
            proof_seal_client=_StaticProofSealClient(sealed_pccb),
            pccb_store=pccb_store,
        )

        admission = kernel.submit_intent(self.payload, self.context)

        self.assertIsNone(admission.refusal)
        self.assertEqual("pccb_sealed_001", admission.pccb.pccb_id)
        self.assertEqual("pccb_sealed_001", escrow.inspect("esc_proof_seal_001").pccb_id)
        self.assertEqual("pccb_sealed_001", writer.receipts[0].correlation.pccb_id)
        self.assertEqual("pccb_sealed_001", pccb_store.get_pccb("pccb_sealed_001").pccb_id)

    def test_required_sealing_failure_returns_refusal_and_skips_escrow(self) -> None:
        kernel, writer, escrow = self._build_kernel(
            proof_seal_client=_FailingProofSealClient(),
            require_proof_seal=True,
        )

        admission = kernel.submit_intent(self.payload, self.context)

        self.assertIsNotNone(admission.refusal)
        self.assertEqual("PROOF_SEAL_FAILED", admission.refusal.refusal_code)
        self.assertIsNone(admission.pccb)
        self.assertEqual([], writer.receipts)
        self.assertEqual(1, len(writer.refusals))
        self.assertIsNone(escrow.inspect("esc_proof_seal_001"))

    def test_disabled_sealing_preserves_existing_kernel_behavior(self) -> None:
        kernel, writer, escrow = self._build_kernel(proof_seal_client=None)

        admission = kernel.submit_intent(self.payload, self.context)

        self.assertIsNone(admission.refusal)
        self.assertEqual("pccb_local_001", admission.pccb.pccb_id)
        self.assertEqual("pccb_local_001", writer.receipts[0].correlation.pccb_id)
        self.assertEqual("pccb_local_001", escrow.inspect("esc_proof_seal_001").pccb_id)


class HttpProofSealClientTests(unittest.TestCase):
    def _minimal_inputs(self) -> tuple:
        now = datetime(2026, 4, 11, 11, 0, tzinfo=timezone.utc)
        payload = {
            "contract": {"name": "action_intent", "version": "v1"},
            "intent_id": "intent_http_proof_seal_minimal",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "tenant": {"tenant_id": "tenant_alpha"},
            "requester": {"type": "service", "id": "actor_123"},
            "action": {
                "name": "refund.create",
                "capability": "refund.execute",
                "parameters": {"amount_minor": 1000, "currency": "USD"},
            },
            "target": {"resource_type": "payment", "resource_id": "pay_001"},
        }
        signer = HmacSha256Signer(secret=b"http-proof-seal-secret", key_id="proof-seal-http")
        intent = ActionIntentIntakeService().parse(payload)
        context = DynamicContextInput(
            request_id="req_http_proof_seal_minimal",
            audience=AudienceRef(type="service", id="protected-endpoint"),
            scope_capabilities=("refund.execute",),
            now=now,
        )
        decision = PolicyDecision(
            outcome="allow",
            summary="Minimal proof-seal test allow.",
            rule_evaluations=(),
            reason_codes=("TEST_ALLOW",),
        )
        pccb = PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="kernel"),
            pccb_id_factory=lambda: "pccb_http_minimal_001",
            nonce_factory=lambda: "nonce-http-minimal-0001",
        ).mint(intent, decision, context, escrow_id="esc_http_minimal_001")
        return intent, decision, context, pccb

    def test_http_client_returns_pccb_from_json_response(self) -> None:
        now = datetime(2026, 4, 11, 11, 0, tzinfo=timezone.utc)
        payload = {
            "contract": {"name": "action_intent", "version": "v1"},
            "intent_id": "intent_http_proof_seal_001",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "tenant": {"tenant_id": "tenant_alpha"},
            "requester": {"type": "service", "id": "actor_123"},
            "action": {
                "name": "refund.create",
                "capability": "refund.execute",
                "parameters": {"amount_minor": 1000, "currency": "USD"},
            },
            "target": {"resource_type": "payment", "resource_id": "pay_001"},
        }
        signer = HmacSha256Signer(secret=b"http-proof-seal-secret", key_id="proof-seal-http")
        intake = ActionIntentIntakeService()
        intent = intake.parse(payload)
        context = DynamicContextInput(
            request_id="req_http_proof_seal_001",
            audience=AudienceRef(type="service", id="protected-endpoint"),
            scope_capabilities=("refund.execute",),
            now=now,
            facts={"risk_level": "normal"},
        )
        decision = PolicyEngine(
            hard_rules=HardRuleEngine((IntentChronologyHardRule(), IntentTtlHardRule(), CapabilityScopeHardRule())),
            tenant_workflow_rules=TenantWorkflowRuleLayer(
                tenant_rules={
                    "tenant_alpha": (
                        TenantWorkflowRule(
                            rule_id="tenant_alpha.refund.allow",
                            outcome="allow",
                            summary="The tenant workflow authorizes this action.",
                            reason_code="WORKFLOW_ALLOW",
                            capabilities=("refund.execute",),
                            required_fact_values={"risk_level": "normal"},
                        ),
                    )
                }
            ),
        ).evaluate(intent, context)
        local_pccb = PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="kernel"),
            pccb_id_factory=lambda: "pccb_http_local_001",
            nonce_factory=lambda: "nonce-http-local-0001",
        ).mint(intent, decision, context, escrow_id="esc_http_proof_seal_001")
        sealed = replace(
            local_pccb,
            pccb_id="pccb_http_sealed_001",
            issuer=PartyRef(type="service", id="trust-seal"),
        )
        sealed = replace(sealed, signature=signer.sign(canonicalize_bytes(sealed.unsigned_payload())))

        def transport(url: str, body: bytes, timeout_seconds: float) -> bytes:
            self.assertEqual("https://trust.example/seal", url)
            request_payload = json.loads(body)
            self.assertEqual("intent_http_proof_seal_001", request_payload["intent"]["intent_id"])
            return json.dumps({"pccb": sealed.to_dict()}).encode("utf-8")

        client = HttpProofSealClient(endpoint_url="https://trust.example/seal", transport=transport)

        result = client.seal(intent=intent, decision=decision, context=context, pccb=local_pccb)

        self.assertEqual("pccb_http_sealed_001", result.pccb_id)

    def test_http_client_rejects_duplicate_json_keys_in_response(self) -> None:
        intent, decision, context, pccb = self._minimal_inputs()

        def transport(url: str, body: bytes, timeout_seconds: float) -> bytes:
            return b'{"pccb":{},"pccb":{}}'

        client = HttpProofSealClient(endpoint_url="https://trust.example/seal", transport=transport)

        with self.assertRaisesRegex(ProofSealError, "invalid JSON"):
            client.seal(intent=intent, decision=decision, context=context, pccb=pccb)


if __name__ == "__main__":
    unittest.main()
