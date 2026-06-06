from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.api import ActionIntentIntakeService
from actenon.core import ProtectedExecutionKernel
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.models import AudienceRef, DynamicContextInput, PartyRef
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
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.verifier import ProtectedEndpointMiddleware


class ReplayMiddlewareIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.replay_db = Path(self.tempdir.name) / "replay.sqlite3"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_duplicate_request_is_refused_by_replay_layer(self) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "contract": {"name": "action_intent", "version": "v1"},
            "intent_id": "intent_demo_001",
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
        context = DynamicContextInput(
            request_id="req_demo_001",
            audience=AudienceRef(type="service", id="protected-endpoint"),
            scope_capabilities=("refund.execute",),
            now=now,
            facts={"risk_level": "normal"},
        )
        signer = HmacSha256Signer(secret=b"demo-secret", key_id="local-demo")
        writer = InMemoryOutcomeWriter()
        receipt_factory = ReceiptFactory()
        refusal_factory = RefusalFactory()
        escrow = InMemoryCapabilityEscrow()
        replay_protector = ReplayProtector(SqliteReplayStore(self.replay_db))
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
            proof_verifier=PCCBVerifier(signer),
            escrow=escrow,
            receipt_factory=receipt_factory,
            refusal_factory=refusal_factory,
            outcome_writer=writer,
            replay_protector=replay_protector,
        )
        kernel = ProtectedExecutionKernel(
            intake=ActionIntentIntakeService(),
            policy_engine=policy,
            pccb_minter=PCCBMinter(signer=signer, issuer=PartyRef(type="service", id="kernel")),
            escrow=escrow,
            middleware=middleware,
            receipt_factory=receipt_factory,
            refusal_factory=refusal_factory,
            outcome_writer=writer,
        )

        admission = kernel.submit_intent(payload, context)
        request = kernel.build_execution_request(intent=admission.intent, pccb=admission.pccb, context=context)
        first = kernel.execute(request, lambda req: {"external_reference": "exec_001"})
        duplicate = kernel.execute(request, lambda req: {"external_reference": "exec_002"})

        self.assertIsNone(first.refusal)
        self.assertIsNotNone(duplicate.refusal)
        self.assertEqual("DUPLICATE_REPLAY", duplicate.refusal.reason_code)


if __name__ == "__main__":
    unittest.main()
