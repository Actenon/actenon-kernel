from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.evidence import InMemoryPCCBStore
from actenon.execution_graph import (
    NoOpExecutionGraphClient,
    build_execution_anchor_hash,
    create_execution_anchor_from_receipt,
    create_execution_anchor_from_refusal,
)
from actenon.models import (
    ActionHashSpec,
    ActionSpec,
    AudienceRef,
    CorrelationRef,
    ExecutionAnchor,
    PCCB,
    PartyRef,
    Receipt,
    Refusal,
    ScopeSpec,
    SignatureSpec,
    TenantRef,
    TargetRef,
    sha256_artifact_hex,
)
from actenon.receipts import InMemoryOutcomeWriter


class _RecordingExecutionGraphClient:
    def __init__(self) -> None:
        self.anchors: list[ExecutionAnchor] = []

    def publish(self, anchor: ExecutionAnchor) -> None:
        self.anchors.append(anchor)


class _FailingExecutionGraphClient:
    def publish(self, anchor: ExecutionAnchor) -> None:
        raise RuntimeError("publish failed")


class ExecutionGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 4, 11, 14, 0, tzinfo=timezone.utc)
        self.tenant = TenantRef(tenant_id="tenant_alpha")
        self.requester = PartyRef(type="service", id="actor_123")
        self.action = ActionSpec(
            name="refund.create",
            capability="refund.execute",
            parameters={"amount_minor": 1000, "currency": "USD"},
        )
        self.target = TargetRef(resource_type="payment", resource_id="pay_001")
        self.action_hash = ActionHashSpec(
            algorithm="sha-256",
            canonicalization="RFC8785-JCS",
            value="ab" * 32,
        )
        self.pccb = PCCB(
            pccb_id="pccb_graph_001",
            intent_id="intent_graph_001",
            issued_at=self.now,
            not_before=self.now,
            expires_at=self.now,
            issuer=PartyRef(type="service", id="kernel"),
            subject=self.requester,
            tenant=self.tenant,
            audience=AudienceRef(type="service", id="refund-endpoint"),
            action=self.action,
            target=self.target,
            scope=ScopeSpec(mode="exact", capabilities=("refund.execute",), single_use=True),
            nonce="nonce_graph_001",
            action_hash=self.action_hash,
            signature=SignatureSpec(
                algorithm="HS256",
                key_id="local-proof-v1",
                encoding="base64url",
                value="signature_graph_001",
            ),
            escrow_id="esc_graph_001",
        )
        self.executed_receipt = Receipt(
            receipt_id="rcpt_graph_001",
            intent_id="intent_graph_001",
            occurred_at=self.now,
            outcome="executed",
            tenant=self.tenant,
            subject=self.requester,
            action=self.action,
            target=self.target,
            summary="Refund executed.",
            phase="execution",
            correlation=CorrelationRef(
                pccb_id=self.pccb.pccb_id,
                escrow_id=self.pccb.escrow_id,
                action_hash=self.action_hash,
            ),
        )
        self.refusal = Refusal(
            refusal_id="rfsl_graph_001",
            category="proof",
            reason_code="AUDIENCE_MISMATCH",
            message="The proof audience does not match this endpoint.",
            retryable=False,
            refused_at=self.now,
            intent_id="intent_graph_001",
            tenant=self.tenant,
            subject=self.requester,
            audience=AudienceRef(type="service", id="wrong-endpoint"),
            action=self.action,
            target=self.target,
            correlation=CorrelationRef(
                pccb_id=self.pccb.pccb_id,
                escrow_id=self.pccb.escrow_id,
                action_hash=self.action_hash,
            ),
        )

    def test_execution_anchor_hash_is_deterministic_and_uses_shared_artifact_hashing(self) -> None:
        anchor = create_execution_anchor_from_receipt(
            self.executed_receipt,
            self.pccb,
            published_at=self.now,
            metadata={"publisher": "unit-test"},
        )

        self.assertEqual(build_execution_anchor_hash(anchor), build_execution_anchor_hash(anchor))
        self.assertEqual(sha256_artifact_hex(anchor), build_execution_anchor_hash(anchor))

    def test_receipt_based_anchor_creation_uses_receipt_and_pccb_digests(self) -> None:
        anchor = create_execution_anchor_from_receipt(self.executed_receipt, self.pccb, published_at=self.now)

        self.assertEqual("executed", anchor.outcome)
        self.assertEqual(self.pccb.action_hash, anchor.action_hash)
        self.assertEqual(self.executed_receipt.receipt_id, self.executed_receipt.receipt_id)
        self.assertEqual(self.pccb.pccb_id, self.pccb.pccb_id)
        self.assertIsNotNone(anchor.receipt_digest)
        self.assertIsNone(anchor.refusal_digest)

    def test_refusal_based_anchor_creation_uses_refusal_and_pccb_digests(self) -> None:
        anchor = create_execution_anchor_from_refusal(self.refusal, self.pccb, published_at=self.now)

        self.assertEqual("refused", anchor.outcome)
        self.assertEqual(self.pccb.action_hash, anchor.action_hash)
        self.assertIsNone(anchor.receipt_digest)
        self.assertIsNotNone(anchor.refusal_digest)

    def test_noop_client_accepts_anchor_without_side_effect(self) -> None:
        client = NoOpExecutionGraphClient()
        anchor = create_execution_anchor_from_receipt(self.executed_receipt, self.pccb, published_at=self.now)

        self.assertIsNone(client.publish(anchor))

    def test_outcome_writer_publishes_executed_receipt_and_refusal_anchors(self) -> None:
        client = _RecordingExecutionGraphClient()
        writer = InMemoryOutcomeWriter(
            pccb_store=InMemoryPCCBStore.from_pccbs((self.pccb,)),
            execution_graph_client=client,
        )

        writer.write_receipt(self.executed_receipt)
        writer.write_refusal(self.refusal)

        self.assertEqual(2, len(client.anchors))
        self.assertEqual("executed", client.anchors[0].outcome)
        self.assertEqual("refused", client.anchors[1].outcome)

    def test_outcome_writer_logs_warning_and_preserves_write_when_publication_fails(self) -> None:
        writer = InMemoryOutcomeWriter(
            pccb_store=InMemoryPCCBStore.from_pccbs((self.pccb,)),
            execution_graph_client=_FailingExecutionGraphClient(),
        )

        with self.assertLogs("actenon.receipts.writers", level="WARNING") as logs:
            writer.write_receipt(self.executed_receipt)

        self.assertEqual(1, len(writer.receipts))
        self.assertIn("Execution anchor publication failed", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
