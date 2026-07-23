from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.api import ActionIntentIntakeService, build_refund_action_intent_payload
from actenon.models import (
    ActionSpec,
    AudienceRef,
    CorrelationRef,
    PartyRef,
    Receipt,
    TargetRef,
    TenantRef,
    receipt_evidence_ref,
)
from actenon.models.runtime import DynamicContextInput
from actenon.policy import ReceiptEvidenceVerificationRule
from actenon.receipts import InMemoryReceiptStore


class ReceiptEvidencePolicyRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 4, 11, 15, 0, tzinfo=timezone.utc)
        self.intake = ActionIntentIntakeService()

    def _context(self) -> DynamicContextInput:
        return DynamicContextInput(
            request_id="req_receipt_evidence_001",
            audience=AudienceRef(type="service", id="refund-endpoint"),
            scope_capabilities=("refund.execute",),
            now=self.now,
            facts={"risk_level": "normal"},
        )

    def _receipt(self, *, receipt_id: str = "rcpt_refund_001", outcome: str = "executed", capability: str = "refund.execute") -> Receipt:
        return Receipt(
            receipt_id=receipt_id,
            intent_id="intent_receipt_source_001",
            occurred_at=self.now,
            outcome=outcome,
            phase="execution",
            tenant=TenantRef(tenant_id="tenant_demo"),
            subject=PartyRef(type="service", id="demo_actor"),
            action=ActionSpec(
                name="refund.create" if capability == "refund.execute" else "invoice_payment.execute",
                capability=capability,
                parameters={"amount_minor": 1200, "currency": "USD"},
            ),
            target=TargetRef(resource_type="payment", resource_id="pay_demo_001"),
            summary="Prior consequential action outcome.",
            correlation=CorrelationRef(request_id="req_receipt_source_001"),
            side_effects={"state": "completed"},
        )

    def _intent(self, *, evidence_refs: list[dict[str, object]] | None = None):
        payload = build_refund_action_intent_payload(
            intent_id="intent_receipt_chain_001",
            tenant_id="tenant_demo",
            requester_id="demo_actor",
            payment_id="pay_demo_001",
            amount_minor=1200,
            currency="USD",
            issued_at=self.now,
            evidence_refs=evidence_refs,
        )
        return self.intake.parse(payload)

    def test_no_receipt_refs_returns_none(self) -> None:
        rule = ReceiptEvidenceVerificationRule(receipt_store=InMemoryReceiptStore())

        evaluation = rule.evaluate(self._intent(), self._context())

        self.assertIsNone(evaluation)

    def test_receipt_missing_denies(self) -> None:
        ref = receipt_evidence_ref(self._receipt())
        rule = ReceiptEvidenceVerificationRule(receipt_store=InMemoryReceiptStore())

        evaluation = rule.evaluate(self._intent(evidence_refs=[ref.to_dict()]), self._context())

        self.assertIsNotNone(evaluation)
        assert evaluation is not None
        self.assertEqual("deny", evaluation.outcome)
        self.assertEqual("RECEIPT_EVIDENCE_MISSING", evaluation.reason_code)

    def test_digest_mismatch_denies(self) -> None:
        receipt = self._receipt()
        ref_payload = receipt_evidence_ref(receipt).to_dict()
        ref_payload["digest"]["value"] = "deadbeef" * 8
        rule = ReceiptEvidenceVerificationRule(receipt_store=InMemoryReceiptStore.from_receipts((receipt,)))

        evaluation = rule.evaluate(self._intent(evidence_refs=[ref_payload]), self._context())

        self.assertIsNotNone(evaluation)
        assert evaluation is not None
        self.assertEqual("deny", evaluation.outcome)
        self.assertEqual("RECEIPT_EVIDENCE_DIGEST_MISMATCH", evaluation.reason_code)

    def test_wrong_outcome_denies(self) -> None:
        receipt = self._receipt(outcome="approval-required")
        rule = ReceiptEvidenceVerificationRule(receipt_store=InMemoryReceiptStore.from_receipts((receipt,)))

        evaluation = rule.evaluate(self._intent(evidence_refs=[receipt_evidence_ref(receipt).to_dict()]), self._context())

        self.assertIsNotNone(evaluation)
        assert evaluation is not None
        self.assertEqual("deny", evaluation.outcome)
        self.assertEqual("RECEIPT_EVIDENCE_OUTCOME_INVALID", evaluation.reason_code)

    def test_capability_mismatch_denies(self) -> None:
        receipt = self._receipt(capability="refund.execute")
        rule = ReceiptEvidenceVerificationRule(
            receipt_store=InMemoryReceiptStore.from_receipts((receipt,)),
            required_capability="invoice_payment.execute",
        )

        evaluation = rule.evaluate(self._intent(evidence_refs=[receipt_evidence_ref(receipt).to_dict()]), self._context())

        self.assertIsNotNone(evaluation)
        assert evaluation is not None
        self.assertEqual("deny", evaluation.outcome)
        self.assertEqual("RECEIPT_EVIDENCE_CAPABILITY_MISMATCH", evaluation.reason_code)

    def test_successful_verification_returns_none(self) -> None:
        receipt = self._receipt()
        rule = ReceiptEvidenceVerificationRule(
            receipt_store=InMemoryReceiptStore.from_receipts((receipt,)),
            required_capability="refund.execute",
        )

        evaluation = rule.evaluate(self._intent(evidence_refs=[receipt_evidence_ref(receipt).to_dict()]), self._context())

        self.assertIsNone(evaluation)


if __name__ == "__main__":
    unittest.main()
