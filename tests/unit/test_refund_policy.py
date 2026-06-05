from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.api import ActionIntentIntakeService, build_refund_action_intent_payload
from actenon.models import AudienceRef, DynamicContextInput
from actenon.policy import build_refund_policy_engine


class RefundPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.intake = ActionIntentIntakeService()
        self.policy = build_refund_policy_engine()

    def _intent(self, *, amount_minor: int = 1500):
        payload = build_refund_action_intent_payload(
            intent_id="intent_test_refund",
            tenant_id="tenant_demo",
            requester_id="actor_demo",
            payment_id="payment_demo_001",
            amount_minor=amount_minor,
            currency="USD",
            issued_at=self.now,
            justification="Refund wedge policy test",
        )
        return self.intake.parse(payload)

    def _context(self, *, risk_level: str, remaining_refundable_minor: int = 5000):
        return DynamicContextInput(
            request_id=f"req_{risk_level}",
            audience=AudienceRef(type="service", id="local-refund-endpoint"),
            scope_capabilities=("refund.execute",),
            now=self.now,
            facts={
                "risk_level": risk_level,
                "payment_id": "payment_demo_001",
                "payment_currency": "USD",
                "remaining_refundable_minor": remaining_refundable_minor,
            },
            approver_types=("finance-operator",),
            required_evidence_types=("external_id",),
        )

    def test_allow_flow(self) -> None:
        decision = self.policy.evaluate(self._intent(), self._context(risk_level="normal"))
        self.assertEqual("allow", decision.outcome)

    def test_deny_flow(self) -> None:
        decision = self.policy.evaluate(self._intent(), self._context(risk_level="blocked"))
        self.assertEqual("deny", decision.outcome)

    def test_approval_required_flow(self) -> None:
        decision = self.policy.evaluate(self._intent(amount_minor=2200), self._context(risk_level="approval"))
        self.assertEqual("approval-required", decision.outcome)
        self.assertIn("finance-operator", decision.approver_types)

    def test_needs_evidence_flow(self) -> None:
        decision = self.policy.evaluate(self._intent(), self._context(risk_level="review"))
        self.assertEqual("needs-evidence", decision.outcome)
        self.assertIn("external_id", decision.required_evidence)

    def test_exact_amount_limit_deny(self) -> None:
        decision = self.policy.evaluate(self._intent(amount_minor=6000), self._context(risk_level="normal", remaining_refundable_minor=5000))
        self.assertEqual("deny", decision.outcome)
        self.assertIn("REFUND_AMOUNT_EXCEEDS_BALANCE", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
