from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.api import ActionIntentIntakeService, build_refund_action_intent_payload
from actenon.models import AudienceRef, DynamicContextInput, PolicyDecision, RuleEvaluation
from actenon.models.intent_record import IntentRecord, build_intent_record


class IntentRecordTests(unittest.TestCase):
    def _build_intent(self):
        issued_at = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        payload = build_refund_action_intent_payload(
            intent_id="intent_refund_record_001",
            tenant_id="tenant_demo",
            requester_id="demo_actor",
            payment_id="payment_demo_001",
            amount_minor=1500,
            currency="USD",
            issued_at=issued_at,
        )
        return ActionIntentIntakeService().parse(payload), issued_at

    def test_build_intent_record_derives_boundaries_from_context_and_decision(self) -> None:
        intent, issued_at = self._build_intent()
        context = DynamicContextInput(
            request_id="req_intent_record_001",
            audience=AudienceRef(type="service", id="local-refund-endpoint"),
            scope_capabilities=("refund.execute",),
            now=issued_at,
            facts={
                "prohibited_actions": ("refund.currency_override", "refund.target_override"),
                "abort_conditions": ("remaining_refundable_minor_below_requested_amount",),
                "blast_radius_limits": {
                    "max_payment_targets": {"value": 1, "summary": "Only one payment may be targeted."},
                    "max_amount_minor": {"value": 1500, "summary": "Do not exceed the delegated amount.", "unit": "minor_units"},
                },
                "required_approval_chain": ("approver_manager",),
            },
            required_evidence_types=("external_id",),
        )
        decision = PolicyDecision(
            outcome="needs-evidence",
            summary="Additional evidence is required before execution can proceed.",
            rule_evaluations=(
                RuleEvaluation(
                    rule_id="workflow.evidence",
                    outcome="needs-evidence",
                    reason_code="EVIDENCE_MISSING",
                    summary="Additional evidence is required before execution can proceed.",
                    required_evidence=("external_id",),
                ),
            ),
            reason_codes=("EVIDENCE_MISSING",),
            required_evidence=("external_id",),
        )

        record = build_intent_record(
            source="unit-test",
            intent=intent,
            context=context,
            decision=decision,
            receipt_id="rcpt_decision_001",
        )

        self.assertEqual("intent_refund_record_001", record.intent_id)
        self.assertEqual("needs-evidence", record.decision.outcome)
        self.assertEqual(("refund.currency_override", "refund.target_override"), record.boundaries.prohibited_actions)
        self.assertEqual(("remaining_refundable_minor_below_requested_amount",), record.boundaries.abort_conditions)
        self.assertEqual(("approver_manager",), record.boundaries.required_approvals)
        self.assertEqual(("external_id",), record.boundaries.required_evidence)
        self.assertEqual("not-issued", record.proof.status)
        self.assertEqual("rcpt_decision_001", record.execution_evidence.receipt_id)
        self.assertEqual(2, len(record.boundaries.blast_radius_limits))

    def test_intent_record_round_trips(self) -> None:
        intent, issued_at = self._build_intent()
        context = DynamicContextInput(
            request_id="req_intent_record_002",
            audience=AudienceRef(type="service", id="local-refund-endpoint"),
            scope_capabilities=("refund.execute",),
            now=issued_at,
        )
        decision = PolicyDecision(
            outcome="allow",
            summary="The refund is approved for protected execution.",
            rule_evaluations=(),
            reason_codes=("WORKFLOW_ALLOW",),
        )
        record = build_intent_record(
            source="unit-test",
            intent=intent,
            context=context,
            decision=decision,
            pccb_id="pccb_001",
            receipt_id="rcpt_001",
        )

        parsed = IntentRecord.from_dict(record.to_dict())
        self.assertEqual(record, parsed)
        self.assertEqual("issued", parsed.proof.status)
        self.assertEqual("pccb_001", parsed.proof.pccb_id)


if __name__ == "__main__":
    unittest.main()
