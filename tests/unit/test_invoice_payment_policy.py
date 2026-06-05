from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.api import (
    ActionIntentIntakeService,
    build_invoice_payment_action_intent_payload,
    compute_invoice_payment_batch_hash,
)
from actenon.models import AudienceRef, DynamicContextInput
from actenon.policy import build_invoice_payment_policy_engine


class InvoicePaymentPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.intake = ActionIntentIntakeService()
        self.policy = build_invoice_payment_policy_engine()

    def _intent(
        self,
        *,
        payer_entity_id: str = "entity_demo_ap",
        supplier_id: str = "supplier_demo_001",
        bank_account_reference: str = "bank_demo_main",
        invoice_ids: tuple[str, ...] = ("inv_allow_001", "inv_allow_002"),
        amount_minor: int = 6500,
        currency: str = "USD",
        payment_date: str = "2026-01-15",
        payment_batch_id: str = "batch_allow_001",
        batch_hash: str | None = None,
        evidence_refs: list[dict[str, str]] | None = None,
    ):
        payload = build_invoice_payment_action_intent_payload(
            intent_id="intent_test_invoice_payment",
            tenant_id="tenant_demo",
            requester_id="demo_actor",
            payer_entity_id=payer_entity_id,
            supplier_id=supplier_id,
            bank_account_reference=bank_account_reference,
            invoice_ids=invoice_ids,
            amount_minor=amount_minor,
            currency=currency,
            payment_date=payment_date,
            payment_batch_id=payment_batch_id,
            issued_at=self.now,
            proposer_id="demo_actor",
            justification="Invoice payment wedge policy test",
            batch_hash=batch_hash,
            evidence_refs=evidence_refs,
        )
        return self.intake.parse(payload)

    def _context(
        self,
        *,
        expected_payer_entity_id: str = "entity_demo_ap",
        expected_supplier_id: str = "supplier_demo_001",
        expected_bank_account_reference: str = "bank_demo_main",
        expected_invoice_ids: tuple[str, ...] = ("inv_allow_001", "inv_allow_002"),
        expected_amount_minor: int = 6500,
        expected_currency: str = "USD",
        expected_payment_date: str = "2026-01-15",
        expected_batch_hash: str | None = None,
        required_approval_chain: tuple[str, ...] = (),
        provided_approval_chain: tuple[str, ...] = (),
        required_approver_types: tuple[str, ...] = ("finance-controller", "treasury-operator"),
        required_evidence_types: tuple[str, ...] = (),
        duplicate_invoice_ids: tuple[str, ...] = (),
    ) -> DynamicContextInput:
        if expected_batch_hash is None:
            expected_batch_hash = compute_invoice_payment_batch_hash(
                payer_entity_id=expected_payer_entity_id,
                supplier_id=expected_supplier_id,
                bank_account_reference=expected_bank_account_reference,
                invoice_ids=expected_invoice_ids,
                amount_minor=expected_amount_minor,
                currency=expected_currency,
                payment_date=expected_payment_date,
                payment_batch_id="batch_allow_001" if expected_invoice_ids == ("inv_allow_001", "inv_allow_002") else "batch_test",
            )
        return DynamicContextInput(
            request_id="req_test_invoice_payment",
            audience=AudienceRef(type="service", id="local-invoice-payment-endpoint"),
            scope_capabilities=("invoice_payment.execute",),
            now=self.now,
            facts={
                "expected_payer_entity_id": expected_payer_entity_id,
                "expected_supplier_id": expected_supplier_id,
                "expected_bank_account_reference": expected_bank_account_reference,
                "expected_invoice_ids": list(expected_invoice_ids),
                "expected_amount_minor": expected_amount_minor,
                "expected_currency": expected_currency,
                "expected_payment_date": expected_payment_date,
                "expected_batch_hash": expected_batch_hash,
                "required_approval_chain": list(required_approval_chain),
                "provided_approval_chain": list(provided_approval_chain),
                "required_approver_types": list(required_approver_types),
                "required_evidence_types": list(required_evidence_types),
                "duplicate_invoice_ids": list(duplicate_invoice_ids),
            },
            approver_types=required_approver_types,
            required_evidence_types=required_evidence_types,
        )

    def test_allow_flow(self) -> None:
        intent = self._intent()
        context = self._context(
            expected_batch_hash=intent.action.parameters["batch_hash"],
            required_approval_chain=("approver_manager", "approver_controller"),
            provided_approval_chain=("approver_manager", "approver_controller"),
        )
        decision = self.policy.evaluate(intent, context)
        self.assertEqual("allow", decision.outcome)

    def test_duplicate_invoice_payment_deny(self) -> None:
        intent = self._intent(invoice_ids=("inv_dup_001",), amount_minor=1200, payment_batch_id="batch_duplicate_001")
        context = self._context(
            expected_invoice_ids=("inv_dup_001",),
            expected_amount_minor=1200,
            expected_payment_date="2026-01-15",
            expected_batch_hash=intent.action.parameters["batch_hash"],
            duplicate_invoice_ids=("inv_dup_001",),
        )
        decision = self.policy.evaluate(intent, context)
        self.assertEqual("deny", decision.outcome)
        self.assertIn("DUPLICATE_INVOICE_PAYMENT", decision.reason_codes)

    def test_wrong_entity_deny(self) -> None:
        intent = self._intent(payer_entity_id="entity_other_ap", invoice_ids=("inv_entity_001",), amount_minor=1600, payment_date="2026-01-18", payment_batch_id="batch_entity_001")
        context = self._context(
            expected_invoice_ids=("inv_entity_001",),
            expected_amount_minor=1600,
            expected_payment_date="2026-01-18",
            expected_batch_hash=intent.action.parameters["batch_hash"],
        )
        decision = self.policy.evaluate(intent, context)
        self.assertEqual("deny", decision.outcome)
        self.assertIn("WRONG_ENTITY", decision.reason_codes)

    def test_bank_mismatch_deny(self) -> None:
        intent = self._intent(bank_account_reference="bank_demo_wrong", invoice_ids=("inv_bank_001",), amount_minor=1900, payment_date="2026-01-19", payment_batch_id="batch_bank_001")
        context = self._context(
            expected_invoice_ids=("inv_bank_001",),
            expected_amount_minor=1900,
            expected_payment_date="2026-01-19",
            expected_batch_hash=intent.action.parameters["batch_hash"],
        )
        decision = self.policy.evaluate(intent, context)
        self.assertEqual("deny", decision.outcome)
        self.assertIn("BANK_MISMATCH", decision.reason_codes)

    def test_approval_required_flow(self) -> None:
        intent = self._intent(invoice_ids=("inv_approval_001",), amount_minor=2200, payment_date="2026-01-16", payment_batch_id="batch_approval_001")
        context = self._context(
            expected_invoice_ids=("inv_approval_001",),
            expected_amount_minor=2200,
            expected_payment_date="2026-01-16",
            expected_batch_hash=intent.action.parameters["batch_hash"],
            required_approval_chain=("approver_manager", "approver_controller"),
            provided_approval_chain=("approver_manager",),
        )
        decision = self.policy.evaluate(intent, context)
        self.assertEqual("approval-required", decision.outcome)
        self.assertIn("finance-controller", decision.approver_types)

    def test_needs_evidence_flow(self) -> None:
        intent = self._intent(invoice_ids=("inv_evidence_001",), amount_minor=1800, payment_date="2026-01-17", payment_batch_id="batch_evidence_001")
        context = self._context(
            expected_invoice_ids=("inv_evidence_001",),
            expected_amount_minor=1800,
            expected_payment_date="2026-01-17",
            expected_batch_hash=intent.action.parameters["batch_hash"],
            required_evidence_types=("invoice_pdf", "supplier_statement"),
        )
        decision = self.policy.evaluate(intent, context)
        self.assertEqual("needs-evidence", decision.outcome)
        self.assertIn("invoice_pdf", decision.required_evidence)

    def test_batch_hash_mismatch_deny(self) -> None:
        intent = self._intent(
            invoice_ids=("inv_hash_001",),
            amount_minor=2100,
            payment_date="2026-01-20",
            payment_batch_id="batch_hash_001",
            batch_hash="batch_tampered_0001",
        )
        context = self._context(
            expected_invoice_ids=("inv_hash_001",),
            expected_amount_minor=2100,
            expected_payment_date="2026-01-20",
            expected_batch_hash=compute_invoice_payment_batch_hash(
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                invoice_ids=("inv_hash_001",),
                amount_minor=2100,
                currency="USD",
                payment_date="2026-01-20",
                payment_batch_id="batch_hash_001",
            ),
        )
        decision = self.policy.evaluate(intent, context)
        self.assertEqual("deny", decision.outcome)
        self.assertIn("BATCH_HASH_MISMATCH", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
