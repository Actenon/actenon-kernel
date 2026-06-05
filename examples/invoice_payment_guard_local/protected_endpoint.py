from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from actenon.api import compute_invoice_payment_batch_hash
from actenon.core.errors import RefusalException
from actenon.models import (
    InvoicePaymentReconciliationState,
    InvoiceRecord,
    PayeeEnrollment,
    PaymentBatchRecord,
    PaymentExecutionRecord,
    PaymentReconciliationRecord,
    ProtectedExecutionRequest,
)


def _seed_state() -> InvoicePaymentReconciliationState:
    return InvoicePaymentReconciliationState(
        resource_version=0,
        payee_enrollments={
            "entity_demo_ap:supplier_demo_001": PayeeEnrollment(
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                display_name="Supplier Demo Primary",
            ),
            "entity_demo_ap:supplier_demo_002": PayeeEnrollment(
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_002",
                bank_account_reference="bank_demo_secondary",
                display_name="Supplier Demo Secondary",
            ),
        },
        invoices={
            "inv_allow_001": InvoiceRecord(
                invoice_id="inv_allow_001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=4000,
                currency="USD",
            ),
            "inv_allow_002": InvoiceRecord(
                invoice_id="inv_allow_002",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=2500,
                currency="USD",
            ),
            "inv_dup_001": InvoiceRecord(
                invoice_id="inv_dup_001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=1200,
                currency="USD",
                status="paid",
                payment_execution_id="payment_local_seeded_0001",
            ),
            "inv_approval_001": InvoiceRecord(
                invoice_id="inv_approval_001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=2200,
                currency="USD",
            ),
            "inv_evidence_001": InvoiceRecord(
                invoice_id="inv_evidence_001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=1800,
                currency="USD",
            ),
            "inv_entity_001": InvoiceRecord(
                invoice_id="inv_entity_001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=1600,
                currency="USD",
            ),
            "inv_bank_001": InvoiceRecord(
                invoice_id="inv_bank_001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=1900,
                currency="USD",
            ),
            "inv_hash_001": InvoiceRecord(
                invoice_id="inv_hash_001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                amount_minor=2100,
                currency="USD",
            ),
        },
        payment_batches={
            "batch_allow_001": PaymentBatchRecord(
                payment_batch_id="batch_allow_001",
                payment_date="2026-01-15",
                batch_hash=compute_invoice_payment_batch_hash(
                    payer_entity_id="entity_demo_ap",
                    supplier_id="supplier_demo_001",
                    bank_account_reference="bank_demo_main",
                    invoice_ids=("inv_allow_001", "inv_allow_002"),
                    amount_minor=6500,
                    currency="USD",
                    payment_date="2026-01-15",
                    payment_batch_id="batch_allow_001",
                ),
            ),
            "batch_duplicate_001": PaymentBatchRecord(
                payment_batch_id="batch_duplicate_001",
                payment_date="2026-01-15",
                batch_hash=compute_invoice_payment_batch_hash(
                    payer_entity_id="entity_demo_ap",
                    supplier_id="supplier_demo_001",
                    bank_account_reference="bank_demo_main",
                    invoice_ids=("inv_dup_001",),
                    amount_minor=1200,
                    currency="USD",
                    payment_date="2026-01-15",
                    payment_batch_id="batch_duplicate_001",
                ),
                payment_execution_ids=("payment_local_seeded_0001",),
            ),
            "batch_approval_001": PaymentBatchRecord(
                payment_batch_id="batch_approval_001",
                payment_date="2026-01-16",
                batch_hash=compute_invoice_payment_batch_hash(
                    payer_entity_id="entity_demo_ap",
                    supplier_id="supplier_demo_001",
                    bank_account_reference="bank_demo_main",
                    invoice_ids=("inv_approval_001",),
                    amount_minor=2200,
                    currency="USD",
                    payment_date="2026-01-16",
                    payment_batch_id="batch_approval_001",
                ),
            ),
            "batch_evidence_001": PaymentBatchRecord(
                payment_batch_id="batch_evidence_001",
                payment_date="2026-01-17",
                batch_hash=compute_invoice_payment_batch_hash(
                    payer_entity_id="entity_demo_ap",
                    supplier_id="supplier_demo_001",
                    bank_account_reference="bank_demo_main",
                    invoice_ids=("inv_evidence_001",),
                    amount_minor=1800,
                    currency="USD",
                    payment_date="2026-01-17",
                    payment_batch_id="batch_evidence_001",
                ),
            ),
            "batch_entity_001": PaymentBatchRecord(
                payment_batch_id="batch_entity_001",
                payment_date="2026-01-18",
                batch_hash=compute_invoice_payment_batch_hash(
                    payer_entity_id="entity_demo_ap",
                    supplier_id="supplier_demo_001",
                    bank_account_reference="bank_demo_main",
                    invoice_ids=("inv_entity_001",),
                    amount_minor=1600,
                    currency="USD",
                    payment_date="2026-01-18",
                    payment_batch_id="batch_entity_001",
                ),
            ),
            "batch_bank_001": PaymentBatchRecord(
                payment_batch_id="batch_bank_001",
                payment_date="2026-01-19",
                batch_hash=compute_invoice_payment_batch_hash(
                    payer_entity_id="entity_demo_ap",
                    supplier_id="supplier_demo_001",
                    bank_account_reference="bank_demo_main",
                    invoice_ids=("inv_bank_001",),
                    amount_minor=1900,
                    currency="USD",
                    payment_date="2026-01-19",
                    payment_batch_id="batch_bank_001",
                ),
            ),
            "batch_hash_001": PaymentBatchRecord(
                payment_batch_id="batch_hash_001",
                payment_date="2026-01-20",
                batch_hash=compute_invoice_payment_batch_hash(
                    payer_entity_id="entity_demo_ap",
                    supplier_id="supplier_demo_001",
                    bank_account_reference="bank_demo_main",
                    invoice_ids=("inv_hash_001",),
                    amount_minor=2100,
                    currency="USD",
                    payment_date="2026-01-20",
                    payment_batch_id="batch_hash_001",
                ),
            ),
        },
        payment_executions={
            "payment_local_seeded_0001": PaymentExecutionRecord(
                payment_execution_id="payment_local_seeded_0001",
                payer_entity_id="entity_demo_ap",
                supplier_id="supplier_demo_001",
                bank_account_reference="bank_demo_main",
                invoice_ids=("inv_dup_001",),
                amount_minor=1200,
                currency="USD",
                payment_date="2026-01-15",
                payment_batch_id="batch_duplicate_001",
                proposer_id="demo_actor",
                request_id="req_seeded_duplicate",
                intent_id="intent_seeded_duplicate",
                pccb_id="pccb_seeded_duplicate",
                executed_at="2026-01-01T12:00:00Z",
                reconciliation_status="recorded-local",
            )
        },
        reconciliation_records={
            "recon_local_seeded_0001": PaymentReconciliationRecord(
                reconciliation_id="recon_local_seeded_0001",
                payment_execution_id="payment_local_seeded_0001",
                payment_batch_id="batch_duplicate_001",
                provider_reference="provider_local_seeded_0001",
                amount_minor=1200,
                currency="USD",
                status="recorded-local",
                recorded_at="2026-01-01T12:00:00Z",
            )
        },
    )


class LocalProtectedInvoicePaymentEndpoint:
    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            self._write_state(_seed_state())

    def handle(self, request: ProtectedExecutionRequest) -> dict[str, Any]:
        params = request.intent.action.parameters
        constraints = request.intent.action.constraints
        state = self._read_state()

        self._require(request.intent.target.resource_type == "payment_batch", "PAYMENT_BATCH_TARGET_INVALID", "Protected invoice payment execution requires a payment_batch target.")
        self._require(request.intent.target.resource_id == params["payment_batch_id"], "PAYMENT_BATCH_BINDING_MISMATCH", "The payment batch target does not match the requested payment batch.")
        self._require(constraints.get("exact_payer_entity_id") == params["payer_entity_id"], "PAYMENT_BINDING_MISMATCH", "Exact payer entity binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_supplier_id") == params["supplier_id"], "PAYMENT_BINDING_MISMATCH", "Exact supplier binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_bank_account_reference") == params["bank_account_reference"], "PAYMENT_BINDING_MISMATCH", "Exact bank reference binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_invoice_ids") == params["invoice_ids"], "PAYMENT_BINDING_MISMATCH", "Exact invoice-set binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_amount_minor") == params["amount_minor"], "PAYMENT_BINDING_MISMATCH", "Exact amount binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_currency") == params["currency"], "PAYMENT_BINDING_MISMATCH", "Exact currency binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_payment_date") == params["payment_date"], "PAYMENT_BINDING_MISMATCH", "Exact payment date binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_payment_batch_id") == params["payment_batch_id"], "PAYMENT_BINDING_MISMATCH", "Exact payment batch binding mismatch for protected invoice payment execution.")
        self._require(constraints.get("exact_batch_hash") == params["batch_hash"], "PAYMENT_BINDING_MISMATCH", "Exact batch hash binding mismatch for protected invoice payment execution.")

        batch = state.payment_batches.get(params["payment_batch_id"])
        self._require(batch is not None, "UNKNOWN_PAYMENT_BATCH", "The requested payment batch is not available in local proof state.")
        assert batch is not None
        self._require(batch.payment_date == params["payment_date"], "PAYMENT_DATE_MISMATCH", "The requested payment date does not match the protected batch.")
        self._require(batch.batch_hash == params["batch_hash"], "BATCH_HASH_MISMATCH", "The requested payment batch hash does not match the protected batch state.")

        enrollment_key = f"{params['payer_entity_id']}:{params['supplier_id']}"
        enrollment = state.payee_enrollments.get(enrollment_key)
        self._require(enrollment is not None, "WRONG_ENTITY", "The requested payer entity and supplier combination is not enrolled for payment execution.")
        assert enrollment is not None
        self._require(enrollment.bank_account_reference == params["bank_account_reference"], "BANK_MISMATCH", "The requested bank account reference does not match the enrolled payee bank details.")

        invoices: list[InvoiceRecord] = []
        for invoice_id in params["invoice_ids"]:
            invoice = state.invoices.get(invoice_id)
            self._require(invoice is not None, "INVOICE_SET_MISMATCH", "The requested invoice set does not match the protected invoice state.")
            assert invoice is not None
            invoices.append(invoice)

        for invoice in invoices:
            self._require(invoice.payer_entity_id == params["payer_entity_id"], "WRONG_ENTITY", "The requested payer entity does not match the invoice owner.")
            self._require(invoice.supplier_id == params["supplier_id"], "PAYEE_MISMATCH", "The requested supplier does not match the invoice payee.")
            self._require(invoice.bank_account_reference == params["bank_account_reference"], "BANK_MISMATCH", "The requested bank account reference does not match the invoice payee bank reference.")
            self._require(invoice.currency == params["currency"], "PAYMENT_CURRENCY_MISMATCH", "The requested currency does not match the invoice currency.")
            self._require(invoice.payment_execution_id is None and invoice.status != "paid", "DUPLICATE_INVOICE_PAYMENT", "The requested invoice payment duplicates an already-paid or already-scheduled invoice.")

        total_amount_minor = sum(invoice.amount_minor for invoice in invoices)
        self._require(total_amount_minor == int(params["amount_minor"]), "PAYMENT_AMOUNT_MISMATCH", "The requested payment amount does not match the sum of the protected invoice set.")

        payment_execution_id = f"payment_local_{len(state.payment_executions) + 1:04d}"
        reconciliation_id = f"recon_local_{len(state.reconciliation_records) + 1:04d}"
        provider_reference = f"provider_local_{len(state.reconciliation_records) + 1:04d}"

        updated_invoices = dict(state.invoices)
        for invoice in invoices:
            updated_invoices[invoice.invoice_id] = replace(invoice, status="paid", payment_execution_id=payment_execution_id)

        updated_batches = dict(state.payment_batches)
        updated_batches[batch.payment_batch_id] = replace(
            batch,
            payment_execution_ids=tuple(batch.payment_execution_ids) + (payment_execution_id,),
        )

        payment_record = PaymentExecutionRecord(
            payment_execution_id=payment_execution_id,
            payer_entity_id=params["payer_entity_id"],
            supplier_id=params["supplier_id"],
            bank_account_reference=params["bank_account_reference"],
            invoice_ids=tuple(params["invoice_ids"]),
            amount_minor=int(params["amount_minor"]),
            currency=str(params["currency"]),
            payment_date=str(params["payment_date"]),
            payment_batch_id=str(params["payment_batch_id"]),
            proposer_id=str(params["proposer_id"]),
            request_id=request.context.request_id,
            intent_id=request.intent.intent_id,
            pccb_id=request.pccb.pccb_id,
            executed_at=request.context.now.isoformat().replace("+00:00", "Z"),
            reconciliation_status="recorded-local",
        )
        reconciliation_record = PaymentReconciliationRecord(
            reconciliation_id=reconciliation_id,
            payment_execution_id=payment_execution_id,
            payment_batch_id=batch.payment_batch_id,
            provider_reference=provider_reference,
            amount_minor=int(params["amount_minor"]),
            currency=str(params["currency"]),
            status="recorded-local",
            recorded_at=request.context.now.isoformat().replace("+00:00", "Z"),
        )

        updated_state = InvoicePaymentReconciliationState(
            resource_version=state.resource_version + 1,
            payee_enrollments=state.payee_enrollments,
            invoices=updated_invoices,
            payment_batches=updated_batches,
            payment_executions={**state.payment_executions, payment_execution_id: payment_record},
            reconciliation_records={**state.reconciliation_records, reconciliation_id: reconciliation_record},
        )
        self._write_state(updated_state)

        return {
            "external_reference": provider_reference,
            "provider_reference": provider_reference,
            "resource_version": str(updated_state.resource_version),
            "state_path": str(self.state_path),
            "payment_execution_id": payment_execution_id,
            "reconciliation_id": reconciliation_id,
            "reconciliation_status": reconciliation_record.status,
            "payment_batch_id": batch.payment_batch_id,
            "invoice_ids": list(payment_record.invoice_ids),
            "payer_entity_id": payment_record.payer_entity_id,
            "supplier_id": payment_record.supplier_id,
            "bank_account_reference": payment_record.bank_account_reference,
            "amount_minor": payment_record.amount_minor,
            "currency": payment_record.currency,
            "operator_summary": (
                f"Invoice payment {payment_execution_id} recorded {payment_record.amount_minor} {payment_record.currency} "
                f"to supplier {payment_record.supplier_id} for invoices {', '.join(payment_record.invoice_ids)} "
                f"in batch {payment_record.payment_batch_id}. Reconciliation record {reconciliation_id} created."
            ),
        }

    def _read_state(self) -> InvoicePaymentReconciliationState:
        return InvoicePaymentReconciliationState.from_dict(json.loads(self.state_path.read_text(encoding="utf-8")))

    def _write_state(self, state: InvoicePaymentReconciliationState) -> None:
        self.state_path.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _require(self, condition: bool, refusal_code: str, message: str) -> None:
        if not condition:
            raise RefusalException(category="execution", refusal_code=refusal_code, message=message)
