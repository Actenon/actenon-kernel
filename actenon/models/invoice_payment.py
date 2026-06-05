from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PayeeEnrollment:
    payer_entity_id: str
    supplier_id: str
    bank_account_reference: str
    display_name: str | None = None

    @property
    def enrollment_key(self) -> str:
        return f"{self.payer_entity_id}:{self.supplier_id}"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PayeeEnrollment":
        return cls(
            payer_entity_id=str(raw["payer_entity_id"]),
            supplier_id=str(raw["supplier_id"]),
            bank_account_reference=str(raw["bank_account_reference"]),
            display_name=raw.get("display_name"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "payer_entity_id": self.payer_entity_id,
            "supplier_id": self.supplier_id,
            "bank_account_reference": self.bank_account_reference,
        }
        if self.display_name is not None:
            payload["display_name"] = self.display_name
        return payload


@dataclass(frozen=True)
class InvoiceRecord:
    invoice_id: str
    payer_entity_id: str
    supplier_id: str
    bank_account_reference: str
    amount_minor: int
    currency: str
    status: str = "approved"
    payment_execution_id: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "InvoiceRecord":
        return cls(
            invoice_id=str(raw["invoice_id"]),
            payer_entity_id=str(raw["payer_entity_id"]),
            supplier_id=str(raw["supplier_id"]),
            bank_account_reference=str(raw["bank_account_reference"]),
            amount_minor=int(raw["amount_minor"]),
            currency=str(raw["currency"]),
            status=str(raw.get("status", "approved")),
            payment_execution_id=raw.get("payment_execution_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "invoice_id": self.invoice_id,
            "payer_entity_id": self.payer_entity_id,
            "supplier_id": self.supplier_id,
            "bank_account_reference": self.bank_account_reference,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "status": self.status,
        }
        if self.payment_execution_id is not None:
            payload["payment_execution_id"] = self.payment_execution_id
        return payload


@dataclass(frozen=True)
class PaymentBatchRecord:
    payment_batch_id: str
    payment_date: str
    batch_hash: str
    payment_execution_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PaymentBatchRecord":
        return cls(
            payment_batch_id=str(raw["payment_batch_id"]),
            payment_date=str(raw["payment_date"]),
            batch_hash=str(raw["batch_hash"]),
            payment_execution_ids=tuple(str(item) for item in raw.get("payment_execution_ids", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "payment_batch_id": self.payment_batch_id,
            "payment_date": self.payment_date,
            "batch_hash": self.batch_hash,
            "payment_execution_ids": list(self.payment_execution_ids),
        }


@dataclass(frozen=True)
class PaymentExecutionRecord:
    payment_execution_id: str
    payer_entity_id: str
    supplier_id: str
    bank_account_reference: str
    invoice_ids: tuple[str, ...]
    amount_minor: int
    currency: str
    payment_date: str
    payment_batch_id: str
    proposer_id: str
    request_id: str
    intent_id: str
    pccb_id: str
    executed_at: str
    reconciliation_status: str = "recorded-local"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PaymentExecutionRecord":
        return cls(
            payment_execution_id=str(raw["payment_execution_id"]),
            payer_entity_id=str(raw["payer_entity_id"]),
            supplier_id=str(raw["supplier_id"]),
            bank_account_reference=str(raw["bank_account_reference"]),
            invoice_ids=tuple(str(item) for item in raw["invoice_ids"]),
            amount_minor=int(raw["amount_minor"]),
            currency=str(raw["currency"]),
            payment_date=str(raw["payment_date"]),
            payment_batch_id=str(raw["payment_batch_id"]),
            proposer_id=str(raw["proposer_id"]),
            request_id=str(raw["request_id"]),
            intent_id=str(raw["intent_id"]),
            pccb_id=str(raw["pccb_id"]),
            executed_at=str(raw["executed_at"]),
            reconciliation_status=str(raw.get("reconciliation_status", "recorded-local")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "payment_execution_id": self.payment_execution_id,
            "payer_entity_id": self.payer_entity_id,
            "supplier_id": self.supplier_id,
            "bank_account_reference": self.bank_account_reference,
            "invoice_ids": list(self.invoice_ids),
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "payment_date": self.payment_date,
            "payment_batch_id": self.payment_batch_id,
            "proposer_id": self.proposer_id,
            "request_id": self.request_id,
            "intent_id": self.intent_id,
            "pccb_id": self.pccb_id,
            "executed_at": self.executed_at,
            "reconciliation_status": self.reconciliation_status,
        }


@dataclass(frozen=True)
class PaymentReconciliationRecord:
    reconciliation_id: str
    payment_execution_id: str
    payment_batch_id: str
    provider_reference: str
    amount_minor: int
    currency: str
    status: str
    recorded_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PaymentReconciliationRecord":
        return cls(
            reconciliation_id=str(raw["reconciliation_id"]),
            payment_execution_id=str(raw["payment_execution_id"]),
            payment_batch_id=str(raw["payment_batch_id"]),
            provider_reference=str(raw["provider_reference"]),
            amount_minor=int(raw["amount_minor"]),
            currency=str(raw["currency"]),
            status=str(raw["status"]),
            recorded_at=str(raw["recorded_at"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reconciliation_id": self.reconciliation_id,
            "payment_execution_id": self.payment_execution_id,
            "payment_batch_id": self.payment_batch_id,
            "provider_reference": self.provider_reference,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "status": self.status,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True)
class InvoicePaymentReconciliationState:
    resource_version: int = 0
    payee_enrollments: dict[str, PayeeEnrollment] = field(default_factory=dict)
    invoices: dict[str, InvoiceRecord] = field(default_factory=dict)
    payment_batches: dict[str, PaymentBatchRecord] = field(default_factory=dict)
    payment_executions: dict[str, PaymentExecutionRecord] = field(default_factory=dict)
    reconciliation_records: dict[str, PaymentReconciliationRecord] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "InvoicePaymentReconciliationState":
        return cls(
            resource_version=int(raw.get("resource_version", 0)),
            payee_enrollments={
                key: PayeeEnrollment.from_dict(value) for key, value in raw.get("payee_enrollments", {}).items()
            },
            invoices={key: InvoiceRecord.from_dict(value) for key, value in raw.get("invoices", {}).items()},
            payment_batches={
                key: PaymentBatchRecord.from_dict(value) for key, value in raw.get("payment_batches", {}).items()
            },
            payment_executions={
                key: PaymentExecutionRecord.from_dict(value)
                for key, value in raw.get("payment_executions", {}).items()
            },
            reconciliation_records={
                key: PaymentReconciliationRecord.from_dict(value)
                for key, value in raw.get("reconciliation_records", {}).items()
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_version": self.resource_version,
            "payee_enrollments": {
                key: value.to_dict() for key, value in sorted(self.payee_enrollments.items())
            },
            "invoices": {key: value.to_dict() for key, value in sorted(self.invoices.items())},
            "payment_batches": {
                key: value.to_dict() for key, value in sorted(self.payment_batches.items())
            },
            "payment_executions": {
                key: value.to_dict() for key, value in sorted(self.payment_executions.items())
            },
            "reconciliation_records": {
                key: value.to_dict() for key, value in sorted(self.reconciliation_records.items())
            },
        }
