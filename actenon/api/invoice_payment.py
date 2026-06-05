from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Iterable

from actenon.proof.canonical import sha256_hex


def normalize_invoice_ids(invoice_ids: Iterable[str]) -> list[str]:
    normalized = sorted({str(item) for item in invoice_ids if str(item)})
    if not normalized:
        raise ValueError("invoice_ids must contain at least one non-empty value")
    return normalized


def normalize_payment_date(value: date | str) -> str:
    if isinstance(value, date):
        return value.isoformat()
    parsed = date.fromisoformat(value)
    return parsed.isoformat()


def compute_invoice_payment_batch_hash(
    *,
    payer_entity_id: str,
    supplier_id: str,
    bank_account_reference: str,
    invoice_ids: Iterable[str],
    amount_minor: int,
    currency: str,
    payment_date: date | str,
    payment_batch_id: str,
) -> str:
    hash_input = {
        "payer_entity_id": payer_entity_id,
        "supplier_id": supplier_id,
        "bank_account_reference": bank_account_reference,
        "invoice_ids": normalize_invoice_ids(invoice_ids),
        "amount_minor": amount_minor,
        "currency": currency,
        "payment_date": normalize_payment_date(payment_date),
        "payment_batch_id": payment_batch_id,
    }
    return f"batch_{sha256_hex(hash_input)}"


def build_invoice_payment_action_intent_payload(
    *,
    intent_id: str,
    tenant_id: str,
    requester_id: str,
    payer_entity_id: str,
    supplier_id: str,
    bank_account_reference: str,
    invoice_ids: Iterable[str],
    amount_minor: int,
    currency: str,
    payment_date: date | str,
    payment_batch_id: str,
    issued_at: datetime,
    proposer_id: str | None = None,
    ttl_seconds: int = 300,
    justification: str | None = None,
    evidence_refs: list[dict[str, Any]] | None = None,
    context: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    batch_hash: str | None = None,
) -> dict[str, Any]:
    normalized_invoice_ids = normalize_invoice_ids(invoice_ids)
    normalized_payment_date = normalize_payment_date(payment_date)
    resolved_batch_hash = batch_hash or compute_invoice_payment_batch_hash(
        payer_entity_id=payer_entity_id,
        supplier_id=supplier_id,
        bank_account_reference=bank_account_reference,
        invoice_ids=normalized_invoice_ids,
        amount_minor=amount_minor,
        currency=currency,
        payment_date=normalized_payment_date,
        payment_batch_id=payment_batch_id,
    )
    resolved_proposer_id = proposer_id or requester_id
    idempotency_key_input = {
        "payment_batch_id": payment_batch_id,
        "invoice_ids": normalized_invoice_ids,
        "amount_minor": amount_minor,
        "currency": currency,
        "payer_entity_id": payer_entity_id,
        "supplier_id": supplier_id,
    }
    idempotency_key = f"ipy_{sha256_hex(idempotency_key_input)}"
    expires_at = issued_at + timedelta(seconds=ttl_seconds)

    payload: dict[str, Any] = {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": intent_id,
        "idempotency_key": idempotency_key,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "tenant": {"tenant_id": tenant_id},
        "requester": {"type": "service", "id": requester_id},
        "action": {
            "name": "invoice_payment.execute",
            "capability": "invoice_payment.execute",
            "parameters": {
                "payer_entity_id": payer_entity_id,
                "supplier_id": supplier_id,
                "bank_account_reference": bank_account_reference,
                "invoice_ids": normalized_invoice_ids,
                "amount_minor": amount_minor,
                "currency": currency,
                "payment_date": normalized_payment_date,
                "payment_batch_id": payment_batch_id,
                "batch_hash": resolved_batch_hash,
                "proposer_id": resolved_proposer_id,
            },
            "constraints": {
                "exact_payer_entity_id": payer_entity_id,
                "exact_supplier_id": supplier_id,
                "exact_bank_account_reference": bank_account_reference,
                "exact_invoice_ids": normalized_invoice_ids,
                "exact_amount_minor": amount_minor,
                "exact_currency": currency,
                "exact_payment_date": normalized_payment_date,
                "exact_payment_batch_id": payment_batch_id,
                "exact_batch_hash": resolved_batch_hash,
            },
            "scope": {
                "target_resource_type": "payment_batch",
                "single_use": True,
            },
        },
        "target": {
            "resource_type": "payment_batch",
            "resource_id": payment_batch_id,
        },
        "context": context or {},
        "metadata": metadata or {},
    }
    if justification is not None:
        payload["justification"] = justification
    if evidence_refs:
        payload["evidence_refs"] = evidence_refs
    return payload
