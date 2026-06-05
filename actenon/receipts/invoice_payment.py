from __future__ import annotations

from typing import Any

from actenon.models.contracts import ActionIntent
from actenon.models.runtime import DynamicContextInput, PolicyDecision


def is_invoice_payment_intent(intent: ActionIntent) -> bool:
    return intent.action.name == "invoice_payment.execute" and intent.action.capability == "invoice_payment.execute"


def invoice_payment_detail_fields(intent: ActionIntent) -> dict[str, Any]:
    params = intent.action.parameters
    return {
        "wedge": "invoice_payment",
        "payer_entity_id": params["payer_entity_id"],
        "supplier_id": params["supplier_id"],
        "bank_account_reference": params["bank_account_reference"],
        "invoice_ids": list(params["invoice_ids"]),
        "amount_minor": params["amount_minor"],
        "currency": params["currency"],
        "payment_date": params["payment_date"],
        "payment_batch_id": params["payment_batch_id"],
        "batch_hash": params["batch_hash"],
        "proposer_id": params["proposer_id"],
        "target_resource_type": intent.target.resource_type,
        "target_resource_id": intent.target.resource_id,
    }


def invoice_payment_decision_details(
    intent: ActionIntent,
    decision: PolicyDecision,
    context: DynamicContextInput,
) -> dict[str, Any]:
    details = invoice_payment_detail_fields(intent)
    details["rule_evaluations"] = [item.rule_id for item in decision.rule_evaluations]
    if decision.outcome == "approval-required":
        details["required_approval_chain"] = list(context.facts.get("required_approval_chain", ()))
        details["provided_approval_chain"] = list(context.facts.get("provided_approval_chain", ()))
    if decision.outcome == "needs-evidence":
        details["required_evidence_types"] = list(decision.required_evidence)
        details["provided_evidence_types"] = [item.type for item in intent.evidence_refs]
    return details


def invoice_payment_operator_summary_for_decision(intent: ActionIntent, decision: PolicyDecision) -> str:
    params = intent.action.parameters
    amount_minor = params["amount_minor"]
    currency = params["currency"]
    supplier_id = params["supplier_id"]
    invoice_count = len(params["invoice_ids"])
    batch_id = params["payment_batch_id"]
    if decision.outcome == "allow":
        return (
            f"Invoice payment of {amount_minor} {currency} to supplier {supplier_id} "
            f"for {invoice_count} invoices in batch {batch_id} is authorized for protected execution."
        )
    if decision.outcome == "deny":
        return (
            f"Invoice payment of {amount_minor} {currency} to supplier {supplier_id} "
            f"for batch {batch_id} was denied by finance controls."
        )
    if decision.outcome == "approval-required":
        return (
            f"Invoice payment of {amount_minor} {currency} to supplier {supplier_id} "
            f"for batch {batch_id} requires the full approval chain before execution."
        )
    if decision.outcome == "needs-evidence":
        return (
            f"Invoice payment of {amount_minor} {currency} to supplier {supplier_id} "
            f"for batch {batch_id} requires additional evidence before execution."
        )
    return decision.summary


def invoice_payment_operator_summary_for_execution(intent: ActionIntent, payload: dict[str, Any] | None) -> str:
    params = intent.action.parameters
    amount_minor = params["amount_minor"]
    currency = params["currency"]
    supplier_id = params["supplier_id"]
    batch_id = params["payment_batch_id"]
    execution_id = None if not payload else payload.get("payment_execution_id")
    reconciliation_id = None if not payload else payload.get("reconciliation_id")
    if execution_id and reconciliation_id:
        return (
            f"Invoice payment {execution_id} executed for {amount_minor} {currency} "
            f"to supplier {supplier_id} in batch {batch_id}. Reconciliation record {reconciliation_id} was written."
        )
    return (
        f"Invoice payment executed for {amount_minor} {currency} "
        f"to supplier {supplier_id} in batch {batch_id}."
    )


def invoice_payment_operator_summary_for_refusal(intent: ActionIntent, refusal_code: str) -> str:
    params = intent.action.parameters
    return (
        f"Invoice payment of {params['amount_minor']} {params['currency']} "
        f"to supplier {params['supplier_id']} in batch {params['payment_batch_id']} was refused ({refusal_code})."
    )
