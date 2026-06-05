from __future__ import annotations

from typing import Any

from actenon.models.contracts import ActionIntent
from actenon.models.runtime import PolicyDecision


def is_refund_intent(intent: ActionIntent) -> bool:
    return intent.action.name == "refund.create" and intent.action.capability == "refund.execute"


def refund_amount_minor(intent: ActionIntent) -> int:
    return int(intent.action.parameters["amount_minor"])


def refund_currency(intent: ActionIntent) -> str:
    return str(intent.action.parameters["currency"])


def refund_target_id(intent: ActionIntent) -> str:
    return intent.target.resource_id


def refund_operator_summary_for_decision(intent: ActionIntent, decision: PolicyDecision) -> str:
    amount_minor = refund_amount_minor(intent)
    currency = refund_currency(intent)
    target_id = refund_target_id(intent)
    if decision.outcome == "allow":
        return f"Refund of {amount_minor} {currency} against payment {target_id} is authorized for protected execution."
    if decision.outcome == "deny":
        return f"Refund of {amount_minor} {currency} against payment {target_id} was denied by policy."
    if decision.outcome == "approval-required":
        return f"Refund of {amount_minor} {currency} against payment {target_id} requires operator approval before execution."
    if decision.outcome == "needs-evidence":
        return f"Refund of {amount_minor} {currency} against payment {target_id} requires more evidence before execution."
    return decision.summary


def refund_operator_summary_for_execution(intent: ActionIntent, payload: dict[str, Any] | None) -> str:
    amount_minor = refund_amount_minor(intent)
    currency = refund_currency(intent)
    target_id = refund_target_id(intent)
    external_reference = payload.get("external_reference") if payload else None
    if external_reference:
        return (
            f"Refund of {amount_minor} {currency} against payment {target_id} executed successfully "
            f"with local reference {external_reference}."
        )
    return f"Refund of {amount_minor} {currency} against payment {target_id} executed successfully."


def refund_detail_fields(intent: ActionIntent) -> dict[str, Any]:
    return {
        "wedge": "refund",
        "amount_minor": refund_amount_minor(intent),
        "currency": refund_currency(intent),
        "target_resource_type": intent.target.resource_type,
        "target_resource_id": refund_target_id(intent),
    }
