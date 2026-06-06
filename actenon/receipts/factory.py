from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from actenon.core.errors import RefusalException
from actenon.models.contracts import ActionHashSpec, ActionIntent, CorrelationRef, Receipt, Refusal
from actenon.models.runtime import DynamicContextInput, PolicyDecision
from .invoice_payment import (
    invoice_payment_decision_details,
    invoice_payment_detail_fields,
    invoice_payment_operator_summary_for_decision,
    invoice_payment_operator_summary_for_execution,
    invoice_payment_operator_summary_for_refusal,
    is_invoice_payment_intent,
)
from .refund import (
    is_refund_intent,
    refund_detail_fields,
    refund_operator_summary_for_decision,
    refund_operator_summary_for_execution,
)


@dataclass
class ReceiptFactory:
    receipt_id_factory: Callable[[], str] = field(default=lambda: f"rcpt_{uuid4().hex}")

    def create_decision_receipt(
        self,
        intent: ActionIntent,
        decision: PolicyDecision,
        context: DynamicContextInput,
        *,
        pccb_id: str | None = None,
        escrow_id: str | None = None,
        action_hash: ActionHashSpec | None = None,
    ) -> Receipt:
        follow_up: dict[str, Any] = {}
        if decision.outcome == "approval-required":
            follow_up["approver_types"] = list(decision.approver_types)
            follow_up["instructions"] = "Additional approval is required before execution."
        if decision.outcome == "needs-evidence":
            follow_up["required_evidence"] = list(decision.required_evidence)
            follow_up["instructions"] = "Additional evidence is required before execution."
        correlation = CorrelationRef(
            pccb_id=pccb_id,
            escrow_id=escrow_id,
            request_id=context.request_id,
            action_hash=action_hash,
        )
        summary = decision.summary
        details: dict[str, Any] = {"rule_evaluations": [item.rule_id for item in decision.rule_evaluations]}
        if is_refund_intent(intent):
            summary = refund_operator_summary_for_decision(intent, decision)
            details.update(refund_detail_fields(intent))
        elif is_invoice_payment_intent(intent):
            summary = invoice_payment_operator_summary_for_decision(intent, decision)
            details = invoice_payment_decision_details(intent, decision, context)
        return Receipt(
            receipt_id=self.receipt_id_factory(),
            intent_id=intent.intent_id,
            occurred_at=context.now,
            outcome=decision.outcome,
            phase="decision",
            tenant=intent.tenant,
            subject=intent.requester,
            action=intent.action,
            target=intent.target,
            correlation=correlation,
            summary=summary,
            reason_codes=decision.reason_codes,
            follow_up=follow_up,
            side_effects={"state": "none"},
            details=details,
        )

    def create_execution_receipt(
        self,
        intent: ActionIntent,
        context: DynamicContextInput,
        *,
        pccb_id: str,
        escrow_id: str | None,
        payload: dict[str, Any] | None,
        action_hash: ActionHashSpec | None = None,
    ) -> Receipt:
        external_reference = None if not payload else payload.get("external_reference")
        provider_reference = None if not payload else payload.get("provider_reference")
        reconciliation_status = None if not payload else payload.get("reconciliation_status")
        resource_version = None if not payload else payload.get("resource_version")
        side_effects = {"state": "completed"}
        if external_reference:
            side_effects["external_reference"] = external_reference
        if provider_reference:
            side_effects["provider_reference"] = provider_reference
        if reconciliation_status:
            side_effects["reconciliation_status"] = reconciliation_status
        if resource_version:
            side_effects["resource_version"] = resource_version
        summary = "The protected action executed successfully."
        details = payload or {}
        if is_refund_intent(intent):
            summary = refund_operator_summary_for_execution(intent, payload)
            details = {**refund_detail_fields(intent), **(payload or {})}
        elif is_invoice_payment_intent(intent):
            summary = invoice_payment_operator_summary_for_execution(intent, payload)
            details = {**invoice_payment_detail_fields(intent), **(payload or {})}
        return Receipt(
            receipt_id=self.receipt_id_factory(),
            intent_id=intent.intent_id,
            occurred_at=context.now,
            outcome="executed",
            phase="execution",
            tenant=intent.tenant,
            subject=intent.requester,
            action=intent.action,
            target=intent.target,
            correlation=CorrelationRef(
                pccb_id=pccb_id,
                escrow_id=escrow_id,
                request_id=context.request_id,
                action_hash=action_hash,
            ),
            summary=summary,
            side_effects=side_effects,
            details=details,
        )

    def create_refused_receipt(
        self,
        intent: ActionIntent,
        context: DynamicContextInput,
        refusal: Refusal,
    ) -> Receipt:
        summary = refusal.message
        details: dict[str, Any] = {}
        if is_refund_intent(intent):
            summary = (
                f"Refund of {intent.action.parameters['amount_minor']} {intent.action.parameters['currency']} "
                f"against payment {intent.target.resource_id} was refused."
            )
            details = refund_detail_fields(intent)
        elif is_invoice_payment_intent(intent):
            summary = invoice_payment_operator_summary_for_refusal(intent, refusal.reason_code)
            details = invoice_payment_detail_fields(intent)
        return Receipt(
            receipt_id=self.receipt_id_factory(),
            intent_id=intent.intent_id,
            occurred_at=context.now,
            outcome="refused",
            phase="execution",
            tenant=intent.tenant,
            subject=intent.requester,
            action=intent.action,
            target=intent.target,
            correlation=CorrelationRef(
                pccb_id=refusal.correlation.pccb_id if refusal.correlation is not None else None,
                escrow_id=refusal.correlation.escrow_id if refusal.correlation is not None else None,
                refusal_id=refusal.refusal_id,
                request_id=context.request_id,
                action_hash=refusal.correlation.action_hash if refusal.correlation is not None else None,
            ),
            summary=summary,
            reason_codes=(refusal.reason_code,),
            side_effects={"state": "none"},
            details=details,
        )


@dataclass
class RefusalFactory:
    refusal_id_factory: Callable[[], str] = field(default=lambda: f"rfsl_{uuid4().hex}")

    def create_from_exception(
        self,
        exc: RefusalException,
        *,
        occurred_at: datetime,
        intent: ActionIntent | None,
        context: DynamicContextInput | None,
        pccb_id: str | None = None,
        escrow_id: str | None = None,
        action_hash: ActionHashSpec | None = None,
    ) -> Refusal:
        correlation = CorrelationRef(
            pccb_id=pccb_id,
            escrow_id=escrow_id,
            request_id=context.request_id if context else None,
            action_hash=action_hash,
        )
        return Refusal(
            refusal_id=self.refusal_id_factory(),
            intent_id=intent.intent_id if intent else None,
            category=exc.category,
            reason_code=exc.refusal_code,
            message=exc.message,
            retryable=exc.retryable,
            refused_at=occurred_at,
            tenant=intent.tenant if intent else None,
            subject=intent.requester if intent else None,
            audience=context.audience if context else None,
            action=intent.action if intent else None,
            target=intent.target if intent else None,
            correlation=correlation,
            rule_refs=exc.rule_refs,
            violations=exc.violations,
            details=exc.details,
        )
