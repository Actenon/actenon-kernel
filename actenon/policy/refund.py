from __future__ import annotations

from dataclasses import dataclass

from actenon.models.contracts import ActionIntent
from actenon.models.runtime import DynamicContextInput, RuleEvaluation
from actenon.receipts import ReceiptStore
from .evidence import ReceiptEvidenceVerificationRule
from .engine import (
    CapabilityScopeHardRule,
    HardRuleEngine,
    IntentChronologyHardRule,
    IntentTtlHardRule,
    PolicyEngine,
    TenantWorkflowRule,
    TenantWorkflowRuleLayer,
)


@dataclass(frozen=True)
class RefundActionShapeRule:
    rule_id: str = "hard.refund.action_shape"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if intent.action.name != "refund.create":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_ACTION_NAME_INVALID",
                summary="The refund wedge only accepts refund.create action intents.",
            )
        if intent.action.capability != "refund.execute":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_CAPABILITY_INVALID",
                summary="The refund wedge only accepts refund.execute capability requests.",
            )
        if intent.target.resource_type != "payment":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_TARGET_TYPE_INVALID",
                summary="Refund execution requires a payment target.",
            )
        amount_minor = intent.action.parameters.get("amount_minor")
        currency = intent.action.parameters.get("currency")
        if not isinstance(amount_minor, int) or amount_minor <= 0:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_AMOUNT_INVALID",
                summary="Refund execution requires a positive integer amount_minor.",
            )
        if not isinstance(currency, str) or len(currency) != 3 or currency.upper() != currency:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_CURRENCY_INVALID",
                summary="Refund execution requires an uppercase three-letter currency.",
            )
        return None


@dataclass(frozen=True)
class RefundTargetBindingRule:
    rule_id: str = "hard.refund.target_binding"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        expected_payment_id = context.facts.get("payment_id")
        if expected_payment_id and intent.target.resource_id != expected_payment_id:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_TARGET_MISMATCH",
                summary="The refund target does not match the protected payment resource.",
                details={"expected_payment_id": expected_payment_id},
            )
        return None


@dataclass(frozen=True)
class RefundAmountLimitRule:
    rule_id: str = "hard.refund.amount_limit"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        amount_minor = int(intent.action.parameters["amount_minor"])
        remaining = context.facts.get("remaining_refundable_minor")
        if remaining is None:
            return None
        if amount_minor > int(remaining):
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_AMOUNT_EXCEEDS_BALANCE",
                summary="The requested refund exceeds the remaining refundable balance.",
                details={"remaining_refundable_minor": remaining, "requested_amount_minor": amount_minor},
            )
        return None


@dataclass(frozen=True)
class RefundCurrencyMatchRule:
    rule_id: str = "hard.refund.currency_match"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        requested_currency = intent.action.parameters["currency"]
        expected_currency = context.facts.get("payment_currency")
        if expected_currency is not None and requested_currency != expected_currency:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="REFUND_CURRENCY_MISMATCH",
                summary="The refund currency must match the original payment currency.",
                details={"expected_currency": expected_currency, "requested_currency": requested_currency},
            )
        return None


def build_refund_policy_engine(receipt_store: ReceiptStore | None = None) -> PolicyEngine:
    return PolicyEngine(
        hard_rules=HardRuleEngine(
            (
                IntentChronologyHardRule(),
                IntentTtlHardRule(),
                CapabilityScopeHardRule(),
                ReceiptEvidenceVerificationRule(
                    receipt_store=receipt_store,
                    required_capability="refund.execute",
                ),
                RefundActionShapeRule(),
                RefundTargetBindingRule(),
                RefundAmountLimitRule(),
                RefundCurrencyMatchRule(),
            )
        ),
        tenant_workflow_rules=TenantWorkflowRuleLayer(
            tenant_rules={
                "tenant_demo": (
                    TenantWorkflowRule(
                        rule_id="tenant_demo.refund.deny",
                        outcome="deny",
                        summary="The refund workflow denies blocked refund requests.",
                        reason_code="WORKFLOW_DENY",
                        capabilities=("refund.execute",),
                        required_fact_values={"risk_level": "blocked"},
                    ),
                    TenantWorkflowRule(
                        rule_id="tenant_demo.refund.needs_evidence",
                        outcome="needs-evidence",
                        summary="The refund workflow requires documentary evidence before review-risk refunds can proceed.",
                        reason_code="EVIDENCE_REQUIRED",
                        capabilities=("refund.execute",),
                        required_fact_values={"risk_level": "review"},
                        required_evidence_types=("external_id",),
                    ),
                    TenantWorkflowRule(
                        rule_id="tenant_demo.refund.approval_required",
                        outcome="approval-required",
                        summary="The refund workflow requires operator approval for elevated-value refunds.",
                        reason_code="APPROVAL_REQUIRED",
                        capabilities=("refund.execute",),
                        required_fact_values={"risk_level": "approval"},
                        approver_types=("finance-operator",),
                    ),
                    TenantWorkflowRule(
                        rule_id="tenant_demo.refund.allow",
                        outcome="allow",
                        summary="The refund workflow authorizes normal-risk refunds.",
                        reason_code="WORKFLOW_ALLOW",
                        capabilities=("refund.execute",),
                        required_fact_values={"risk_level": "normal"},
                    ),
                )
            }
        ),
    )
