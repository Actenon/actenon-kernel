from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from actenon.api.invoice_payment import compute_invoice_payment_batch_hash, normalize_invoice_ids
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


def _parameters(intent: ActionIntent) -> dict[str, Any]:
    return intent.action.parameters


def _invoice_ids(intent: ActionIntent) -> list[str]:
    raw_invoice_ids = _parameters(intent).get("invoice_ids", [])
    if not isinstance(raw_invoice_ids, list):
        return []
    return [str(item) for item in raw_invoice_ids]


@dataclass(frozen=True)
class InvoicePaymentActionShapeRule:
    rule_id: str = "hard.invoice_payment.action_shape"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        params = _parameters(intent)
        if intent.action.name != "invoice_payment.execute":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_PAYMENT_ACTION_NAME_INVALID",
                summary="The invoice payment wedge only accepts invoice_payment.execute action intents.",
            )
        if intent.action.capability != "invoice_payment.execute":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_PAYMENT_CAPABILITY_INVALID",
                summary="The invoice payment wedge only accepts invoice_payment.execute capability requests.",
            )
        if intent.target.resource_type != "payment_batch":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_PAYMENT_TARGET_TYPE_INVALID",
                summary="Invoice payment execution requires a payment_batch target.",
            )

        required_string_fields = (
            "payer_entity_id",
            "supplier_id",
            "bank_account_reference",
            "currency",
            "payment_date",
            "payment_batch_id",
            "batch_hash",
            "proposer_id",
        )
        for field_name in required_string_fields:
            value = params.get(field_name)
            if not isinstance(value, str) or not value:
                return RuleEvaluation(
                    rule_id=self.rule_id,
                    outcome="deny",
                    reason_code="INVOICE_PAYMENT_FIELD_INVALID",
                    summary=f"Invoice payment execution requires a non-empty {field_name}.",
                    details={"field_name": field_name},
                )

        amount_minor = params.get("amount_minor")
        if not isinstance(amount_minor, int) or amount_minor <= 0:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_PAYMENT_AMOUNT_INVALID",
                summary="Invoice payment execution requires a positive integer amount_minor.",
            )

        currency = params["currency"]
        if len(currency) != 3 or currency.upper() != currency:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_PAYMENT_CURRENCY_INVALID",
                summary="Invoice payment execution requires an uppercase three-letter currency.",
            )

        invoice_ids = _invoice_ids(intent)
        if not invoice_ids:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_SET_INVALID",
                summary="Invoice payment execution requires a non-empty invoice_ids set.",
            )
        if invoice_ids != normalize_invoice_ids(invoice_ids):
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_SET_INVALID",
                summary="Invoice payment invoice_ids must be unique and sorted for exact invoice-set binding.",
            )

        try:
            date.fromisoformat(params["payment_date"])
        except ValueError:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="PAYMENT_DATE_INVALID",
                summary="Invoice payment execution requires a YYYY-MM-DD payment_date.",
            )

        if intent.target.resource_id != params["payment_batch_id"]:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="PAYMENT_BATCH_BINDING_MISMATCH",
                summary="The payment batch target must match action.parameters.payment_batch_id.",
            )

        if params["proposer_id"] != intent.requester.id:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="PROPOSER_IDENTITY_MISMATCH",
                summary="The proposer identity must exactly match the requesting subject.",
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentConstraintBindingRule:
    rule_id: str = "hard.invoice_payment.constraint_binding"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        params = _parameters(intent)
        constraints = intent.action.constraints
        expected_bindings = {
            "exact_payer_entity_id": params["payer_entity_id"],
            "exact_supplier_id": params["supplier_id"],
            "exact_bank_account_reference": params["bank_account_reference"],
            "exact_invoice_ids": _invoice_ids(intent),
            "exact_amount_minor": params["amount_minor"],
            "exact_currency": params["currency"],
            "exact_payment_date": params["payment_date"],
            "exact_payment_batch_id": params["payment_batch_id"],
            "exact_batch_hash": params["batch_hash"],
        }
        for field_name, expected_value in expected_bindings.items():
            if constraints.get(field_name) != expected_value:
                return RuleEvaluation(
                    rule_id=self.rule_id,
                    outcome="deny",
                    reason_code="PAYMENT_BINDING_MISMATCH",
                    summary="The invoice payment action constraints must exactly mirror the requested payment values.",
                    details={"field_name": field_name, "expected": expected_value, "observed": constraints.get(field_name)},
                )
        return None


@dataclass(frozen=True)
class InvoicePaymentEntityBindingRule:
    rule_id: str = "hard.invoice_payment.entity_binding"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        expected_entity = context.facts.get("expected_payer_entity_id")
        payer_entity_id = _parameters(intent)["payer_entity_id"]
        if expected_entity is not None and payer_entity_id != expected_entity:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="WRONG_ENTITY",
                summary="The requested payer entity does not match the protected payment context.",
                details={"expected_payer_entity_id": expected_entity, "observed_payer_entity_id": payer_entity_id},
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentPayeeBindingRule:
    rule_id: str = "hard.invoice_payment.payee_binding"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        expected_supplier_id = context.facts.get("expected_supplier_id")
        supplier_id = _parameters(intent)["supplier_id"]
        if expected_supplier_id is not None and supplier_id != expected_supplier_id:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="PAYEE_MISMATCH",
                summary="The requested supplier does not match the protected payment context.",
                details={"expected_supplier_id": expected_supplier_id, "observed_supplier_id": supplier_id},
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentBankBindingRule:
    rule_id: str = "hard.invoice_payment.bank_binding"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        expected_bank_reference = context.facts.get("expected_bank_account_reference")
        bank_reference = _parameters(intent)["bank_account_reference"]
        if expected_bank_reference is not None and bank_reference != expected_bank_reference:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="BANK_MISMATCH",
                summary="The requested bank account reference does not match the validated payee bank details.",
                details={"expected_bank_account_reference": expected_bank_reference, "observed_bank_account_reference": bank_reference},
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentInvoiceSetRule:
    rule_id: str = "hard.invoice_payment.invoice_set"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        expected_invoice_ids = context.facts.get("expected_invoice_ids")
        invoice_ids = _invoice_ids(intent)
        if expected_invoice_ids is not None and invoice_ids != normalize_invoice_ids(expected_invoice_ids):
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVOICE_SET_MISMATCH",
                summary="The requested invoice set does not match the protected payment context.",
                details={"expected_invoice_ids": normalize_invoice_ids(expected_invoice_ids), "observed_invoice_ids": invoice_ids},
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentAmountCurrencyRule:
    rule_id: str = "hard.invoice_payment.amount_currency"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        params = _parameters(intent)
        expected_amount_minor = context.facts.get("expected_amount_minor")
        expected_currency = context.facts.get("expected_currency")
        expected_payment_date = context.facts.get("expected_payment_date")
        if expected_amount_minor is not None and params["amount_minor"] != int(expected_amount_minor):
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="PAYMENT_AMOUNT_MISMATCH",
                summary="The requested payment amount does not match the protected payment context.",
                details={"expected_amount_minor": int(expected_amount_minor), "observed_amount_minor": params["amount_minor"]},
            )
        if expected_currency is not None and params["currency"] != expected_currency:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="PAYMENT_CURRENCY_MISMATCH",
                summary="The requested payment currency does not match the protected payment context.",
                details={"expected_currency": expected_currency, "observed_currency": params["currency"]},
            )
        if expected_payment_date is not None and params["payment_date"] != expected_payment_date:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="PAYMENT_DATE_MISMATCH",
                summary="The requested payment date does not match the protected payment context.",
                details={"expected_payment_date": expected_payment_date, "observed_payment_date": params["payment_date"]},
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentDuplicateRule:
    rule_id: str = "hard.invoice_payment.duplicate"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        invoice_ids = set(_invoice_ids(intent))
        duplicate_invoice_ids = {str(item) for item in context.facts.get("duplicate_invoice_ids", ())}
        duplicate_match = sorted(invoice_ids & duplicate_invoice_ids)
        if duplicate_match or context.facts.get("duplicate_payment_detected"):
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="DUPLICATE_INVOICE_PAYMENT",
                summary="The requested invoice payment duplicates an already-paid or already-scheduled invoice payment.",
                details={"duplicate_invoice_ids": duplicate_match},
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentBatchHashRule:
    rule_id: str = "hard.invoice_payment.batch_hash"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        params = _parameters(intent)
        computed_batch_hash = compute_invoice_payment_batch_hash(
            payer_entity_id=params["payer_entity_id"],
            supplier_id=params["supplier_id"],
            bank_account_reference=params["bank_account_reference"],
            invoice_ids=_invoice_ids(intent),
            amount_minor=params["amount_minor"],
            currency=params["currency"],
            payment_date=params["payment_date"],
            payment_batch_id=params["payment_batch_id"],
        )
        if params["batch_hash"] != computed_batch_hash:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="BATCH_HASH_MISMATCH",
                summary="The requested payment batch hash does not match the declared invoice payment set.",
                details={"expected_batch_hash": computed_batch_hash, "observed_batch_hash": params["batch_hash"]},
            )
        expected_batch_hash = context.facts.get("expected_batch_hash")
        if expected_batch_hash is not None and params["batch_hash"] != expected_batch_hash:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="BATCH_HASH_MISMATCH",
                summary="The requested payment batch hash does not match the protected payment context.",
                details={"expected_batch_hash": expected_batch_hash, "observed_batch_hash": params["batch_hash"]},
            )
        return None


@dataclass(frozen=True)
class InvoicePaymentEvidenceWorkflowRule:
    rule_id: str = "tenant_demo.invoice_payment.evidence"
    tenant_id: str = "tenant_demo"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if intent.tenant.tenant_id != self.tenant_id or intent.action.capability != "invoice_payment.execute":
            return None
        required_evidence = tuple(str(item) for item in context.facts.get("required_evidence_types", context.required_evidence_types))
        if not required_evidence:
            return None
        evidence_types = {item.type for item in intent.evidence_refs}
        missing = tuple(sorted(set(required_evidence) - evidence_types))
        if not missing:
            return None
        return RuleEvaluation(
            rule_id=self.rule_id,
            outcome="needs-evidence",
            reason_code="EVIDENCE_MISSING",
            summary="The invoice payment requires additional evidence before execution can proceed.",
            required_evidence=missing,
            details={"required_evidence_types": list(required_evidence)},
        )


@dataclass(frozen=True)
class InvoicePaymentApprovalWorkflowRule:
    rule_id: str = "tenant_demo.invoice_payment.approval"
    tenant_id: str = "tenant_demo"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if intent.tenant.tenant_id != self.tenant_id or intent.action.capability != "invoice_payment.execute":
            return None
        required_chain = tuple(str(item) for item in context.facts.get("required_approval_chain", ()))
        provided_chain = {str(item) for item in context.facts.get("provided_approval_chain", ())}
        missing_approvals = tuple(item for item in required_chain if item not in provided_chain)
        if not missing_approvals and not context.facts.get("approval_required"):
            return None
        approver_types = tuple(str(item) for item in context.facts.get("required_approver_types", context.approver_types))
        return RuleEvaluation(
            rule_id=self.rule_id,
            outcome="approval-required",
            reason_code="APPROVAL_MISSING",
            summary="The invoice payment requires the full approval chain before execution can proceed.",
            approver_types=approver_types,
            details={"missing_approvals": list(missing_approvals), "required_approval_chain": list(required_chain)},
        )


@dataclass(frozen=True)
class InvoicePaymentAllowWorkflowRule:
    rule_id: str = "tenant_demo.invoice_payment.allow"
    tenant_id: str = "tenant_demo"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if intent.tenant.tenant_id != self.tenant_id or intent.action.capability != "invoice_payment.execute":
            return None
        return RuleEvaluation(
            rule_id=self.rule_id,
            outcome="allow",
            reason_code="PAYMENT_READY",
            summary="The invoice payment is approved for protected execution.",
        )


def build_invoice_payment_policy_engine(receipt_store: ReceiptStore | None = None) -> PolicyEngine:
    return PolicyEngine(
        hard_rules=HardRuleEngine(
            (
                IntentChronologyHardRule(),
                IntentTtlHardRule(),
                CapabilityScopeHardRule(),
                ReceiptEvidenceVerificationRule(
                    receipt_store=receipt_store,
                    required_capability="invoice_payment.execute",
                ),
                InvoicePaymentActionShapeRule(),
                InvoicePaymentConstraintBindingRule(),
                InvoicePaymentEntityBindingRule(),
                InvoicePaymentPayeeBindingRule(),
                InvoicePaymentBankBindingRule(),
                InvoicePaymentInvoiceSetRule(),
                InvoicePaymentAmountCurrencyRule(),
                InvoicePaymentDuplicateRule(),
                InvoicePaymentBatchHashRule(),
            )
        ),
        tenant_workflow_rules=TenantWorkflowRuleLayer(
            tenant_rules={
                "tenant_demo": (
                    TenantWorkflowRule(
                        rule_id="tenant_demo.invoice_payment.blocked",
                        outcome="deny",
                        summary="The invoice payment workflow denies blocked payment requests.",
                        reason_code="PAYMENT_BLOCKED_RISK",
                        capabilities=("invoice_payment.execute",),
                        required_fact_values={"risk_level": "blocked"},
                    ),
                    InvoicePaymentEvidenceWorkflowRule(),
                    InvoicePaymentApprovalWorkflowRule(),
                    InvoicePaymentAllowWorkflowRule(),
                )
            }
        ),
    )
