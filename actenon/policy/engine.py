from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Protocol

from actenon.models.contracts import ActionIntent
from actenon.models.runtime import DynamicContextInput, PolicyDecision, RuleEvaluation


class PolicyRule(Protocol):
    rule_id: str

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        ...


@dataclass(frozen=True)
class IntentChronologyHardRule:
    rule_id: str = "hard.intent.chronology"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if intent.issued_at > context.now:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INTENT_ISSUED_IN_FUTURE",
                summary="The action intent was issued in the future.",
            )
        if intent.expires_at <= context.now:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INTENT_EXPIRED",
                summary="The action intent has expired.",
            )
        return None


@dataclass(frozen=True)
class IntentTtlHardRule:
    default_max_ttl_seconds: int = 900
    rule_id: str = "hard.intent.ttl"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        max_ttl_seconds = context.max_ttl_seconds if context.max_ttl_seconds is not None else self.default_max_ttl_seconds
        if max_ttl_seconds <= 0:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INVALID_MAX_TTL",
                summary="The runtime max TTL configuration is invalid.",
            )
        if intent.expires_at - intent.issued_at > timedelta(seconds=max_ttl_seconds):
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="INTENT_TTL_EXCEEDED",
                summary="The action intent exceeds the configured maximum lifetime.",
                details={"max_ttl_seconds": max_ttl_seconds},
            )
        return None


@dataclass(frozen=True)
class CapabilityScopeHardRule:
    rule_id: str = "hard.scope.capability"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if context.scope_capabilities and intent.action.capability not in context.scope_capabilities:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="CAPABILITY_OUTSIDE_SCOPE",
                summary="The requested capability is outside the protected endpoint scope.",
                details={"allowed_capabilities": list(context.scope_capabilities)},
            )
        return None


@dataclass(frozen=True)
class TenantWorkflowRule:
    rule_id: str
    outcome: str
    summary: str
    reason_code: str
    tenant_ids: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    required_fact_values: dict[str, Any] = field(default_factory=dict)
    required_evidence_types: tuple[str, ...] = ()
    approver_types: tuple[str, ...] = ()

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if self.tenant_ids and intent.tenant.tenant_id not in self.tenant_ids:
            return None
        if self.capabilities and intent.action.capability not in self.capabilities:
            return None
        for key, expected_value in self.required_fact_values.items():
            if context.facts.get(key) != expected_value:
                return None

        evidence_types = {item.type for item in intent.evidence_refs}
        missing_evidence = tuple(sorted(set(self.required_evidence_types) - evidence_types))
        if self.outcome == "needs-evidence" and missing_evidence:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="needs-evidence",
                reason_code=self.reason_code,
                summary=self.summary,
                required_evidence=missing_evidence,
            )
        if self.outcome == "approval-required":
            approvers = self.approver_types or context.approver_types
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="approval-required",
                reason_code=self.reason_code,
                summary=self.summary,
                approver_types=tuple(approvers),
            )
        if self.outcome == "deny":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code=self.reason_code,
                summary=self.summary,
            )
        if self.outcome == "allow":
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="allow",
                reason_code=self.reason_code,
                summary=self.summary,
            )
        return None


@dataclass
class HardRuleEngine:
    rules: tuple[PolicyRule, ...]

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> tuple[RuleEvaluation, ...]:
        evaluations: list[RuleEvaluation] = []
        for rule in self.rules:
            evaluation = rule.evaluate(intent, context)
            if evaluation is not None:
                evaluations.append(evaluation)
        return tuple(evaluations)


@dataclass
class TenantWorkflowRuleLayer:
    tenant_rules: dict[str, tuple[PolicyRule, ...]] = field(default_factory=dict)
    default_rules: tuple[PolicyRule, ...] = ()

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> tuple[RuleEvaluation, ...]:
        rules: list[PolicyRule] = list(self.default_rules)
        rules.extend(self.tenant_rules.get(intent.tenant.tenant_id, ()))
        evaluations: list[RuleEvaluation] = []
        for rule in rules:
            evaluation = rule.evaluate(intent, context)
            if evaluation is not None:
                evaluations.append(evaluation)
        return tuple(evaluations)


@dataclass
class PolicyEngine:
    hard_rules: HardRuleEngine
    tenant_workflow_rules: TenantWorkflowRuleLayer

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> PolicyDecision:
        evaluations: list[RuleEvaluation] = list(self.hard_rules.evaluate(intent, context))
        hard_denials = [item for item in evaluations if item.outcome == "deny"]
        if hard_denials:
            return PolicyDecision(
                outcome="deny",
                summary=hard_denials[0].summary,
                rule_evaluations=tuple(evaluations),
                reason_codes=tuple(item.reason_code for item in hard_denials),
            )

        workflow_evaluations = list(self.tenant_workflow_rules.evaluate(intent, context))
        evaluations.extend(workflow_evaluations)
        if not workflow_evaluations:
            default_deny = RuleEvaluation(
                rule_id="workflow.default_deny",
                outcome="deny",
                reason_code="NO_WORKFLOW_RULE_MATCH",
                summary="No tenant workflow rule matched the action intent.",
            )
            evaluations.append(default_deny)
            return PolicyDecision(
                outcome="deny",
                summary=default_deny.summary,
                rule_evaluations=tuple(evaluations),
                reason_codes=(default_deny.reason_code,),
            )

        denials = [item for item in workflow_evaluations if item.outcome == "deny"]
        if denials:
            return PolicyDecision(
                outcome="deny",
                summary=denials[0].summary,
                rule_evaluations=tuple(evaluations),
                reason_codes=tuple(item.reason_code for item in denials),
            )

        evidence_requirements = [item for item in workflow_evaluations if item.outcome == "needs-evidence"]
        if evidence_requirements:
            missing_evidence = sorted({value for item in evidence_requirements for value in item.required_evidence})
            return PolicyDecision(
                outcome="needs-evidence",
                summary=evidence_requirements[0].summary,
                rule_evaluations=tuple(evaluations),
                reason_codes=tuple(item.reason_code for item in evidence_requirements),
                required_evidence=tuple(missing_evidence),
            )

        approvals = [item for item in workflow_evaluations if item.outcome == "approval-required"]
        if approvals:
            approver_types = sorted({value for item in approvals for value in item.approver_types})
            return PolicyDecision(
                outcome="approval-required",
                summary=approvals[0].summary,
                rule_evaluations=tuple(evaluations),
                reason_codes=tuple(item.reason_code for item in approvals),
                approver_types=tuple(approver_types),
            )

        allows = [item for item in workflow_evaluations if item.outcome == "allow"]
        if allows:
            return PolicyDecision(
                outcome="allow",
                summary=allows[0].summary,
                rule_evaluations=tuple(evaluations),
                reason_codes=tuple(item.reason_code for item in allows),
            )

        fallback_deny = RuleEvaluation(
            rule_id="workflow.no_allow",
            outcome="deny",
            reason_code="WORKFLOW_DENIED",
            summary="The workflow layer did not produce an allow decision.",
        )
        evaluations.append(fallback_deny)
        return PolicyDecision(
            outcome="deny",
            summary=fallback_deny.summary,
            rule_evaluations=tuple(evaluations),
            reason_codes=(fallback_deny.reason_code,),
        )
