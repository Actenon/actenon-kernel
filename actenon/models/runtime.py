from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from .contracts import ActionIntent, AudienceRef, PCCB, Receipt, Refusal, utc_now


PolicyOutcome = Literal["allow", "deny", "approval-required", "needs-evidence"]


@dataclass(frozen=True)
class DynamicContextInput:
    request_id: str
    audience: AudienceRef
    scope_capabilities: tuple[str, ...]
    now: datetime = field(default_factory=utc_now)
    facts: dict[str, Any] = field(default_factory=dict)
    parameter_constraints: dict[str, Any] = field(default_factory=dict)
    resource_selectors: tuple[dict[str, Any], ...] = ()
    required_evidence_types: tuple[str, ...] = ()
    approver_types: tuple[str, ...] = ()
    max_ttl_seconds: int | None = 900


@dataclass(frozen=True)
class RuleEvaluation:
    rule_id: str
    outcome: PolicyOutcome
    reason_code: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    required_evidence: tuple[str, ...] = ()
    approver_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    outcome: PolicyOutcome
    summary: str
    rule_evaluations: tuple[RuleEvaluation, ...]
    reason_codes: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    approver_types: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"


@dataclass(frozen=True)
class AdmissionResult:
    intent: ActionIntent | None
    decision: PolicyDecision | None
    receipt: Receipt | None
    refusal: Refusal | None
    pccb: PCCB | None = None
    escrow_id: str | None = None


@dataclass(frozen=True)
class ProtectedExecutionRequest:
    intent: ActionIntent
    pccb: PCCB
    context: DynamicContextInput


@dataclass(frozen=True)
class ExecutionResult:
    receipt: Receipt | None
    refusal: Refusal | None
    payload: dict[str, Any] | None = None
