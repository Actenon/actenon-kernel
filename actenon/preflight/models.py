from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


PreflightOutcome = Literal["allow", "deny", "approval_required", "needs_evidence"]
PREFLIGHT_OUTCOMES: tuple[str, ...] = ("allow", "deny", "approval_required", "needs_evidence")


@dataclass(frozen=True)
class PreflightDecision:
    decision_id: str
    outcome: PreflightOutcome
    reason_code: str
    summary: str
    required_evidence: tuple[str, ...] = ()
    required_approvals: tuple[str, ...] = ()
    risk_level: str = "medium"
    matched_rules: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": {"name": "preflight_decision", "version": "v1"},
            "decision_id": self.decision_id,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "summary": self.summary,
            "required_evidence": list(self.required_evidence),
            "required_approvals": list(self.required_approvals),
            "risk_level": self.risk_level,
            "matched_rules": list(self.matched_rules),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PreflightDecision":
        contract = raw.get("contract")
        if not isinstance(contract, dict) or contract.get("name") != "preflight_decision" or contract.get("version") != "v1":
            raise ValueError("contract must declare preflight_decision v1")
        outcome = raw.get("outcome")
        if outcome not in PREFLIGHT_OUTCOMES:
            raise ValueError("outcome must be one of allow, deny, approval_required, needs_evidence")
        return cls(
            decision_id=str(raw["decision_id"]),
            outcome=outcome,
            reason_code=str(raw["reason_code"]),
            summary=str(raw["summary"]),
            required_evidence=tuple(str(item) for item in raw.get("required_evidence", [])),
            required_approvals=tuple(str(item) for item in raw.get("required_approvals", [])),
            risk_level=str(raw.get("risk_level", "medium")),
            matched_rules=tuple(str(item) for item in raw.get("matched_rules", [])),
            metadata=dict(raw.get("metadata", {})),
        )
