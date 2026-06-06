from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


PreflightOutcome = Literal["allow", "deny", "approval_required", "needs_evidence"]
PREFLIGHT_OUTCOMES: tuple[str, ...] = ("allow", "deny", "approval_required", "needs_evidence")


@dataclass(frozen=True)
class EvidenceKey:
    key: str
    value_type: str
    example: Any
    description: str
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "type": self.value_type,
            "example": self.example,
            "description": self.description,
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EvidenceKey":
        return cls(
            key=str(raw["key"]),
            value_type=str(raw["type"]),
            example=raw.get("example"),
            description=str(raw.get("description", "")),
            required=bool(raw.get("required", True)),
        )


@dataclass(frozen=True)
class Requirement:
    reason_code: str
    summary: str
    evidence_keys: tuple[EvidenceKey, ...] = ()
    required_approvals: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    outcome: PreflightOutcome = "needs_evidence"
    risk_level: str = "medium"
    matched_rules: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "summary": self.summary,
            "evidence_keys": [item.to_dict() for item in self.evidence_keys],
            "required_approvals": list(self.required_approvals),
            "required_evidence": list(self.required_evidence),
            "outcome": self.outcome,
            "risk_level": self.risk_level,
            "matched_rules": list(self.matched_rules),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Requirement":
        outcome = raw.get("outcome", "needs_evidence")
        if outcome not in PREFLIGHT_OUTCOMES:
            raise ValueError("requirement outcome must be a valid Preflight outcome")
        return cls(
            reason_code=str(raw["reason_code"]),
            summary=str(raw["summary"]),
            evidence_keys=tuple(EvidenceKey.from_dict(dict(item)) for item in raw.get("evidence_keys", [])),
            required_approvals=tuple(str(item) for item in raw.get("required_approvals", [])),
            required_evidence=tuple(str(item) for item in raw.get("required_evidence", [])),
            outcome=outcome,
            risk_level=str(raw.get("risk_level", "medium")),
            matched_rules=tuple(str(item) for item in raw.get("matched_rules", [])),
        )


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
    unmet_requirements: tuple[Requirement, ...] = ()

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
            "unmet_requirements": [item.to_dict() for item in self.unmet_requirements],
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
            unmet_requirements=tuple(
                Requirement.from_dict(dict(item))
                for item in raw.get("unmet_requirements", [])
            ),
        )
