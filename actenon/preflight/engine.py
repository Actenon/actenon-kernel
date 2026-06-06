from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from actenon.api.intake import ActionIntentIntakeService
from actenon.models import ActionIntent
from actenon.proof import sha256_hex

from .evidence import PreflightEvidence
from .models import EvidenceKey, PreflightDecision, Requirement
from .policy_packs import DEFAULT_PREFLIGHT_POLICY_PACK, PolicyPack


def _coerce_intent(raw: ActionIntent | Mapping[str, Any]) -> ActionIntent:
    if isinstance(raw, ActionIntent):
        return raw
    return ActionIntentIntakeService().parse(raw)


def _decision_id(*, intent: ActionIntent, reason_code: str, outcome: str) -> str:
    digest = sha256_hex(
        {
            "intent_id": intent.intent_id,
            "capability": intent.action.capability,
            "target": intent.target.to_dict(),
            "outcome": outcome,
            "reason_code": reason_code,
        }
    )
    return f"pfl_{digest[:24]}"


_RISK_PRIORITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_OUTCOME_PRIORITY = {
    "allow": 1,
    "needs_evidence": 2,
    "approval_required": 3,
    "deny": 4,
}


def _result_priority(indexed_result: tuple[int, dict[str, Any]]) -> tuple[int, int, int]:
    index, result = indexed_result
    return (
        _RISK_PRIORITY.get(str(result.get("risk_level", "medium")), 2),
        _OUTCOME_PRIORITY.get(str(result.get("outcome", "needs_evidence")), 2),
        -index,
    )


def _unique_strings(results: list[dict[str, Any]], key: str) -> tuple[str, ...]:
    values: list[str] = []
    for result in results:
        for raw in result.get(key, ()):
            value = str(raw)
            if value not in values:
                values.append(value)
    return tuple(values)


def _requirement_from_result(result: dict[str, Any]) -> Requirement:
    evidence_keys = tuple(
        item if isinstance(item, EvidenceKey) else EvidenceKey.from_dict(dict(item))
        for item in result.get("evidence_keys", ())
    )
    return Requirement(
        reason_code=str(result["reason_code"]),
        summary=str(result["summary"]),
        evidence_keys=evidence_keys,
        required_approvals=tuple(str(item) for item in result.get("required_approvals", ())),
        required_evidence=tuple(str(item) for item in result.get("required_evidence", ())),
        outcome=result["outcome"],
        risk_level=str(result.get("risk_level", "medium")),
        matched_rules=tuple(str(item) for item in result.get("matched_rules", ())),
    )


@dataclass(frozen=True)
class PreflightEngine:
    policy_pack: PolicyPack = DEFAULT_PREFLIGHT_POLICY_PACK

    def check(
        self,
        intent: ActionIntent | Mapping[str, Any],
        *,
        policy_pack: PolicyPack | None = None,
        evidence_context: Mapping[str, Any] | PreflightEvidence | None = None,
    ) -> PreflightDecision:
        parsed_intent = _coerce_intent(intent)
        if isinstance(evidence_context, PreflightEvidence):
            evidence = evidence_context.to_dict()
        else:
            evidence = dict(evidence_context or {})
        pack = policy_pack or self.policy_pack
        results: list[dict[str, Any]] = []
        for rule in pack.rules:
            result = rule(parsed_intent, evidence)
            if result is not None:
                results.append(result)
        if not results:
            raise RuntimeError("preflight policy pack did not produce a decision")

        blockers = [result for result in results if result["outcome"] != "allow"]
        candidates = blockers or [result for result in results if result["outcome"] == "allow"]
        _, selected = max(enumerate(candidates), key=_result_priority)
        requirements = tuple(_requirement_from_result(result) for result in blockers)
        metadata = {
            "policy_pack": {
                "pack_id": pack.pack_id,
                "display_name": pack.display_name,
            },
            "intent_id": parsed_intent.intent_id,
            "capability": parsed_intent.action.capability,
            "target": parsed_intent.target.to_dict(),
            "evaluated_rule_count": len(pack.rules),
            "matched_result_count": len(results),
            "unmet_requirement_count": len(requirements),
            **dict(selected.get("metadata", {})),
        }
        return PreflightDecision(
            decision_id=_decision_id(
                intent=parsed_intent,
                reason_code=str(selected["reason_code"]),
                outcome=str(selected["outcome"]),
            ),
            outcome=selected["outcome"],
            reason_code=str(selected["reason_code"]),
            summary=str(selected["summary"]),
            required_evidence=_unique_strings(blockers, "required_evidence"),
            required_approvals=_unique_strings(blockers, "required_approvals"),
            risk_level=str(selected.get("risk_level", "medium")),
            matched_rules=_unique_strings(blockers or [selected], "matched_rules"),
            metadata=metadata,
            unmet_requirements=requirements,
        )
