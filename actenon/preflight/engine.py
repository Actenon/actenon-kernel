from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from actenon.api.intake import ActionIntentIntakeService
from actenon.models import ActionIntent
from actenon.proof import sha256_hex
from actenon.verifier.trust_artifacts import verify_approval_artifact

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


def _party_key(raw: Any) -> tuple[str, str] | None:
    if not isinstance(raw, Mapping):
        return None
    party_type = raw.get("type")
    party_id = raw.get("id")
    if not isinstance(party_type, str) or not isinstance(party_id, str):
        return None
    return party_type, party_id


def _with_verified_approvals(
    intent: ActionIntent,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    raw_artifacts = evidence.get("approval_artifacts", ())
    if not raw_artifacts:
        return evidence
    if not isinstance(raw_artifacts, (list, tuple)):
        raise ValueError("approval_artifacts must be an array of approval objects")
    raw_key_sets = evidence.get("approval_trusted_keys", ())
    if not isinstance(raw_key_sets, (list, tuple)) or not raw_key_sets:
        raise ValueError(
            "approval_trusted_keys must contain a public key set for each signed approval"
        )
    key_sets: dict[tuple[str, str], Mapping[str, Any]] = {}
    for raw_key_set in raw_key_sets:
        if not isinstance(raw_key_set, Mapping):
            raise ValueError("approval_trusted_keys entries must be JSON objects")
        identity = _party_key(raw_key_set.get("issuer"))
        if identity is None or identity in key_sets:
            raise ValueError(
                "approval_trusted_keys must have unique, valid issuer identities"
            )
        key_sets[identity] = raw_key_set

    approval_types: list[str] = []
    approver_ids: list[str] = []
    approval_ids: list[str] = []
    for raw_artifact in raw_artifacts:
        if not isinstance(raw_artifact, Mapping):
            raise ValueError("approval_artifacts entries must be JSON objects")
        identity = _party_key(raw_artifact.get("approver"))
        if identity is None or identity not in key_sets:
            raise ValueError(
                "no trusted approval key set matches the artifact approver"
            )
        verified = verify_approval_artifact(
            raw_artifact,
            key_sets[identity],
            expected_action=intent,
        )
        if verified.approval_type not in approval_types:
            approval_types.append(verified.approval_type)
        if verified.approver.id not in approver_ids:
            approver_ids.append(verified.approver.id)
        approval_ids.append(verified.approval_id)

    return {
        **evidence,
        "verified_approval_present": True,
        "verified_approver_types": approval_types,
        "verified_approver_ids": approver_ids,
        "verified_approval_ids": approval_ids,
    }


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
        evidence = _with_verified_approvals(parsed_intent, evidence)
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
        policy_pack_metadata: dict[str, Any] = {
            "pack_id": pack.pack_id,
            "display_name": pack.display_name,
        }
        if pack.is_template:
            policy_pack_metadata["is_template"] = True
            policy_pack_metadata["disclaimer"] = pack.disclaimer
        metadata = {
            "policy_pack": policy_pack_metadata,
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
