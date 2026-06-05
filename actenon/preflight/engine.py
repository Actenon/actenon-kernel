from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from actenon.api.intake import ActionIntentIntakeService
from actenon.models import ActionIntent
from actenon.proof import sha256_hex

from .models import PreflightDecision
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


@dataclass(frozen=True)
class PreflightEngine:
    policy_pack: PolicyPack = DEFAULT_PREFLIGHT_POLICY_PACK

    def check(
        self,
        intent: ActionIntent | Mapping[str, Any],
        *,
        policy_pack: PolicyPack | None = None,
        evidence_context: Mapping[str, Any] | None = None,
    ) -> PreflightDecision:
        parsed_intent = _coerce_intent(intent)
        evidence = dict(evidence_context or {})
        pack = policy_pack or self.policy_pack
        for rule in pack.rules:
            result = rule(parsed_intent, evidence)
            if result is None:
                continue
            metadata = {
                "policy_pack": {
                    "pack_id": pack.pack_id,
                    "display_name": pack.display_name,
                },
                "intent_id": parsed_intent.intent_id,
                "capability": parsed_intent.action.capability,
                "target": parsed_intent.target.to_dict(),
                **dict(result.get("metadata", {})),
            }
            return PreflightDecision(
                decision_id=_decision_id(
                    intent=parsed_intent,
                    reason_code=str(result["reason_code"]),
                    outcome=str(result["outcome"]),
                ),
                outcome=result["outcome"],
                reason_code=str(result["reason_code"]),
                summary=str(result["summary"]),
                required_evidence=tuple(str(item) for item in result.get("required_evidence", ())),
                required_approvals=tuple(str(item) for item in result.get("required_approvals", ())),
                risk_level=str(result.get("risk_level", "medium")),
                matched_rules=tuple(str(item) for item in result.get("matched_rules", ())),
                metadata=metadata,
            )
        raise RuntimeError("preflight policy pack did not produce a decision")
