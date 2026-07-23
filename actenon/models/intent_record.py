from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping

from .contracts import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PartyRef,
    TargetRef,
    TenantRef,
    expect_mapping,
    expect_string,
    format_timestamp,
    parse_timestamp,
)
from .runtime import DynamicContextInput, PolicyDecision


IntentRecordProofStatus = Literal["issued", "not-issued"]


def _normalize_string_tuple(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, tuple):
        return tuple(str(item) for item in raw if str(item))
    if isinstance(raw, list):
        return tuple(str(item) for item in raw if str(item))
    return ()


def _slug_intent_record_source(value: str) -> str:
    cleaned = "".join(char if char.isalnum() else "_" for char in value)
    return cleaned.strip("_") or "intent_record"


@dataclass(frozen=True)
class BlastRadiusLimit:
    name: str
    summary: str
    value: str | int | float | bool | None = None
    unit: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "BlastRadiusLimit":
        data = expect_mapping(raw, "blast_radius_limit")
        return cls(
            name=expect_string(data.get("name"), "blast_radius_limit.name"),
            summary=expect_string(data.get("summary"), "blast_radius_limit.summary"),
            value=data.get("value"),
            unit=data.get("unit"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "summary": self.summary,
        }
        if self.value is not None:
            payload["value"] = self.value
        if self.unit is not None:
            payload["unit"] = self.unit
        return payload


@dataclass(frozen=True)
class IntentBoundaries:
    prohibited_actions: tuple[str, ...] = ()
    abort_conditions: tuple[str, ...] = ()
    blast_radius_limits: tuple[BlastRadiusLimit, ...] = ()
    required_approvals: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: Any) -> "IntentBoundaries":
        data = expect_mapping(raw, "boundaries")
        return cls(
            prohibited_actions=tuple(str(item) for item in data.get("prohibited_actions", ())),
            abort_conditions=tuple(str(item) for item in data.get("abort_conditions", ())),
            blast_radius_limits=tuple(BlastRadiusLimit.from_dict(item) for item in data.get("blast_radius_limits", ())),
            required_approvals=tuple(str(item) for item in data.get("required_approvals", ())),
            required_evidence=tuple(str(item) for item in data.get("required_evidence", ())),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if self.prohibited_actions:
            payload["prohibited_actions"] = list(self.prohibited_actions)
        if self.abort_conditions:
            payload["abort_conditions"] = list(self.abort_conditions)
        if self.blast_radius_limits:
            payload["blast_radius_limits"] = [item.to_dict() for item in self.blast_radius_limits]
        if self.required_approvals:
            payload["required_approvals"] = list(self.required_approvals)
        if self.required_evidence:
            payload["required_evidence"] = list(self.required_evidence)
        return payload


@dataclass(frozen=True)
class IntentRecordDecision:
    outcome: str
    summary: str
    reason_codes: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: Any) -> "IntentRecordDecision":
        data = expect_mapping(raw, "decision")
        return cls(
            outcome=expect_string(data.get("outcome"), "decision.outcome"),
            summary=expect_string(data.get("summary"), "decision.summary"),
            reason_codes=tuple(str(item) for item in data.get("reason_codes", ())),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "outcome": self.outcome,
            "summary": self.summary,
        }
        if self.reason_codes:
            payload["reason_codes"] = list(self.reason_codes)
        return payload


@dataclass(frozen=True)
class IntentRecordProofState:
    required_for_execution: bool
    status: IntentRecordProofStatus
    pccb_id: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "IntentRecordProofState":
        data = expect_mapping(raw, "proof")
        return cls(
            required_for_execution=bool(data.get("required_for_execution", True)),
            status=expect_string(data.get("status"), "proof.status"),
            pccb_id=data.get("pccb_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "required_for_execution": self.required_for_execution,
            "status": self.status,
        }
        if self.pccb_id is not None:
            payload["pccb_id"] = self.pccb_id
        return payload


@dataclass(frozen=True)
class IntentRecordEvidenceState:
    receipt_id: str | None = None
    refusal_id: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "IntentRecordEvidenceState":
        data = expect_mapping(raw, "execution_evidence")
        return cls(
            receipt_id=data.get("receipt_id"),
            refusal_id=data.get("refusal_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if self.receipt_id is not None:
            payload["receipt_id"] = self.receipt_id
        if self.refusal_id is not None:
            payload["refusal_id"] = self.refusal_id
        return payload


@dataclass(frozen=True)
class IntentRecord:
    intent_record_id: str
    created_at: datetime
    source: str
    intent_id: str
    tenant: TenantRef
    subject: PartyRef
    audience: AudienceRef
    action: ActionSpec
    target: TargetRef
    decision: IntentRecordDecision
    boundaries: IntentBoundaries
    proof: IntentRecordProofState
    execution_evidence: IntentRecordEvidenceState = field(default_factory=IntentRecordEvidenceState)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "IntentRecord":
        data = expect_mapping(raw, "intent_record")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != "intent_record" or contract.get("version") != "v1alpha1":
            raise ValueError("contract must declare intent_record v1alpha1")
        return cls(
            intent_record_id=expect_string(data.get("intent_record_id"), "intent_record_id"),
            created_at=parse_timestamp(data.get("created_at"), "created_at"),
            source=expect_string(data.get("source"), "source"),
            intent_id=expect_string(data.get("intent_id"), "intent_id"),
            tenant=TenantRef.from_dict(data.get("tenant")),
            subject=PartyRef.from_dict(data.get("subject"), "subject"),
            audience=AudienceRef.from_dict(data.get("audience"), "audience"),
            action=ActionSpec.from_dict(data.get("action")),
            target=TargetRef.from_dict(data.get("target")),
            decision=IntentRecordDecision.from_dict(data.get("decision")),
            boundaries=IntentBoundaries.from_dict(data.get("boundaries", {})),
            proof=IntentRecordProofState.from_dict(data.get("proof")),
            execution_evidence=IntentRecordEvidenceState.from_dict(data.get("execution_evidence", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": {"name": "intent_record", "version": "v1alpha1"},
            "intent_record_id": self.intent_record_id,
            "created_at": format_timestamp(self.created_at),
            "source": self.source,
            "intent_id": self.intent_id,
            "tenant": self.tenant.to_dict(),
            "subject": self.subject.to_dict(),
            "audience": self.audience.to_dict(),
            "action": self.action.to_dict(),
            "target": self.target.to_dict(),
            "decision": self.decision.to_dict(),
            "boundaries": self.boundaries.to_dict(),
            "proof": self.proof.to_dict(),
            "execution_evidence": self.execution_evidence.to_dict(),
        }


def _normalize_blast_radius_limits(raw: Any) -> tuple[BlastRadiusLimit, ...]:
    if raw is None:
        return ()
    if isinstance(raw, tuple):
        return tuple(item if isinstance(item, BlastRadiusLimit) else BlastRadiusLimit.from_dict(item) for item in raw)
    if isinstance(raw, list):
        return tuple(item if isinstance(item, BlastRadiusLimit) else BlastRadiusLimit.from_dict(item) for item in raw)
    if isinstance(raw, Mapping):
        normalized: list[BlastRadiusLimit] = []
        for name, value in raw.items():
            if isinstance(value, Mapping):
                normalized.append(
                    BlastRadiusLimit(
                        name=str(value.get("name", name)),
                        summary=str(value.get("summary", f"Bound {name} during delegated execution.")),
                        value=value.get("value"),
                        unit=value.get("unit"),
                    )
                )
            else:
                normalized.append(
                    BlastRadiusLimit(
                        name=str(name),
                        summary=f"Bound {name} during delegated execution.",
                        value=value,
                    )
                )
        return tuple(normalized)
    return ()


def build_intent_record(
    *,
    source: str,
    intent: ActionIntent,
    context: DynamicContextInput,
    decision: PolicyDecision,
    intent_record_id: str | None = None,
    created_at: datetime | None = None,
    pccb_id: str | None = None,
    receipt_id: str | None = None,
    refusal_id: str | None = None,
    prohibited_actions: tuple[str, ...] | None = None,
    abort_conditions: tuple[str, ...] | None = None,
    blast_radius_limits: tuple[BlastRadiusLimit, ...] | Mapping[str, Any] | None = None,
    required_approvals: tuple[str, ...] | None = None,
    required_evidence: tuple[str, ...] | None = None,
) -> IntentRecord:
    derived_required_approvals = (
        required_approvals
        if required_approvals is not None
        else (
            _normalize_string_tuple(context.facts.get("required_approval_chain"))
            or tuple(str(item) for item in (decision.approver_types or context.approver_types))
        )
    )
    derived_required_evidence = (
        required_evidence
        if required_evidence is not None
        else (
            tuple(str(item) for item in (decision.required_evidence or context.required_evidence_types))
            or _normalize_string_tuple(context.facts.get("required_evidence_types"))
        )
    )
    boundaries = IntentBoundaries(
        prohibited_actions=prohibited_actions if prohibited_actions is not None else _normalize_string_tuple(context.facts.get("prohibited_actions")),
        abort_conditions=abort_conditions if abort_conditions is not None else _normalize_string_tuple(context.facts.get("abort_conditions")),
        blast_radius_limits=_normalize_blast_radius_limits(
            blast_radius_limits if blast_radius_limits is not None else context.facts.get("blast_radius_limits")
        ),
        required_approvals=tuple(str(item) for item in derived_required_approvals),
        required_evidence=tuple(str(item) for item in derived_required_evidence),
    )
    proof_status: IntentRecordProofStatus = "issued" if pccb_id is not None else "not-issued"
    resolved_record_id = intent_record_id or f"ir_{_slug_intent_record_source(source)}_{intent.intent_id}"
    return IntentRecord(
        intent_record_id=resolved_record_id,
        created_at=created_at or context.now,
        source=source,
        intent_id=intent.intent_id,
        tenant=intent.tenant,
        subject=intent.requester,
        audience=context.audience,
        action=intent.action,
        target=intent.target,
        decision=IntentRecordDecision(
            outcome=decision.outcome,
            summary=decision.summary,
            reason_codes=tuple(str(item) for item in decision.reason_codes),
        ),
        boundaries=boundaries,
        proof=IntentRecordProofState(
            required_for_execution=True,
            status=proof_status,
            pccb_id=pccb_id,
        ),
        execution_evidence=IntentRecordEvidenceState(
            receipt_id=receipt_id,
            refusal_id=refusal_id,
        ),
    )
