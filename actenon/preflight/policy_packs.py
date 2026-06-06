from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from actenon.models import ActionIntent

from .models import EvidenceKey, PreflightOutcome


EvidenceContext = dict[str, Any]
PreflightRule = Callable[[ActionIntent, EvidenceContext], Optional[dict[str, Any]]]


@dataclass(frozen=True)
class PolicyPack:
    pack_id: str
    display_name: str
    capabilities: tuple[str, ...]
    rules: tuple[PreflightRule, ...]


DESTRUCTIVE_AND_DATA_CAPABILITIES: tuple[str, ...] = (
    "database.delete",
    "database.schema.apply",
    "infrastructure.delete",
    "backup.delete",
    "volume.delete",
    "migration.apply",
    "deployment.execute",
    "iam.permission.grant",
    "data.export",
    "payment.release",
)


def _env(intent: ActionIntent, evidence: EvidenceContext) -> str:
    raw = (
        evidence.get("environment")
        or intent.action.parameters.get("environment")
        or intent.target.selectors.get("environment")
        or intent.context.get("environment")
        or "unknown"
    )
    return str(raw).lower()


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"", "0", "false", "no", "n", "none", "null", "missing", "absent", "unavailable"}:
            return False
        return True
    return bool(value)


def _has_change_ticket(intent: ActionIntent, evidence: EvidenceContext) -> bool:
    return _truthy(evidence.get("change_ticket")) or _truthy(intent.action.parameters.get("change_ticket")) or _truthy(intent.context.get("change_ticket"))


def _has_backup_evidence(intent: ActionIntent, evidence: EvidenceContext) -> bool:
    return (
        _truthy(evidence.get("backup_verified"))
        or _truthy(evidence.get("backup_snapshot"))
        or _truthy(intent.action.parameters.get("backup_verified"))
        or _truthy(intent.context.get("backup_verified"))
    )


def _requires_backup(capability: str) -> bool:
    return capability in {
        "database.delete",
        "database.schema.apply",
        "infrastructure.delete",
        "backup.delete",
        "volume.delete",
        "migration.apply",
    }


def _approval_present(intent: ActionIntent, evidence: EvidenceContext) -> bool:
    return (
        _truthy(evidence.get("approval_present"))
        or _truthy(intent.action.parameters.get("approval_present"))
        or _truthy(intent.context.get("approval_present"))
    )


def _approver_types(intent: ActionIntent, evidence: EvidenceContext) -> tuple[str, ...]:
    raw = (
        evidence.get("approver_types")
        or intent.action.parameters.get("approver_types")
        or intent.context.get("approver_types")
        or ()
    )
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in raw)
    return ()


def _approval_satisfied(
    intent: ActionIntent,
    evidence: EvidenceContext,
    required_approvals: tuple[str, ...],
) -> bool:
    if not _approval_present(intent, evidence):
        return False
    provided = _approver_types(intent, evidence)
    if not provided:
        return True
    return set(required_approvals).issubset(provided)


def _row_count(intent: ActionIntent, evidence: EvidenceContext) -> int:
    raw = evidence.get("row_count", intent.action.parameters.get("row_count", intent.action.parameters.get("records", 0)))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _is_external_destination(intent: ActionIntent, evidence: EvidenceContext) -> bool:
    destination = str(evidence.get("destination", intent.action.parameters.get("destination", ""))).lower()
    return destination.startswith(("http://", "https://", "s3://", "gs://")) or destination in {"external", "third_party", "vendor"}


def _result(
    *,
    outcome: PreflightOutcome,
    reason_code: str,
    summary: str,
    risk_level: str,
    matched_rule: str,
    required_evidence: tuple[str, ...] = (),
    required_approvals: tuple[str, ...] = (),
    evidence_keys: tuple[EvidenceKey, ...] = (),
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "reason_code": reason_code,
        "summary": summary,
        "risk_level": risk_level,
        "matched_rules": (matched_rule,),
        "required_evidence": required_evidence,
        "required_approvals": required_approvals,
        "evidence_keys": evidence_keys,
        "metadata": dict(metadata or {}),
    }


def _evidence_key(
    key: str,
    value_type: str,
    example: Any,
    description: str,
) -> EvidenceKey:
    return EvidenceKey(
        key=key,
        value_type=value_type,
        example=example,
        description=description,
    )


def _approval_evidence_keys(required_approvals: tuple[str, ...]) -> tuple[EvidenceKey, ...]:
    return (
        _evidence_key(
            "approval_present",
            "boolean",
            True,
            "Set true only after the required approval has been verified.",
        ),
        _evidence_key(
            "approver_types",
            "array[string]",
            list(required_approvals),
            "Approval roles present for this exact action.",
        ),
    )


def _unsupported_capability(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    if intent.action.capability not in DESTRUCTIVE_AND_DATA_CAPABILITIES:
        classification = str(evidence.get("capability_classification", "")).strip().lower()
        if classification == "non_consequential":
            return None
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_CAPABILITY_UNCLASSIFIED",
            summary="The action capability is not covered by the default preflight policy pack.",
            risk_level="medium",
            matched_rule="destructive_data.capability_unclassified",
            required_evidence=("capability_classification",),
            evidence_keys=(
                _evidence_key(
                    "capability_classification",
                    "string",
                    "non_consequential",
                    "Use non_consequential only after locally reviewing a capability outside the default policy pack.",
                ),
            ),
            metadata={"capability": intent.action.capability},
        )
    return None


def _missing_change_ticket(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    capability = intent.action.capability
    environment = _env(intent, evidence)
    if capability in DESTRUCTIVE_AND_DATA_CAPABILITIES and environment == "production" and not _has_change_ticket(intent, evidence):
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_CHANGE_TICKET_REQUIRED",
            summary="Production consequential action requires a change ticket before execution.",
            risk_level="high",
            matched_rule="destructive_data.change_ticket_required",
            required_evidence=("change_ticket",),
            evidence_keys=(
                _evidence_key(
                    "change_ticket",
                    "string",
                    "CHG-2026-0042",
                    "Verified change-ticket identifier bound to this action.",
                ),
            ),
            metadata={"environment": environment, "capability": capability},
        )
    return None


def _missing_backup_evidence(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    capability = intent.action.capability
    environment = _env(intent, evidence)
    if environment == "production" and _requires_backup(capability) and not _has_backup_evidence(intent, evidence):
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_BACKUP_EVIDENCE_REQUIRED",
            summary="Production destructive action requires current backup evidence before execution.",
            risk_level="high",
            matched_rule="destructive_data.backup_evidence_required",
            required_evidence=("backup_verified",),
            evidence_keys=(
                _evidence_key(
                    "backup_verified",
                    "boolean",
                    True,
                    "True only after a current backup has been verified.",
                ),
            ),
            metadata={"environment": environment, "capability": capability},
        )
    return None


def _production_destructive_without_approval(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    capability = intent.action.capability
    environment = _env(intent, evidence)
    if environment != "production":
        return None
    if capability in {"database.delete", "infrastructure.delete", "backup.delete", "volume.delete", "migration.apply", "database.schema.apply"}:
        if capability == "backup.delete":
            return _result(
                outcome="deny",
                reason_code="PREFLIGHT_PRODUCTION_BACKUP_DELETE_DENIED",
                summary="Production backup deletion is denied by the default preflight policy pack.",
                risk_level="critical",
                matched_rule="destructive_data.production_backup_delete_denied",
                metadata={"environment": environment, "capability": capability},
            )
        required_approvals = ("infrastructure_owner", "security_admin")
        if not _approval_satisfied(intent, evidence, required_approvals):
            return _result(
                outcome="approval_required",
                reason_code="PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
                summary="Production destructive action requires explicit approval before execution.",
                risk_level="critical",
                matched_rule="destructive_data.production_destructive_approval_required",
                required_approvals=required_approvals,
                evidence_keys=_approval_evidence_keys(required_approvals),
                metadata={"environment": environment, "capability": capability},
            )
    return None


def _broad_data_export(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    if intent.action.capability != "data.export":
        return None
    row_count = _row_count(intent, evidence)
    sensitive = _truthy(evidence.get("sensitive_data", intent.action.parameters.get("sensitive_data")))
    external = _is_external_destination(intent, evidence)
    required_approvals = ("data_owner", "privacy_reviewer")
    if (row_count >= 10_000 or sensitive or external) and not _approval_satisfied(
        intent,
        evidence,
        required_approvals,
    ):
        return _result(
            outcome="approval_required",
            reason_code="PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED",
            summary="Broad or sensitive data export requires approval before execution.",
            risk_level="high",
            matched_rule="destructive_data.broad_data_export_approval_required",
            required_approvals=required_approvals,
            evidence_keys=_approval_evidence_keys(required_approvals),
            metadata={"row_count": row_count, "sensitive_data": sensitive, "external_destination": external},
        )
    return None


def _admin_permission_grant(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    if intent.action.capability != "iam.permission.grant":
        return None
    role = str(evidence.get("role", intent.action.parameters.get("role", intent.action.parameters.get("permission", "")))).lower()
    required_approvals = ("security_admin",)
    if (
        role in {"admin", "administrator", "owner", "root", "superuser"}
        or "*" in role
    ) and not _approval_satisfied(intent, evidence, required_approvals):
        return _result(
            outcome="approval_required",
            reason_code="PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED",
            summary="Admin or wildcard permission grant requires approval before execution.",
            risk_level="high",
            matched_rule="destructive_data.admin_permission_approval_required",
            required_approvals=required_approvals,
            evidence_keys=_approval_evidence_keys(required_approvals),
            metadata={"role": role},
        )
    return None


def _sandbox_low_risk_allow(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    environment = _env(intent, evidence)
    if environment in {"sandbox", "dev", "development", "test", "staging"}:
        return _result(
            outcome="allow",
            reason_code="PREFLIGHT_SANDBOX_LOW_RISK_ALLOWED",
            summary="Sandbox or non-production consequential action is allowed by the default preflight policy pack.",
            risk_level="low",
            matched_rule="destructive_data.sandbox_low_risk_allowed",
            metadata={"environment": environment, "capability": intent.action.capability},
        )
    return None


def _default_decision(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
    environment = _env(intent, evidence)
    if environment == "unknown":
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_CONTEXT_REQUIRED",
            summary="Preflight needs an environment classification before this action can proceed.",
            risk_level="medium",
            matched_rule="destructive_data.context_required",
            required_evidence=("environment",),
            evidence_keys=(
                _evidence_key(
                    "environment",
                    "string",
                    "production",
                    "Deployment environment for the exact target action.",
                ),
            ),
            metadata={"capability": intent.action.capability},
        )
    return _result(
        outcome="allow",
        reason_code="PREFLIGHT_REQUIREMENTS_SATISFIED",
        summary="All requirements in the default Preflight policy pack are satisfied.",
        risk_level="low",
        matched_rule="destructive_data.requirements_satisfied",
        metadata={"environment": environment, "capability": intent.action.capability},
    )


def build_destructive_actions_policy_pack() -> PolicyPack:
    return PolicyPack(
        pack_id="destructive_data_v1",
        display_name="Destructive infrastructure and data actions",
        capabilities=DESTRUCTIVE_AND_DATA_CAPABILITIES,
        rules=(
            _unsupported_capability,
            _missing_change_ticket,
            _missing_backup_evidence,
            _production_destructive_without_approval,
            _broad_data_export,
            _admin_permission_grant,
            _sandbox_low_risk_allow,
            _default_decision,
        ),
    )


DEFAULT_PREFLIGHT_POLICY_PACK = build_destructive_actions_policy_pack()
