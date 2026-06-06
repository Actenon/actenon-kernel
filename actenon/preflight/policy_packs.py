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
    is_template: bool = False
    disclaimer: str | None = None


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

DATA_PRIVACY_CAPABILITIES: tuple[str, ...] = (
    "data.export",
    "data.download",
    "data.share",
    "data.sync.external",
    "report.generate.external",
)

ACCESS_GOVERNANCE_CAPABILITIES: tuple[str, ...] = (
    "iam.permission.grant",
    "iam.role.assign",
    "iam.role.membership.change",
    "iam.api_key.create",
    "iam.credential.rotate",
    "workspace.share",
)

PAYMENTS_CAPABILITIES: tuple[str, ...] = (
    "payment.create",
    "payment.release",
    "payment.transfer",
    "payment.refund",
    "invoice.approve",
    "payout.release",
    "bank_details.update",
)

CLINICAL_TEMPLATE_CAPABILITIES: tuple[str, ...] = (
    "clinical.note.draft",
    "clinical.note.publish",
    "clinical.record.update",
    "medication.order",
    "treatment_plan.change",
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


def _sensitivity_classification(
    intent: ActionIntent,
    evidence: EvidenceContext,
) -> str:
    for key in ("sensitivity_classification", "data_classification", "sensitivity"):
        value = _string_value(intent, evidence, key)
        if value:
            return value
    return ""


def _is_external_destination(intent: ActionIntent, evidence: EvidenceContext) -> bool:
    destination = _string_value(intent, evidence, "destination")
    destination_classification = _string_value(
        intent,
        evidence,
        "destination_classification",
    )
    return (
        destination.startswith(("http://", "https://", "s3://", "gs://"))
        or destination in {"external", "third_party", "vendor"}
        or destination_classification in {"external", "third_party", "vendor"}
    )


def _value(intent: ActionIntent, evidence: EvidenceContext, key: str, default: Any = None) -> Any:
    if key in evidence:
        return evidence[key]
    if key in intent.action.parameters:
        return intent.action.parameters[key]
    return intent.context.get(key, default)


def _string_value(
    intent: ActionIntent,
    evidence: EvidenceContext,
    key: str,
    default: str = "",
) -> str:
    return str(_value(intent, evidence, key, default)).strip().lower()


def _string_values(
    intent: ActionIntent,
    evidence: EvidenceContext,
    key: str,
) -> tuple[str, ...]:
    raw = _value(intent, evidence, key, ())
    if isinstance(raw, str):
        return (raw.strip().lower(),) if raw.strip() else ()
    if isinstance(raw, (list, tuple, set, frozenset)):
        return tuple(str(item).strip().lower() for item in raw if str(item).strip())
    return ()


def _domain_capability_rule(
    *,
    pack_id: str,
    capabilities: tuple[str, ...],
) -> PreflightRule:
    def check(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any] | None:
        if intent.action.capability in capabilities:
            return None
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_CAPABILITY_NOT_COVERED",
            summary=f"The action capability is not covered by the {pack_id} policy pack.",
            risk_level="medium",
            matched_rule=f"{pack_id}.capability_not_covered",
            required_evidence=("policy_pack_selection",),
            evidence_keys=(
                _evidence_key(
                    "policy_pack_selection",
                    "string",
                    pack_id,
                    "Select a policy pack that explicitly covers this action capability.",
                ),
            ),
            metadata={"capability": intent.action.capability},
        )

    return check


def _requirements_satisfied_rule(
    *,
    pack_id: str,
    summary: str,
) -> PreflightRule:
    def allow(intent: ActionIntent, evidence: EvidenceContext) -> dict[str, Any]:
        return _result(
            outcome="allow",
            reason_code="PREFLIGHT_REQUIREMENTS_SATISFIED",
            summary=summary,
            risk_level="low",
            matched_rule=f"{pack_id}.requirements_satisfied",
            metadata={"capability": intent.action.capability},
        )

    return allow


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


def build_evidence_key(
    key: str,
    value_type: str,
    example: Any,
    description: str,
) -> EvidenceKey:
    """Build one documented evidence requirement for a custom rule."""

    return _evidence_key(key, value_type, example, description)


def build_preflight_rule_result(
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
    """Build a result dictionary with the shape consumed by PreflightEngine."""

    return _result(
        outcome=outcome,
        reason_code=reason_code,
        summary=summary,
        risk_level=risk_level,
        matched_rule=matched_rule,
        required_evidence=required_evidence,
        required_approvals=required_approvals,
        evidence_keys=evidence_keys,
        metadata=metadata,
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


def build_data_privacy_policy_pack(
    *,
    broad_export_row_threshold: int = 10_000,
    allowed_external_destinations: tuple[str, ...] = (),
    allowed_residency_pairs: tuple[tuple[str, str], ...] = (),
) -> PolicyPack:
    """Build policy for representative data export, sharing, and egress actions."""

    if broad_export_row_threshold < 1:
        raise ValueError("broad_export_row_threshold must be positive")
    allowed_destinations = {
        value.strip().lower()
        for value in allowed_external_destinations
        if value.strip()
    }
    allowed_residencies = {
        (source.strip().lower(), destination.strip().lower())
        for source, destination in allowed_residency_pairs
        if source.strip() and destination.strip()
    }

    def classification_required(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in DATA_PRIVACY_CAPABILITIES:
            return None
        sensitivity = _sensitivity_classification(intent, evidence)
        if sensitivity or _truthy(_value(intent, evidence, "sensitive_data")):
            return None
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_DATA_CLASSIFICATION_REQUIRED",
            summary="Data movement requires a sensitivity classification before execution.",
            risk_level="medium",
            matched_rule="data_privacy.data_classification_required",
            required_evidence=("sensitivity_classification",),
            evidence_keys=(
                _evidence_key(
                    "sensitivity_classification",
                    "string",
                    "internal",
                    "Classification for the exact dataset, such as public, internal, confidential, restricted, pii, or phi.",
                ),
            ),
        )

    def broad_or_sensitive_export(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in DATA_PRIVACY_CAPABILITIES:
            return None
        row_count = _row_count(intent, evidence)
        sensitivity = _sensitivity_classification(intent, evidence)
        sensitive = sensitivity in {
            "confidential",
            "restricted",
            "sensitive",
            "pii",
            "phi",
            "financial",
        } or _truthy(_value(intent, evidence, "sensitive_data"))
        external = _is_external_destination(intent, evidence)
        required_approvals = ("data_owner", "privacy_reviewer")
        if (
            row_count >= broad_export_row_threshold or sensitive or external
        ) and not _approval_satisfied(intent, evidence, required_approvals):
            return _result(
                outcome="approval_required",
                reason_code="PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED",
                summary="Broad, sensitive, or external data movement requires data-owner and privacy approval.",
                risk_level="high",
                matched_rule="data_privacy.broad_export_approval_required",
                required_approvals=required_approvals,
                evidence_keys=_approval_evidence_keys(required_approvals),
                metadata={
                    "row_count": row_count,
                    "row_threshold": broad_export_row_threshold,
                    "sensitivity_classification": sensitivity,
                    "external_destination": external,
                },
            )
        return None

    def external_destination_control(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in DATA_PRIVACY_CAPABILITIES:
            return None
        if not _is_external_destination(intent, evidence):
            return None
        destination = _string_value(intent, evidence, "destination")
        configured_allow = destination in allowed_destinations
        evidence_allow = _truthy(_value(intent, evidence, "destination_allowlisted"))
        egress_approval = _truthy(_value(intent, evidence, "external_egress_approved"))
        if configured_allow or evidence_allow or egress_approval:
            return None
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_EXTERNAL_EGRESS_EVIDENCE_REQUIRED",
            summary="External data movement requires an allow-listed destination or verified egress exception.",
            risk_level="high",
            matched_rule="data_privacy.external_egress_evidence_required",
            required_evidence=("destination_allowlisted", "external_egress_approved"),
            evidence_keys=(
                _evidence_key(
                    "destination_allowlisted",
                    "boolean",
                    True,
                    "True when the exact destination is on the deployment's reviewed allow-list.",
                ),
                _evidence_key(
                    "external_egress_approved",
                    "boolean",
                    True,
                    "True only after a reviewed exception authorizes this exact external destination.",
                ),
            ),
            metadata={"destination": destination},
        )

    def residency_control(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in DATA_PRIVACY_CAPABILITIES:
            return None
        source = _string_value(intent, evidence, "source_residency")
        destination = _string_value(intent, evidence, "destination_residency")
        if not source or not destination or source == destination:
            return None
        configured_allow = (source, destination) in allowed_residencies
        if configured_allow or _truthy(_value(intent, evidence, "residency_allowed")):
            return None
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_RESIDENCY_EVIDENCE_REQUIRED",
            summary="Cross-residency data movement requires verified residency authorization.",
            risk_level="high",
            matched_rule="data_privacy.residency_evidence_required",
            required_evidence=("residency_allowed",),
            evidence_keys=(
                _evidence_key(
                    "residency_allowed",
                    "boolean",
                    True,
                    "True only when policy permits this exact source-to-destination residency pair.",
                ),
            ),
            metadata={
                "source_residency": source,
                "destination_residency": destination,
            },
        )

    return PolicyPack(
        pack_id="data_privacy_v1",
        display_name="Data privacy and external egress",
        capabilities=DATA_PRIVACY_CAPABILITIES,
        rules=(
            _domain_capability_rule(
                pack_id="data_privacy_v1",
                capabilities=DATA_PRIVACY_CAPABILITIES,
            ),
            classification_required,
            broad_or_sensitive_export,
            external_destination_control,
            residency_control,
            _requirements_satisfied_rule(
                pack_id="data_privacy",
                summary="Data privacy requirements are satisfied for this action.",
            ),
        ),
    )


def build_access_governance_policy_pack(
    *,
    privileged_roles: tuple[str, ...] = (
        "admin",
        "administrator",
        "owner",
        "root",
        "superuser",
    ),
) -> PolicyPack:
    """Build policy for representative role, credential, and sharing actions."""

    privileged = {role.strip().lower() for role in privileged_roles if role.strip()}

    def privileged_or_standing_access(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in ACCESS_GOVERNANCE_CAPABILITIES:
            return None
        role = _string_value(intent, evidence, "role") or _string_value(
            intent,
            evidence,
            "permission",
        )
        role_tier = _string_value(intent, evidence, "role_tier")
        access_mode = _string_value(intent, evidence, "access_mode", "jit")
        wildcard = "*" in role
        privileged_role = role in privileged or role_tier in {
            "admin",
            "privileged",
            "critical",
        }
        standing_access = access_mode == "standing"
        required_approvals = ("security_admin", "resource_owner")
        if (
            privileged_role or wildcard or standing_access
        ) and not _approval_satisfied(intent, evidence, required_approvals):
            return _result(
                outcome="approval_required",
                reason_code="PREFLIGHT_PRIVILEGED_ACCESS_APPROVAL_REQUIRED",
                summary="Privileged, wildcard, or standing access requires security and resource-owner approval.",
                risk_level="high",
                matched_rule="access_governance.privileged_access_approval_required",
                required_approvals=required_approvals,
                evidence_keys=_approval_evidence_keys(required_approvals),
                metadata={
                    "role": role,
                    "role_tier": role_tier,
                    "access_mode": access_mode,
                },
            )
        return None

    def separation_of_duties(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in ACCESS_GOVERNANCE_CAPABILITIES:
            return None
        if not _approval_present(intent, evidence):
            return None
        approver_ids = set(_string_values(intent, evidence, "approver_ids"))
        requester_is_approver = _truthy(
            _value(intent, evidence, "requester_is_approver")
        )
        if intent.requester.id.lower() not in approver_ids and not requester_is_approver:
            return None
        return _result(
            outcome="deny",
            reason_code="PREFLIGHT_SEPARATION_OF_DUTIES_VIOLATION",
            summary="The requesting subject cannot satisfy its own privileged-access approval.",
            risk_level="critical",
            matched_rule="access_governance.separation_of_duties",
            evidence_keys=(
                _evidence_key(
                    "approver_ids",
                    "array[string]",
                    ["security-reviewer-42", "resource-owner-17"],
                    "Verified approver identities for separation-of-duties evaluation.",
                ),
            ),
        )

    return PolicyPack(
        pack_id="access_governance_v1",
        display_name="IAM and access governance",
        capabilities=ACCESS_GOVERNANCE_CAPABILITIES,
        rules=(
            _domain_capability_rule(
                pack_id="access_governance_v1",
                capabilities=ACCESS_GOVERNANCE_CAPABILITIES,
            ),
            separation_of_duties,
            privileged_or_standing_access,
            _requirements_satisfied_rule(
                pack_id="access_governance",
                summary="Access-governance requirements are satisfied for this action.",
            ),
        ),
    )


def build_payments_policy_pack(
    *,
    approval_threshold_minor: int = 100_000,
) -> PolicyPack:
    """Build policy for representative payment, refund, and payout actions."""

    if approval_threshold_minor < 1:
        raise ValueError("approval_threshold_minor must be positive")

    def payment_approval(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in PAYMENTS_CAPABILITIES:
            return None
        raw_amount = _value(
            intent,
            evidence,
            "amount_minor",
            _value(intent, evidence, "notional_minor", 0),
        )
        try:
            amount_minor = int(raw_amount)
        except (TypeError, ValueError):
            amount_minor = 0
        new_payee = _truthy(_value(intent, evidence, "new_payee"))
        destination_changed = intent.action.capability == "bank_details.update" or _truthy(
            _value(intent, evidence, "destination_changed")
        )
        required_approvals = ("finance_approver",)
        if (
            amount_minor >= approval_threshold_minor
            or new_payee
            or destination_changed
        ) and not _approval_satisfied(intent, evidence, required_approvals):
            return _result(
                outcome="approval_required",
                reason_code="PREFLIGHT_PAYMENT_APPROVAL_REQUIRED",
                summary="High-notional payment or changed payee destination requires finance approval.",
                risk_level="high",
                matched_rule="payments.payment_approval_required",
                required_approvals=required_approvals,
                evidence_keys=_approval_evidence_keys(required_approvals),
                metadata={
                    "amount_minor": amount_minor,
                    "approval_threshold_minor": approval_threshold_minor,
                    "new_payee": new_payee,
                    "destination_changed": destination_changed,
                },
            )
        return None

    def payee_verification(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in PAYMENTS_CAPABILITIES:
            return None
        new_payee = _truthy(_value(intent, evidence, "new_payee"))
        destination_changed = intent.action.capability == "bank_details.update" or _truthy(
            _value(intent, evidence, "destination_changed")
        )
        if not (new_payee or destination_changed):
            return None
        if _truthy(_value(intent, evidence, "payee_verified")) and _truthy(
            _value(intent, evidence, "destination_verified")
        ):
            return None
        return _result(
            outcome="needs_evidence",
            reason_code="PREFLIGHT_PAYEE_DESTINATION_VERIFICATION_REQUIRED",
            summary="New or changed payment destinations require verified payee and destination evidence.",
            risk_level="high",
            matched_rule="payments.payee_destination_verification_required",
            required_evidence=("payee_verified", "destination_verified"),
            evidence_keys=(
                _evidence_key(
                    "payee_verified",
                    "boolean",
                    True,
                    "True after the payee identity has been verified for this action.",
                ),
                _evidence_key(
                    "destination_verified",
                    "boolean",
                    True,
                    "True after the exact bank, wallet, or payout destination has been verified.",
                ),
            ),
        )

    return PolicyPack(
        pack_id="payments_v1",
        display_name="Payments and destination controls",
        capabilities=PAYMENTS_CAPABILITIES,
        rules=(
            _domain_capability_rule(
                pack_id="payments_v1",
                capabilities=PAYMENTS_CAPABILITIES,
            ),
            payment_approval,
            payee_verification,
            _requirements_satisfied_rule(
                pack_id="payments",
                summary="Payment policy requirements are satisfied for this action.",
            ),
        ),
    )


def build_clinical_policy_pack_template() -> PolicyPack:
    """Build an illustrative clinical workflow template, not certified guidance."""

    def high_risk_clinical_action(
        intent: ActionIntent,
        evidence: EvidenceContext,
    ) -> dict[str, Any] | None:
        if intent.action.capability not in CLINICAL_TEMPLATE_CAPABILITIES:
            return None
        risk = _string_value(intent, evidence, "clinical_risk")
        high_risk = intent.action.capability in {
            "medication.order",
            "treatment_plan.change",
            "clinical.note.publish",
        } or risk in {"high", "critical"}
        required_approvals = ("licensed_clinician",)
        if high_risk and not _approval_satisfied(
            intent,
            evidence,
            required_approvals,
        ):
            return _result(
                outcome="approval_required",
                reason_code="PREFLIGHT_CLINICAL_REVIEW_REQUIRED",
                summary="This template requires licensed-clinician review for the selected clinical action.",
                risk_level="high",
                matched_rule="clinical_template.clinical_review_required",
                required_approvals=required_approvals,
                evidence_keys=_approval_evidence_keys(required_approvals),
                metadata={"clinical_risk": risk},
            )
        return None

    disclaimer = (
        "Illustrative template only. It is not certified clinical guidance, "
        "medical advice, or a substitute for local clinical governance."
    )
    return PolicyPack(
        pack_id="clinical_template_v1",
        display_name="Clinical workflow TEMPLATE (not certified guidance)",
        capabilities=CLINICAL_TEMPLATE_CAPABILITIES,
        rules=(
            _domain_capability_rule(
                pack_id="clinical_template_v1",
                capabilities=CLINICAL_TEMPLATE_CAPABILITIES,
            ),
            high_risk_clinical_action,
            _requirements_satisfied_rule(
                pack_id="clinical_template",
                summary="The illustrative clinical-template requirements are satisfied.",
            ),
        ),
        is_template=True,
        disclaimer=disclaimer,
    )


def build_clinical_policy_pack() -> PolicyPack:
    """Compatibility-friendly name for the explicitly marked clinical template."""

    return build_clinical_policy_pack_template()


DEFAULT_PREFLIGHT_POLICY_PACK = build_destructive_actions_policy_pack()
