from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class PreflightEvidence:
    """Typed builder for the default local Preflight evidence context."""

    environment: str | None = None
    change_ticket: str | None = None
    backup_verified: bool | None = None
    backup_snapshot: str | None = None
    approval_present: bool | None = None
    approver_types: tuple[str, ...] = ()
    approval_artifacts: tuple[Mapping[str, Any], ...] = ()
    approval_trusted_keys: tuple[Mapping[str, Any], ...] = ()
    capability_classification: str | None = None
    row_count: int | None = None
    destination: str | None = None
    sensitive_data: bool | None = None
    role: str | None = None
    sensitivity_classification: str | None = None
    destination_classification: str | None = None
    destination_allowlisted: bool | None = None
    external_egress_approved: bool | None = None
    source_residency: str | None = None
    destination_residency: str | None = None
    residency_allowed: bool | None = None
    role_tier: str | None = None
    access_mode: str | None = None
    approver_ids: tuple[str, ...] = ()
    requester_is_approver: bool | None = None
    amount_minor: int | None = None
    notional_minor: int | None = None
    new_payee: bool | None = None
    destination_changed: bool | None = None
    payee_verified: bool | None = None
    destination_verified: bool | None = None
    clinical_risk: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key in (
            "environment",
            "change_ticket",
            "backup_verified",
            "backup_snapshot",
            "approval_present",
            "capability_classification",
            "row_count",
            "destination",
            "sensitive_data",
            "role",
            "sensitivity_classification",
            "destination_classification",
            "destination_allowlisted",
            "external_egress_approved",
            "source_residency",
            "destination_residency",
            "residency_allowed",
            "role_tier",
            "access_mode",
            "requester_is_approver",
            "amount_minor",
            "notional_minor",
            "new_payee",
            "destination_changed",
            "payee_verified",
            "destination_verified",
            "clinical_risk",
        ):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.approver_types:
            payload["approver_types"] = list(self.approver_types)
        if self.approval_artifacts:
            payload["approval_artifacts"] = [
                dict(item) for item in self.approval_artifacts
            ]
        if self.approval_trusted_keys:
            payload["approval_trusted_keys"] = [
                dict(item) for item in self.approval_trusted_keys
            ]
        if self.approver_ids:
            payload["approver_ids"] = list(self.approver_ids)
        return payload

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PreflightEvidence":
        approver_types = raw.get("approver_types", ())
        if isinstance(approver_types, str):
            approver_types = (approver_types,)
        approver_ids = raw.get("approver_ids", ())
        if isinstance(approver_ids, str):
            approver_ids = (approver_ids,)
        return cls(
            environment=raw.get("environment"),
            change_ticket=raw.get("change_ticket"),
            backup_verified=raw.get("backup_verified"),
            backup_snapshot=raw.get("backup_snapshot"),
            approval_present=raw.get("approval_present"),
            approver_types=tuple(str(item) for item in approver_types),
            approval_artifacts=tuple(
                dict(item) for item in raw.get("approval_artifacts", ())
            ),
            approval_trusted_keys=tuple(
                dict(item) for item in raw.get("approval_trusted_keys", ())
            ),
            capability_classification=raw.get("capability_classification"),
            row_count=raw.get("row_count"),
            destination=raw.get("destination"),
            sensitive_data=raw.get("sensitive_data"),
            role=raw.get("role"),
            sensitivity_classification=raw.get("sensitivity_classification"),
            destination_classification=raw.get("destination_classification"),
            destination_allowlisted=raw.get("destination_allowlisted"),
            external_egress_approved=raw.get("external_egress_approved"),
            source_residency=raw.get("source_residency"),
            destination_residency=raw.get("destination_residency"),
            residency_allowed=raw.get("residency_allowed"),
            role_tier=raw.get("role_tier"),
            access_mode=raw.get("access_mode"),
            approver_ids=tuple(str(item) for item in approver_ids),
            requester_is_approver=raw.get("requester_is_approver"),
            amount_minor=raw.get("amount_minor"),
            notional_minor=raw.get("notional_minor"),
            new_payee=raw.get("new_payee"),
            destination_changed=raw.get("destination_changed"),
            payee_verified=raw.get("payee_verified"),
            destination_verified=raw.get("destination_verified"),
            clinical_risk=raw.get("clinical_risk"),
        )
