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
    capability_classification: str | None = None
    row_count: int | None = None
    destination: str | None = None
    sensitive_data: bool | None = None
    role: str | None = None

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
        ):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.approver_types:
            payload["approver_types"] = list(self.approver_types)
        return payload

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PreflightEvidence":
        approver_types = raw.get("approver_types", ())
        if isinstance(approver_types, str):
            approver_types = (approver_types,)
        return cls(
            environment=raw.get("environment"),
            change_ticket=raw.get("change_ticket"),
            backup_verified=raw.get("backup_verified"),
            backup_snapshot=raw.get("backup_snapshot"),
            approval_present=raw.get("approval_present"),
            approver_types=tuple(str(item) for item in approver_types),
            capability_classification=raw.get("capability_classification"),
            row_count=raw.get("row_count"),
            destination=raw.get("destination"),
            sensitive_data=raw.get("sensitive_data"),
            role=raw.get("role"),
        )
