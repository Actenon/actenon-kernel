from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol


ActionConsumptionStatus = Literal["claimed", "consumed", "released", "expired"]


@dataclass(frozen=True)
class ActionConsumptionClaim:
    replay_key: str
    intent_id: str | None
    pccb_id: str
    nonce: str
    action_hash: str
    audience: str
    capability: str
    tenant_id: str | None
    subject_id: str | None
    expires_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionConsumptionState:
    replay_key: str
    intent_id: str | None
    pccb_id: str
    nonce: str
    action_hash: str
    audience: str
    capability: str
    tenant_id: str | None
    subject_id: str | None
    status: ActionConsumptionStatus
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def terminal(self) -> bool:
        return self.status in {"consumed", "released", "expired"}


class ReplayStore(Protocol):
    def claim_once(self, claim: ActionConsumptionClaim, *, now: datetime) -> ActionConsumptionState:
        ...

    def mark_consumed(self, replay_key: str, *, now: datetime) -> ActionConsumptionState:
        ...

    def release_claim(self, replay_key: str, *, now: datetime, reason: str) -> ActionConsumptionState:
        ...

    def inspect(self, replay_key: str, *, now: datetime | None = None) -> ActionConsumptionState | None:
        ...

    def purge_expired(self, *, now: datetime) -> int:
        ...

