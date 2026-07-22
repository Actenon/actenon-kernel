from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class EscrowRecord:
    escrow_id: str
    pccb_id: str
    capability: str
    expires_at: datetime
    state: str = "issued"
    consumed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class CapabilityEscrow(Protocol):
    def issue(self, *, escrow_id: str, pccb_id: str, capability: str, expires_at: datetime, metadata: dict[str, Any] | None = None) -> EscrowRecord:
        ...

    def inspect(self, escrow_id: str) -> EscrowRecord | None:
        ...

    def consume(self, *, escrow_id: str, pccb_id: str, capability: str, now: datetime) -> EscrowRecord:
        ...

    def revoke(self, escrow_id: str, *, reason: str) -> EscrowRecord:
        ...

