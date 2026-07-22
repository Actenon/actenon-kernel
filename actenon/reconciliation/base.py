"""Reserved-surface reconciliation interfaces.

These types support ecosystem adapters, local examples, and future standards
work. Their presence does not by itself activate Reconciliation as an active
public compatibility target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol


KernelReconciliationStatus = Literal[
    "recorded-local",
    "provider-pending",
    "provider-confirmed",
    "provider-failed",
    "reversed",
    "unknown",
]


@dataclass(frozen=True)
class ProviderReconciliationSnapshot:
    """Provider-facing reconciliation observation.

    A snapshot captures what an adapter or reconciliation worker learned from an
    external provider or system of record at a point in time. The open kernel
    intentionally treats this as input to a mapping layer rather than as final
    truth on its own.
    """

    provider_name: str
    provider_reference: str
    provider_state: str
    observed_at: datetime
    amount_minor: int | None = None
    currency: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderStateMapping:
    """Mapping from a provider-specific state into a kernel reconciliation state."""

    provider_state: str
    kernel_status: KernelReconciliationStatus
    terminal: bool
    description: str


@dataclass(frozen=True)
class KernelReconciliationRecord:
    """Portable reconciliation record after provider-state normalization."""

    reconciliation_id: str
    provider_name: str
    provider_reference: str
    provider_state: str
    kernel_status: KernelReconciliationStatus
    observed_at: datetime
    terminal: bool
    metadata: dict[str, Any] = field(default_factory=dict)


class ReconciliationMapper(Protocol):
    """Protocol for mapping provider states into kernel reconciliation states."""

    def mapping_for(self, provider_state: str) -> ProviderStateMapping:
        """Return the mapping rule for a provider-specific state string."""

    def reconcile(self, snapshot: ProviderReconciliationSnapshot, *, reconciliation_id: str) -> KernelReconciliationRecord:
        """Convert a provider snapshot into a portable kernel reconciliation record."""


@dataclass(frozen=True)
class StaticReconciliationMapper:
    """Generic mapping implementation suitable for tests and lightweight adapters.

    The mapper accepts provider-specific state labels and normalizes them into
    the public kernel reconciliation vocabulary without embedding any
    provider-product logic in this repository.
    """

    mappings: dict[str, ProviderStateMapping]
    default_status: KernelReconciliationStatus = "unknown"
    default_terminal: bool = False
    default_description: str = "Provider state is not mapped by this adapter."

    def mapping_for(self, provider_state: str) -> ProviderStateMapping:
        return self.mappings.get(
            provider_state,
            ProviderStateMapping(
                provider_state=provider_state,
                kernel_status=self.default_status,
                terminal=self.default_terminal,
                description=self.default_description,
            ),
        )

    def reconcile(self, snapshot: ProviderReconciliationSnapshot, *, reconciliation_id: str) -> KernelReconciliationRecord:
        mapping = self.mapping_for(snapshot.provider_state)
        return KernelReconciliationRecord(
            reconciliation_id=reconciliation_id,
            provider_name=snapshot.provider_name,
            provider_reference=snapshot.provider_reference,
            provider_state=snapshot.provider_state,
            kernel_status=mapping.kernel_status,
            observed_at=snapshot.observed_at,
            terminal=mapping.terminal,
            metadata={**snapshot.metadata, "mapping_description": mapping.description},
        )
