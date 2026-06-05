from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from actenon.models.contracts import ActionSpec, PCCB, TargetRef
from actenon.models.runtime import ProtectedExecutionRequest

if TYPE_CHECKING:  # pragma: no cover
    from actenon.reconciliation.base import ProviderReconciliationSnapshot


@dataclass(frozen=True)
class ProviderAdapterContext:
    """Execution context passed from the kernel to a provider adapter.

    The context contains only execution-relevant identifiers and timing metadata.
    It intentionally avoids embedding host-specific control-plane state so that
    adapter implementations remain portable across integration environments.
    """

    request_id: str
    intent_id: str
    pccb_id: str
    tenant_id: str
    subject_id: str
    audience: str
    executed_at: datetime


@dataclass(frozen=True)
class ProviderAdapterRequest:
    """Portable provider-adapter request produced after proof verification.

    Adapters receive a normalized request derived from the protected execution
    path. The request carries only the action, target, and execution context the
    adapter needs to perform a side effect or translate the call into a
    provider-specific operation.
    """

    action: ActionSpec
    target: TargetRef
    context: ProviderAdapterContext
    pccb: PCCB
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_execution_request(cls, request: ProtectedExecutionRequest, *, metadata: dict[str, Any] | None = None) -> "ProviderAdapterRequest":
        """Build a portable adapter request from a verified execution request."""

        return cls(
            action=request.intent.action,
            target=request.intent.target,
            context=ProviderAdapterContext(
                request_id=request.context.request_id,
                intent_id=request.intent.intent_id,
                pccb_id=request.pccb.pccb_id,
                tenant_id=request.intent.tenant.tenant_id,
                subject_id=request.intent.requester.id,
                audience=f"{request.context.audience.type}:{request.context.audience.id}",
                executed_at=request.context.now,
            ),
            pccb=request.pccb,
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True)
class ProviderAdapterResult:
    """Normalized side-effect result returned by a provider adapter.

    The adapter result is intentionally generic. It lets the kernel or a future
    reconciliation layer capture stable references without committing this
    repository to a particular provider or control-plane product model.
    """

    provider_reference: str | None
    provider_state: str
    side_effect_reference: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ProviderAdapter(Protocol):
    """Protocol for execution adapters that call consequential downstream systems.

    Concrete provider integrations belong outside the open kernel. This
    interface gives the paid or external ecosystem a stable execution boundary
    without embedding those integrations here.
    """

    adapter_id: str
    provider_name: str
    supported_capabilities: tuple[str, ...]

    def execute(self, request: ProviderAdapterRequest) -> ProviderAdapterResult:
        """Execute a verified protected action against a downstream provider."""


class ReconciliationCapableProviderAdapter(ProviderAdapter, Protocol):
    """Optional provider-adapter extension for reconciliation-aware integrations."""

    def fetch_reconciliation_snapshot(self, provider_reference: str) -> "ProviderReconciliationSnapshot":
        """Return the latest provider view for a previously executed side effect."""
