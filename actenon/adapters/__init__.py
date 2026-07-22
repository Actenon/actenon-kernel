"""Provider adapter interfaces for protected consequential actions."""

from .base import (
    ProviderAdapter,
    ProviderAdapterContext,
    ProviderAdapterRequest,
    ProviderAdapterResult,
    ReconciliationCapableProviderAdapter,
)
from .edge import EdgeConfigurationError, ProtectedEdge

__all__ = [
    "EdgeConfigurationError",
    "ProtectedEdge",
    "ProviderAdapter",
    "ProviderAdapterContext",
    "ProviderAdapterRequest",
    "ProviderAdapterResult",
    "ReconciliationCapableProviderAdapter",
]
