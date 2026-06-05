"""Provider adapter interfaces for protected consequential actions."""

from .base import (
    ProviderAdapter,
    ProviderAdapterContext,
    ProviderAdapterRequest,
    ProviderAdapterResult,
    ReconciliationCapableProviderAdapter,
)

__all__ = [
    "ProviderAdapter",
    "ProviderAdapterContext",
    "ProviderAdapterRequest",
    "ProviderAdapterResult",
    "ReconciliationCapableProviderAdapter",
]
