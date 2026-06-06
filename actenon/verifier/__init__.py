"""Protected endpoint helpers for proof-present and local-admission adoption."""

from .countersignature import (
    CounterSignatureVerificationError,
    VerifiedCounterSignature,
    verify_countersignature,
)
from .endpoint import LocalAdmissionOutcome, LocalAdmissionProtectedEndpoint, PythonProtectedEndpoint
from .middleware import ProtectedEndpointMiddleware
from .sdk import VerifiedPortableRequest, VerifierSDK
from .transparency import (
    TransparencyVerificationError,
    VerifiedCheckpoint,
    VerifiedConsistency,
    VerifiedInclusion,
    VerifiedMonitorUpdate,
    verify_checkpoint_signature,
    verify_consistency,
    verify_countersignature_inclusion,
    verify_inclusion,
    verify_monitor_update,
)

__all__ = [
    "LocalAdmissionOutcome",
    "LocalAdmissionProtectedEndpoint",
    "ProtectedEndpointMiddleware",
    "PythonProtectedEndpoint",
    "CounterSignatureVerificationError",
    "TransparencyVerificationError",
    "VerifiedCounterSignature",
    "VerifiedCheckpoint",
    "VerifiedConsistency",
    "VerifiedInclusion",
    "VerifiedMonitorUpdate",
    "VerifiedPortableRequest",
    "VerifierSDK",
    "verify_countersignature",
    "verify_checkpoint_signature",
    "verify_consistency",
    "verify_countersignature_inclusion",
    "verify_inclusion",
    "verify_monitor_update",
]
