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
from .trust_artifacts import (
    TrustArtifactVerificationError,
    VerifiedApprovalArtifact,
    VerifiedIssuerStatus,
    verify_approval_artifact,
    verify_issuer_status,
)

__all__ = [
    "LocalAdmissionOutcome",
    "LocalAdmissionProtectedEndpoint",
    "ProtectedEndpointMiddleware",
    "PythonProtectedEndpoint",
    "CounterSignatureVerificationError",
    "TransparencyVerificationError",
    "TrustArtifactVerificationError",
    "VerifiedApprovalArtifact",
    "VerifiedCounterSignature",
    "VerifiedCheckpoint",
    "VerifiedConsistency",
    "VerifiedInclusion",
    "VerifiedMonitorUpdate",
    "VerifiedIssuerStatus",
    "VerifiedPortableRequest",
    "VerifierSDK",
    "verify_countersignature",
    "verify_checkpoint_signature",
    "verify_consistency",
    "verify_countersignature_inclusion",
    "verify_inclusion",
    "verify_monitor_update",
    "verify_approval_artifact",
    "verify_issuer_status",
]
