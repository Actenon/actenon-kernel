"""Protected endpoint helpers for proof-present and local-admission adoption."""

from .countersignature import (
    CounterSignatureVerificationError,
    VerifiedCounterSignature,
    verify_countersignature,
)
from .endpoint import LocalAdmissionOutcome, LocalAdmissionProtectedEndpoint, PythonProtectedEndpoint
from .middleware import ProtectedEndpointMiddleware
from .sdk import VerifiedPortableRequest, VerifierSDK

__all__ = [
    "LocalAdmissionOutcome",
    "LocalAdmissionProtectedEndpoint",
    "ProtectedEndpointMiddleware",
    "PythonProtectedEndpoint",
    "CounterSignatureVerificationError",
    "VerifiedCounterSignature",
    "VerifiedPortableRequest",
    "VerifierSDK",
    "verify_countersignature",
]
