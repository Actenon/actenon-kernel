"""Core orchestration services for the kernel."""

from .errors import (
    ContractValidationError,
    EscrowValidationError,
    PolicyDecisionError,
    ProofVerificationError,
    ReplayValidationError,
    RefusalException,
)
from .json import (
    DEFAULT_MAX_JSON_BYTES,
    DEFAULT_MAX_JSON_DEPTH,
    DuplicateJSONKeyError,
    JSONInputTooLargeError,
    JSONNestingDepthError,
    loads_no_duplicate_keys,
    reject_duplicate_object_pairs,
    validate_json_depth,
)

__all__ = [
    "ContractValidationError",
    "DEFAULT_MAX_JSON_BYTES",
    "DEFAULT_MAX_JSON_DEPTH",
    "DuplicateJSONKeyError",
    "EscrowValidationError",
    "JSONInputTooLargeError",
    "JSONNestingDepthError",
    "PolicyDecisionError",
    "ProofVerificationError",
    "ProtectedExecutionKernel",
    "ReplayValidationError",
    "RefusalException",
    "loads_no_duplicate_keys",
    "reject_duplicate_object_pairs",
    "validate_json_depth",
]


def __getattr__(name: str):
    if name == "ProtectedExecutionKernel":
        from .kernel import ProtectedExecutionKernel

        return ProtectedExecutionKernel
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
