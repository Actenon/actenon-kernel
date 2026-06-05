from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from actenon.models.contracts import Violation


@dataclass
class RefusalException(Exception):
    category: str
    refusal_code: str
    message: str
    retryable: bool = False
    rule_refs: tuple[str, ...] = ()
    violations: tuple[Violation, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.refusal_code}: {self.message}"


class ContractValidationError(RefusalException):
    def __init__(self, message: str, *, violations: tuple[Violation, ...] = (), details: dict[str, Any] | None = None) -> None:
        super().__init__(
            category="schema",
            refusal_code="SCHEMA_INVALID",
            message=message,
            retryable=False,
            violations=violations,
            details=details or {},
        )


class PolicyDecisionError(RefusalException):
    def __init__(
        self,
        refusal_code: str,
        message: str,
        *,
        rule_refs: tuple[str, ...] = (),
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            category="policy",
            refusal_code=refusal_code,
            message=message,
            retryable=False,
            rule_refs=rule_refs,
            details=details or {},
        )


class ProofVerificationError(RefusalException):
    def __init__(self, refusal_code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            category="proof",
            refusal_code=refusal_code,
            message=message,
            retryable=False,
            details=details or {},
        )


class EscrowValidationError(RefusalException):
    def __init__(self, refusal_code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            category="escrow",
            refusal_code=refusal_code,
            message=message,
            retryable=False,
            details=details or {},
        )


class ReplayValidationError(RefusalException):
    def __init__(self, refusal_code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            category="replay",
            refusal_code=refusal_code,
            message=message,
            retryable=False,
            details=details or {},
        )
