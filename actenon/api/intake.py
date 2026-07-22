from __future__ import annotations

from typing import Any, Mapping

from actenon.core.errors import ContractValidationError
from actenon.models.contracts import ActionIntent, Violation


class ActionIntentIntakeService:
    """Parses and validates external Action Intent payloads."""

    def parse(self, payload: Mapping[str, Any]) -> ActionIntent:
        try:
            intent = ActionIntent.from_dict(payload)
        except ValueError as exc:
            violation = Violation(code="INVALID_CONTRACT", message=str(exc))
            raise ContractValidationError("Action Intent contract validation failed", violations=(violation,)) from exc

        violations: list[Violation] = []
        if intent.expires_at <= intent.issued_at:
            violations.append(
                Violation(
                    code="INVALID_WINDOW",
                    field_path="expires_at",
                    message="expires_at must be later than issued_at",
                )
            )
        if not intent.action.parameters:
            violations.append(
                Violation(
                    code="MISSING_ACTION_PARAMETERS",
                    field_path="action.parameters",
                    message="action.parameters must contain at least one value",
                )
            )
        if violations:
            raise ContractValidationError("Action Intent semantic validation failed", violations=tuple(violations))
        return intent

