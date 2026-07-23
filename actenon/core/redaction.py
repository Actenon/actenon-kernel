from __future__ import annotations

from typing import Any


SAFE_HANDLER_EXCEPTION_CODE = "EXECUTION_FAILED"
SAFE_HANDLER_EXCEPTION_MESSAGE = (
    "Execution failed after verification; sensitive exception details were redacted from the artifact."
)


def redacted_handler_exception_details(exc: Exception, *, request_id: str | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {
        "exception_type": type(exc).__name__,
        "phase": "execution",
        "safe_error_code": SAFE_HANDLER_EXCEPTION_CODE,
        "sensitive_details_redacted": True,
    }
    if request_id is not None:
        details["request_id"] = request_id
    return details
