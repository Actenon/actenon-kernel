from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from actenon.core import RefusalException
from actenon.verifier.sdk import VerifiedPortableRequest


@dataclass(frozen=True)
class HelloWorldProtectedResource:
    resource_id: str = "hello_resource_demo_001"

    def handle(self, request: VerifiedPortableRequest) -> dict[str, Any]:
        if request.intent.target.resource_type != "hello_resource":
            raise RefusalException(
                category="execution",
                refusal_code="HELLO_RESOURCE_TYPE_INVALID",
                message="The protected hello-world example requires a hello_resource target.",
            )
        if request.intent.target.resource_id != self.resource_id:
            raise RefusalException(
                category="execution",
                refusal_code="HELLO_RESOURCE_ID_MISMATCH",
                message="The protected hello-world example requires the expected resource id.",
            )
        message = request.intent.action.parameters.get("message")
        if not isinstance(message, str) or not message:
            raise RefusalException(
                category="execution",
                refusal_code="HELLO_MESSAGE_INVALID",
                message="The protected hello-world example requires a non-empty message parameter.",
            )
        expected_message = request.intent.action.constraints.get("exact_message")
        if expected_message is not None and expected_message != message:
            raise RefusalException(
                category="execution",
                refusal_code="HELLO_MESSAGE_MISMATCH",
                message="The protected hello-world example requires exact message binding.",
            )
        return {
            "resource_id": self.resource_id,
            "message": message,
            "request_id": request.context.request_id,
            "intent_id": request.intent.intent_id,
            "pccb_id": request.pccb.pccb_id,
            "action_hash": request.pccb.action_hash.value,
            "operator_summary": f"Hello world protected resource returned the bound message '{message}'.",
        }
