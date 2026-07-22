from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from actenon.models.runtime import ProtectedExecutionRequest


@dataclass
class LocalProtectedRefundEndpoint:
    state_path: Path

    def __post_init__(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            self._write_state(
                {
                    "resource_version": 0,
                    "payments": {
                        "payment_demo_001": {
                            "payment_id": "payment_demo_001",
                            "currency": "USD",
                            "captured_amount_minor": 5000,
                            "remaining_refundable_minor": 5000,
                            "refunds": [],
                        }
                    },
                }
            )

    def handle(self, request: ProtectedExecutionRequest) -> dict[str, Any]:
        state = self._read_state()
        payment_id = request.intent.target.resource_id
        payment = state["payments"].get(payment_id)
        if payment is None:
            raise ValueError(f"Unknown payment resource: {payment_id}")

        amount_minor = int(request.intent.action.parameters["amount_minor"])
        currency = request.intent.action.parameters["currency"]
        constraints = request.intent.action.constraints
        if constraints.get("exact_amount_minor") != amount_minor:
            raise ValueError("Exact amount binding mismatch for protected refund execution.")
        if constraints.get("exact_currency") != currency:
            raise ValueError("Exact currency binding mismatch for protected refund execution.")
        if request.intent.target.resource_type != "payment":
            raise ValueError("Protected refund execution requires a payment target.")
        if payment["currency"] != currency:
            raise ValueError("Currency mismatch for protected refund execution.")
        if amount_minor > int(payment["remaining_refundable_minor"]):
            raise ValueError("Requested refund exceeds remaining refundable balance.")

        refund_id = f"refund_local_{len(payment['refunds']) + 1:04d}"
        payment["remaining_refundable_minor"] = int(payment["remaining_refundable_minor"]) - amount_minor
        payment["refunds"].append(
            {
                "refund_id": refund_id,
                "amount_minor": amount_minor,
                "currency": currency,
                "intent_id": request.intent.intent_id,
                "pccb_id": request.pccb.pccb_id,
                "request_id": request.context.request_id,
                "occurred_at": request.context.now.isoformat().replace("+00:00", "Z"),
            }
        )
        state["resource_version"] = int(state["resource_version"]) + 1
        self._write_state(state)
        return {
            "external_reference": refund_id,
            "resource_version": str(state["resource_version"]),
            "state_path": str(self.state_path),
            "payment_id": payment_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "remaining_refundable_minor": payment["remaining_refundable_minor"],
            "operator_summary": (
                f"Refund {refund_id} executed for {amount_minor} {currency} "
                f"against payment {payment_id}. Remaining refundable balance: {payment['remaining_refundable_minor']}."
            ),
        }

    def _read_state(self) -> dict[str, Any]:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _write_state(self, payload: dict[str, Any]) -> None:
        self.state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
