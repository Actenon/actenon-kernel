from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from actenon import ActenonGate


app = FastAPI(title="Actenon Protected Refund Resource Boundary")

gate = ActenonGate.local_dev(audience="service:refunds")

ledger: list[dict[str, Any]] = []


class RefundRequest(BaseModel):
    amount_cents: int
    requester_id: str = "support-agent"
    tenant_id: str = "demo"


def reset_ledger() -> None:
    ledger.clear()


def issue_refund(order_id: str, amount_cents: int) -> dict[str, Any]:
    event = {"order_id": order_id, "amount_cents": amount_cents}
    ledger.append(event)
    return {"status": "refunded", **event}


def build_refund_action(
    *,
    order_id: str,
    amount_cents: int,
    requester_id: str = "support-agent",
    tenant_id: str = "demo",
) -> dict[str, Any]:
    return gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id=tenant_id,
        requester_id=requester_id,
    )


@app.post("/refunds/{order_id}")
def refund_order(
    order_id: str,
    body: RefundRequest,
    x_actenon_proof: Optional[str] = Header(default=None),
) -> Any:
    action = build_refund_action(
        order_id=order_id,
        amount_cents=body.amount_cents,
        requester_id=body.requester_id,
        tenant_id=body.tenant_id,
    )

    outcome = gate.protect(
        action,
        x_actenon_proof,
        lambda: issue_refund(order_id=order_id, amount_cents=body.amount_cents),
        audience="service:refunds",
    )

    status = getattr(outcome, "status", None)

    if status == "EXECUTED":
        return {
            "status": "EXECUTED",
            "result": getattr(outcome, "result", outcome),
        }

    reason = getattr(outcome, "reason", "REFUSED")
    raise HTTPException(
        status_code=403,
        detail={
            "status": "REFUSED",
            "reason": reason,
        },
    )


@app.get("/ledger")
def get_ledger() -> dict[str, Any]:
    return {"events": ledger}
