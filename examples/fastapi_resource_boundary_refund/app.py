
"""FastAPI resource-boundary refund example.

This example deliberately transports the exact ActionIntent with the PCCB proof.
That is the important point: the protected endpoint verifies the proof against
the exact action that was approved, not a newly rebuilt lookalike action.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from actenon import ActenonGate
from actenon.models import PCCB


AUDIENCE = "service:refunds"

gate = ActenonGate.local_dev(audience=AUDIENCE)

app = FastAPI(title="Actenon FastAPI resource-boundary refund demo")

ledger = []
balances = {"ord-123": 100000, "ord-456": 100000}


class RefundRequest(BaseModel):
    amount_cents: int


def reset_ledger() -> None:
    ledger.clear()
    balances.clear()
    balances.update({"ord-123": 100000, "ord-456": 100000})


def build_refund_action(order_id: str, amount_cents: int) -> Dict[str, Any]:
    return gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id="demo",
        requester_id="refund-agent",
    )


def proof_to_header(action: Dict[str, Any], proof: PCCB) -> str:
    """Serialize the exact action + proof as one HTTP-header-safe envelope."""
    envelope = {
        "action_intent": action,
        "pccb": proof.to_dict(),
    }
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def proof_from_header(value: Optional[str]) -> Tuple[Dict[str, Any], PCCB]:
    if not value:
        raise ValueError("missing proof header")

    padded = value + ("=" * (-len(value) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    envelope = json.loads(raw)

    action = envelope["action_intent"]
    proof = PCCB.from_dict(envelope["pccb"])
    return action, proof


def mint_refund_proof(order_id: str, amount_cents: int):
    action = build_refund_action(order_id, amount_cents)
    proof = gate.mint_proof(action)
    proof_header = proof_to_header(action, proof)
    return action, proof, proof_header


def _request_matches_approved_action(
    action: Dict[str, Any],
    *,
    order_id: str,
    amount_cents: int,
) -> bool:
    params = action.get("action", {}).get("parameters", {})
    target = action.get("target", {})

    return (
        params.get("order_id") == order_id
        and params.get("amount_cents") == amount_cents
        and target.get("resource_id") == order_id
    )


@app.post("/refunds/{order_id}")
def refund_order(
    order_id: str,
    request: RefundRequest,
    x_actenon_proof: Optional[str] = Header(default=None),
):
    try:
        action, proof = proof_from_header(x_actenon_proof)
    except Exception as exc:
        raise HTTPException(
            status_code=403,
            detail={"reason_code": "PCCB_REQUIRED", "message": str(exc)},
        )

    if not _request_matches_approved_action(
        action,
        order_id=order_id,
        amount_cents=request.amount_cents,
    ):
        raise HTTPException(
            status_code=403,
            detail={"reason_code": "REQUEST_ACTION_MISMATCH"},
        )

    def execute_refund():
        balances[order_id] -= request.amount_cents
        event = {"order_id": order_id, "amount_cents": request.amount_cents}
        ledger.append(event)
        return event

    outcome = gate.protect(
        action,
        proof,
        execute_refund,
        audience=AUDIENCE,
    )

    if not outcome.ok:
        raise HTTPException(
            status_code=403,
            detail={"reason_code": outcome.reason_code},
        )

    return {
        "ok": True,
        "ledger": ledger,
        "balance_cents": balances[order_id],
    }


client = TestClient(app)
