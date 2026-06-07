from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from actenon.gate import ActenonGate
from actenon.models.contracts import PCCB


AUDIENCE = "service:refunds"

# This boundary verifies only. In production this would be configured with
# public verification material / well-known keys, not issuer signing custody.
verifier_gate = ActenonGate.local_dev(audience=AUDIENCE)

app = FastAPI(title="Actenon verifier-only FastAPI refund boundary")
client = TestClient(app)

ledger = []
balances = {"ord-123": 100000, "ord-456": 100000}


class RefundRequest(BaseModel):
    amount_cents: int


def reset_ledger() -> None:
    ledger.clear()
    balances.clear()
    balances.update({"ord-123": 100000, "ord-456": 100000})


def build_refund_action(order_id: str, amount_cents: int):
    return verifier_gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id="demo",
        requester_id="fastapi-agent",
    )


def _iso(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def action_for_request_bound_to_proof(order_id: str, amount_cents: int, proof: PCCB):
    action = build_refund_action(order_id, amount_cents)
    action["intent_id"] = proof.intent_id
    action["issued_at"] = _iso(proof.issued_at)
    action["expires_at"] = _iso(proof.expires_at)
    return action


def proof_from_header(value: Optional[str]) -> Optional[PCCB]:
    if value is None:
        return None
    try:
        return PCCB.from_wire(value)
    except Exception as exc:
        raise HTTPException(status_code=403, detail={"reason": "PCCB_MALFORMED"}) from exc


@app.post("/refunds/{order_id}")
def refund_order(
    order_id: str,
    request: RefundRequest,
    x_actenon_proof: Optional[str] = Header(default=None),
):
    proof = proof_from_header(x_actenon_proof)
    if proof is None:
        raise HTTPException(status_code=403, detail={"reason": "PCCB_REQUIRED"})

    action = action_for_request_bound_to_proof(order_id, request.amount_cents, proof)

    def side_effect():
        balances[order_id] = balances.get(order_id, 0) - request.amount_cents
        event = {"order_id": order_id, "amount_cents": request.amount_cents}
        ledger.append(event)
        return event

    outcome = verifier_gate.protect(
        action,
        proof,
        side_effect,
        audience=AUDIENCE,
    )

    allowed = getattr(outcome, "allowed", None)
    if allowed is False:
        reason = getattr(outcome, "reason", "REFUSED")
        raise HTTPException(status_code=403, detail={"reason": reason})

    if isinstance(outcome, dict) and outcome.get("allowed") is False:
        raise HTTPException(status_code=403, detail={"reason": outcome.get("reason", "REFUSED")})

    return {
        "ok": True,
        "ledger": ledger,
        "balance_cents": balances[order_id],
    }
