from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from actenon.gate import ActenonGate
from actenon.models.contracts import PCCB


AUDIENCE = "service:refunds"

gate = ActenonGate.local_dev(audience=AUDIENCE)

app = FastAPI(title="Actenon FastAPI Resource Boundary Refund Demo")
client = TestClient(app)

ledger: List[Dict[str, int]] = []
balances: Dict[str, int] = {"ord-123": 100000, "ord-456": 100000}


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
        requester_id="fastapi-demo-agent",
    )


def action_from_request_and_proof(order_id: str, amount_cents: int, proof: PCCB) -> Dict[str, Any]:
    """Reconstruct the exact action intent being attempted at the boundary.

    The endpoint receives the requested order/amount plus a serialized proof.
    build_action creates the semantic action; the proof supplies the original
    proof-bound metadata needed for exact canonical verification.
    """
    action = build_refund_action(order_id, amount_cents)
    action["intent_id"] = proof.intent_id
    action["issued_at"] = proof.issued_at.isoformat()
    action["expires_at"] = proof.expires_at.isoformat()
    return action


def mint_refund_proof(order_id: str, amount_cents: int) -> Tuple[Dict[str, Any], PCCB, str]:
    action = build_refund_action(order_id, amount_cents)
    proof = gate.mint_proof(action)
    return action, proof, proof.to_wire()


def outcome_allowed(outcome: Any) -> bool:
    if outcome is True:
        return True
    if isinstance(outcome, dict):
        return bool(outcome.get("allowed"))
    return bool(getattr(outcome, "allowed", False))


def outcome_reason(outcome: Any) -> str:
    if isinstance(outcome, dict):
        return str(outcome.get("reason") or outcome.get("code") or "REFUSED")
    return str(getattr(outcome, "reason", None) or getattr(outcome, "code", None) or "REFUSED")


def refuse(reason: str) -> None:
    raise HTTPException(status_code=403, detail={"reason": reason})


@app.post("/refunds/{order_id}")
def refund_order(
    order_id: str,
    body: RefundRequest,
    x_actenon_proof: Optional[str] = Header(default=None),
):
    if x_actenon_proof is None:
        refuse("PCCB_REQUIRED")

    try:
        proof = PCCB.from_wire(x_actenon_proof)
    except ValueError:
        refuse("PCCB_MALFORMED")

    action = action_from_request_and_proof(order_id, body.amount_cents, proof)

    def side_effect() -> Dict[str, Any]:
        if order_id not in balances:
            balances[order_id] = 100000
        balances[order_id] -= body.amount_cents
        event = {"order_id": order_id, "amount_cents": body.amount_cents}
        ledger.append(event)
        return event

    outcome = gate.protect(
        action,
        proof,
        side_effect,
        audience=AUDIENCE,
    )

    if not outcome_allowed(outcome):
        refuse(outcome_reason(outcome))

    return {
        "ok": True,
        "ledger": ledger,
        "balance_cents": balances[order_id],
    }
