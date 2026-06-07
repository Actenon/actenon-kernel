from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from actenon.gate import ActenonGate
from actenon.models.contracts import PCCB


AUDIENCE = "service:refunds"

app = FastAPI(title="Actenon Verifier-Only FastAPI Demo")

# This endpoint is verifier-only.
# It does not expose mint_proof, mint_refund_proof or any issuer helper.
verifier_gate = ActenonGate.local_dev(audience=AUDIENCE)

ledger = []
balances = {
    "ord-123": 100000,
    "ord-456": 100000,
}


class RefundRequest(BaseModel):
    amount_cents: int


def reset_ledger() -> None:
    ledger.clear()
    balances.clear()
    balances.update(
        {
            "ord-123": 100000,
            "ord-456": 100000,
        }
    )


def build_request_action(order_id: str, amount_cents: int) -> Dict[str, Any]:
    return verifier_gate.build_action(
        "refund.issue",
        "payment.refund",
        {
            "order_id": order_id,
            "amount_cents": amount_cents,
        },
        target_type="order",
        target_id=order_id,
        tenant_id="demo",
        requester_id="verifier-only-api",
    )


def bind_request_action_to_proof(action: Dict[str, Any], proof: PCCB) -> Dict[str, Any]:
    action["intent_id"] = proof.intent_id

    if hasattr(proof.issued_at, "isoformat"):
        action["issued_at"] = proof.issued_at.isoformat()
    else:
        action["issued_at"] = proof.issued_at

    if hasattr(proof.expires_at, "isoformat"):
        action["expires_at"] = proof.expires_at.isoformat()
    else:
        action["expires_at"] = proof.expires_at

    return action


def issue_refund(order_id: str, amount_cents: int) -> Dict[str, Any]:
    balances[order_id] -= amount_cents
    event = {
        "order_id": order_id,
        "amount_cents": amount_cents,
    }
    ledger.append(event)
    return event


def outcome_allowed(outcome: Any) -> bool:
    if isinstance(outcome, dict):
        return bool(outcome.get("allowed") or outcome.get("ok") or outcome.get("executed"))

    if hasattr(outcome, "allowed"):
        return bool(outcome.allowed)

    if hasattr(outcome, "ok"):
        return bool(outcome.ok)

    if hasattr(outcome, "executed"):
        return bool(outcome.executed)

    return bool(outcome)


@app.post("/refunds/{order_id}")
def refund_order(
    order_id: str,
    request: RefundRequest,
    x_actenon_proof: Optional[str] = Header(default=None),
):
    if x_actenon_proof is None:
        raise HTTPException(status_code=403, detail="PCCB_REQUIRED")

    proof = PCCB.from_wire(x_actenon_proof)

    action = build_request_action(order_id, request.amount_cents)
    action = bind_request_action_to_proof(action, proof)

    try:
        outcome = verifier_gate.protect(
            action,
            proof,
            lambda: issue_refund(order_id, request.amount_cents),
            audience=AUDIENCE,
        )
    except Exception as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    if not outcome_allowed(outcome):
        raise HTTPException(status_code=403, detail=str(outcome))

    return {
        "status": "executed",
        "ledger": ledger,
        "balance_cents": balances[order_id],
    }
