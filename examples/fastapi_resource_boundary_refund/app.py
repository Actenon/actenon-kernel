from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from actenon import ActenonGate


AUDIENCE = "service:refunds"

# local_dev requires audience as a keyword-only argument in this repo.
gate = ActenonGate.local_dev(audience=AUDIENCE)

app = FastAPI(title="Actenon FastAPI resource-boundary refund example")


class RefundRequest(BaseModel):
    amount_cents: int


ledger: List[Dict[str, int]] = []
balances: Dict[str, int] = {
    "ord-123": 100000,
    "ord-456": 100000,
}

# This registry represents the issuer/control-plane handoff in the example.
# The HTTP header carries a safe proof reference. The resource boundary looks up
# the exact action+proof minted by the issuer and verifies that exact action.
_PROOF_REGISTRY: Dict[str, Tuple[dict, object]] = {}


def reset_ledger() -> None:
    ledger.clear()
    balances.clear()
    balances.update({"ord-123": 100000, "ord-456": 100000})
    _PROOF_REGISTRY.clear()

    # Reset replay tracking if this gate implementation exposes a local replay cache.
    # This keeps tests independent while preserving replay protection inside each test.
    for attr in ("_seen_pccb_ids", "_used_pccb_ids", "_replay_cache", "_used_proofs"):
        cache = getattr(gate, attr, None)
        if hasattr(cache, "clear"):
            cache.clear()


def build_refund_action(order_id: str, amount_cents: int) -> dict:
    return gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id="demo",
        requester_id="fastapi-example-agent",
    )


def proof_to_header(proof: object) -> str:
    """Return an HTTP-safe proof reference for a proof already in the registry."""
    for proof_id, (_action, registered_proof) in _PROOF_REGISTRY.items():
        if registered_proof is proof:
            return proof_id

    raise ValueError(
        "Proof is not registered. Use mint_refund_proof(...) in this example."
    )


def proof_from_header(value: Optional[str]) -> Tuple[Optional[dict], Optional[object]]:
    if value is None:
        return None, None

    return _PROOF_REGISTRY.get(value, (None, None))


def mint_refund_proof(order_id: str, amount_cents: int):
    """Issuer/control-plane helper for the example tests and docs.

    The important bit: the proof is registered with the exact action intent that
    was used when minting. The FastAPI endpoint must verify that same action.
    """
    action = build_refund_action(order_id, amount_cents)
    proof = gate.mint_proof(action)

    proof_id = "proof_" + uuid4().hex
    _PROOF_REGISTRY[proof_id] = (action, proof)

    return action, proof, proof_id


def _refuse(reason: str) -> None:
    raise HTTPException(status_code=403, detail=reason)


@app.post("/refunds/{order_id}")
def refund_order(
    order_id: str,
    request: RefundRequest,
    x_actenon_proof: Optional[str] = Header(default=None),
):
    registered_action, proof = proof_from_header(x_actenon_proof)

    if registered_action is None or proof is None:
        _refuse("PCCB_REQUIRED")

    expected_params = registered_action["action"]["parameters"]

    # Bind the HTTP request to the proofed intent before side effect.
    # This catches tampered path/body values before protect() is called.
    if expected_params.get("order_id") != order_id:
        _refuse("INTENT_MISMATCH")

    if expected_params.get("amount_cents") != request.amount_cents:
        _refuse("INTENT_MISMATCH")

    if order_id not in balances:
        _refuse("UNKNOWN_ORDER")

    if request.amount_cents <= 0:
        _refuse("POLICY_REFUSED")

    if request.amount_cents > balances[order_id]:
        _refuse("POLICY_REFUSED")

    before = len(ledger)

    def side_effect():
        balances[order_id] -= request.amount_cents
        ledger.append(
            {
                "order_id": order_id,
                "amount_cents": request.amount_cents,
            }
        )
        return {
            "status": "executed",
            "order_id": order_id,
            "amount_cents": request.amount_cents,
        }

    outcome = gate.protect(
        registered_action,
        proof,
        side_effect,
        audience=AUDIENCE,
    )

    # Different gate versions return different outcome shapes. The invariant is
    # stable: if the side effect did not run, this HTTP boundary refuses.
    if len(ledger) == before:
        reason = getattr(outcome, "reason", None) or getattr(outcome, "code", None) or "REFUSED"
        _refuse(str(reason))

    return {
        "status": "executed",
        "ledger": ledger,
        "balance_cents": balances[order_id],
    }
