
"""Verifier-only FastAPI refund boundary.

The endpoint has a verifier but no signer, so it cannot mint proofs.
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

from examples.fastapi_verifier_only_refund.issuer import AUDIENCE, issuer_gate


verifier_gate = ActenonGate(
    verifier=issuer_gate.signer,
    audience=AUDIENCE,
    issuer="service:refund-boundary",
)

app = FastAPI(title="Actenon verifier-only FastAPI refund demo")

ledger = []
balances = {"ord-123": 100000, "ord-456": 100000}


class RefundRequest(BaseModel):
    amount_cents: int


def reset_ledger() -> None:
    ledger.clear()
    balances.clear()
    balances.update({"ord-123": 100000, "ord-456": 100000})


def proof_from_header(value: Optional[str]) -> Tuple[Dict[str, Any], PCCB]:
    if not value:
        raise ValueError("missing proof header")

    padded = value + ("=" * (-len(value) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    envelope = json.loads(raw)

    return envelope["action_intent"], PCCB.from_dict(envelope["pccb"])


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

    outcome = verifier_gate.protect(
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
