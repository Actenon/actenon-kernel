
"""Issuer-side proof minting for verifier-only FastAPI example."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

from actenon import ActenonGate
from actenon.models import PCCB


AUDIENCE = "service:refunds-verifier-only"

issuer_gate = ActenonGate.local_dev(
    audience=AUDIENCE,
    issuer="service:refund-issuer",
)


def build_refund_action(order_id: str, amount_cents: int) -> Dict[str, Any]:
    return issuer_gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id="demo",
        requester_id="refund-agent",
    )


def proof_to_header(action: Dict[str, Any], proof: PCCB) -> str:
    envelope = {
        "action_intent": action,
        "pccb": proof.to_dict(),
    }
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def mint_refund_proof(order_id: str, amount_cents: int):
    action = build_refund_action(order_id, amount_cents)
    proof = issuer_gate.mint_proof(action)
    proof_header = proof_to_header(action, proof)
    return action, proof, proof_header
