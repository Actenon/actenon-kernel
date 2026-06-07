from __future__ import annotations

from actenon.gate import ActenonGate

from examples.fastapi_verifier_only_refund.app import AUDIENCE


issuer_gate = ActenonGate.local_dev(audience=AUDIENCE)


def build_refund_action(order_id: str, amount_cents: int):
    return issuer_gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id="demo",
        requester_id="issuer-control-plane",
    )


def mint_refund_proof(order_id: str, amount_cents: int):
    action = build_refund_action(order_id, amount_cents)
    proof = issuer_gate.mint_proof(action)
    return action, proof, proof.to_wire()
