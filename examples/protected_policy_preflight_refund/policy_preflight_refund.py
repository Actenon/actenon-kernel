from actenon import ActenonGate


MAX_REFUND_CENTS = 500000


class RefundLedger:
    def __init__(self):
        self.events = []

    def issue_refund(self, order_id: str, amount_cents: int):
        self.events.append({"order_id": order_id, "amount_cents": amount_cents})
        return {"status": "refunded", "order_id": order_id, "amount_cents": amount_cents}


def refund_preflight_policy(action_intent):
    """Issuer-side business policy for refund proof issuance.

    Actenon core remains domain-neutral. This policy is the issuer/control-plane
    decision point that decides whether a refund action may receive proof.
    """
    params = action_intent.get("action", {}).get("parameters", {})
    amount_cents = params.get("amount_cents")

    if not isinstance(amount_cents, int):
        raise PermissionError("PREFLIGHT_POLICY_DENIED: amount_cents must be an integer")

    if amount_cents <= 0:
        raise PermissionError("PREFLIGHT_POLICY_DENIED: amount_cents must be greater than zero")

    if amount_cents > MAX_REFUND_CENTS:
        raise PermissionError("PREFLIGHT_POLICY_DENIED: refund exceeds maximum allowed amount")

    return True


def build_refund_action(gate, order_id: str, amount_cents: int):
    return gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id="demo",
        requester_id="support-agent",
    )


def run_demo():
    gate = ActenonGate.local_dev(audience="service:refunds")
    ledger = RefundLedger()

    approved = build_refund_action(gate, "ord-123", 2500)
    proof = gate.mint_proof_after_preflight(approved, refund_preflight_policy)

    gate.protect(
        approved,
        proof,
        lambda: ledger.issue_refund("ord-123", 2500),
        audience="service:refunds",
    )

    refused = []

    for label, action in [
        ("negative refund", build_refund_action(gate, "ord-124", -2500)),
        ("excessive refund", build_refund_action(gate, "ord-125", 500001)),
    ]:
        try:
            gate.mint_proof_after_preflight(action, refund_preflight_policy)
        except PermissionError as exc:
            refused.append({"case": label, "reason": str(exc)})

    tampered = build_refund_action(gate, "ord-123", 250000)
    gate.protect(
        tampered,
        proof,
        lambda: ledger.issue_refund("ord-123", 250000),
        audience="service:refunds",
    )

    return {"ledger": ledger.events, "preflight_refusals": refused}


if __name__ == "__main__":
    result = run_demo()
    print(result)
