#!/usr/bin/env python3
"""
Actenon 3-minute interactive demo.

Shows the core guarantee:
- the approved action executes
- a hallucinated/tampered agent command is refused before side effect
- replay is refused
- missing proof is refused

Run:
    python examples/interactive_execution_demo.py
"""

import argparse
from typing import Any

from actenon import ActenonGate


LEDGER = {
    "balance_cents": 100_000,
    "events": [],
}


def issue_refund(order_id: str, amount_cents: int) -> dict[str, Any]:
    LEDGER["balance_cents"] -= amount_cents
    event = {"order_id": order_id, "amount_cents": amount_cents}
    LEDGER["events"].append(event)
    return {"refunded": order_id, "amount_cents": amount_cents}


def as_dict(outcome: Any) -> dict[str, Any]:
    if isinstance(outcome, dict):
        return outcome
    if hasattr(outcome, "to_dict"):
        return outcome.to_dict()
    return {
        "outcome": getattr(outcome, "outcome", None),
        "reason_code": getattr(outcome, "reason_code", None),
    }


def print_result(label: str, outcome: Any) -> None:
    data = as_dict(outcome)
    status = data.get("outcome")
    reason = data.get("reason_code")
    tail = f" / {reason}" if reason else ""
    icon = "✅" if status == "executed" else "🛑"
    print(f"{icon} {label:<46} -> {status}{tail}")


def build_refund_action(gate: ActenonGate, order_id: str, amount_cents: int, *, intent_suffix: str):
    return gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": order_id, "amount_cents": amount_cents},
        target_type="order",
        target_id=order_id,
        tenant_id="demo-shop",
        requester_id="support-agent",
        intent_id=f"intent_demo_refund_{intent_suffix}",
    )


def attempt_refund(gate: ActenonGate, action: dict[str, Any], proof: Any):
    params = action["action"]["parameters"]
    return gate.protect(
        action,
        proof,
        lambda: issue_refund(params["order_id"], int(params["amount_cents"])),
        audience="service:refunds",
    )


def run_demo() -> int:
    print("=" * 74)
    print("Actenon 3-minute demo: hallucinated agent command vs proof gate")
    print("=" * 74)
    print()
    print("The agent wants to issue refunds. The boundary only executes actions")
    print("with a valid proof bound to the exact order and exact amount.")
    print()

    gate = ActenonGate.local_dev(audience="service:refunds")

    approved = build_refund_action(gate, "ord-123", 2500, intent_suffix="approved")
    approved_proof = gate.mint_proof(approved)

    tamper_base = build_refund_action(gate, "ord-456", 2500, intent_suffix="tamper_base")
    tamper_proof = gate.mint_proof(tamper_base)
    hallucinated = build_refund_action(gate, "ord-456", 250000, intent_suffix="hallucinated")

    no_proof = build_refund_action(gate, "ord-789", 1000, intent_suffix="no_proof")

    print("Agent attempt log:")
    print()

    out1 = attempt_refund(gate, approved, approved_proof)
    print_result("approved refund: ord-123 £25.00", out1)

    out2 = attempt_refund(gate, hallucinated, tamper_proof)
    print_result("hallucinated refund: ord-456 £2,500.00", out2)

    out3 = attempt_refund(gate, approved, approved_proof)
    print_result("replay approved refund", out3)

    out4 = attempt_refund(gate, no_proof, None)
    print_result("refund with no proof", out4)

    print()
    print(f"Final ledger events: {LEDGER['events']}")
    print(f"Final balance: £{LEDGER['balance_cents'] / 100:,.2f}")
    print()
    print("No valid proof, no execution.")
    print("=" * 74)

    ok = (
        as_dict(out1).get("outcome") == "executed"
        and as_dict(out2).get("outcome") == "refused"
        and as_dict(out2).get("reason_code") == "INTENT_MISMATCH"
        and as_dict(out3).get("reason_code") == "DUPLICATE_REPLAY"
        and as_dict(out4).get("reason_code") == "PCCB_REQUIRED"
        and LEDGER["events"] == [{"order_id": "ord-123", "amount_cents": 2500}]
    )

    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Actenon interactive execution-gate demo.")
    parser.add_argument("--scripted", action="store_true", help="Run the deterministic scripted demo.")
    parser.parse_args()
    return run_demo()


if __name__ == "__main__":
    raise SystemExit(main())
