#!/usr/bin/env python3
"""
Actenon worked example & evidence: a protected LangChain financial-ops agent.

WHAT THIS DEMONSTRATES
----------------------
A runnable, self-verifying demonstration that destructive LangChain tools,
protected with Actenon's shipped `protected_structured_tool` adapter, enforce
proof-bound execution:

- the one authorised action runs once
- every adversarial variant is refused before side effect
- proof is delivered through LangChain RunnableConfig using `actenon_runnable_config`
- proof is never exposed as a model-visible tool argument

This is the companion to the MCP evidence example. Together they show the same
kernel enforcing across two different integration models:

- MCP: proof in request metadata/context
- LangChain: proof in RunnableConfig

That is evidence that the kernel is framework-agnostic.

This proves local enforcement correctness with the development signer. It is not
a production deployment, third-party audit, or evidence of production key custody.
The local HMAC signer is development-only; production should use asymmetric
signing under managed custody.

Run:

    pip install -e ".[asymmetric]"
    pip install langchain-core
    python examples/protected_langchain_finance_agent/protected_langchain_finance_agent.py

Exit code is 0 only if every expected outcome matches, so this doubles as a CI check.
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from actenon import ActenonGate
from actenon.adapters.langchain import (
    actenon_runnable_config,
    protected_structured_tool,
)

NOW = datetime.now(timezone.utc)

# The simulated real system this finance agent can touch.
LEDGER: dict[str, Any] = {
    "balance_cents": 5_000_000,
    "payouts": [],
}


gate = ActenonGate.local_dev(
    audience="service:finance-ops-agent",
    clock=lambda: NOW,
)


def _stable_intent_id(
    name: str,
    target_id: str,
    params: dict[str, Any],
) -> str:
    material = repr((name, target_id, sorted(params.items()))).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:12]
    return f"intent_{name}_{target_id}_{digest}".replace(":", "_").replace(".", "_")


def _intent(
    name: str,
    capability: str,
    params: dict[str, Any],
    target_type: str,
    target_id: str,
) -> dict[str, Any]:
    return {
        "contract": {
            "name": "action_intent",
            "version": "v1",
        },
        "intent_id": _stable_intent_id(name, target_id, params),
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "tenant": {
            "tenant_id": "acme-fin",
        },
        "requester": {
            "type": "agent",
            "id": "fin-bot",
        },
        "action": {
            "name": name,
            "capability": capability,
            "parameters": dict(params),
        },
        "target": {
            "resource_type": target_type,
            "resource_id": target_id,
        },
    }


# Domain functions: only business arguments are visible to the model.
# Proof is not a function argument and is not part of the tool schema.


def pay_vendor(vendor_id: str, amount_cents: int) -> dict[str, Any]:
    """Release a payment to a vendor. Destructive: moves money."""
    LEDGER["balance_cents"] -= amount_cents
    LEDGER["payouts"].append(
        {
            "vendor": vendor_id,
            "amount_cents": amount_cents,
        }
    )
    return {
        "paid": vendor_id,
        "amount_cents": amount_cents,
        "balance_cents": LEDGER["balance_cents"],
    }


def issue_refund(order_id: str, amount_cents: int) -> dict[str, Any]:
    """Issue a customer refund. Destructive: moves money."""
    LEDGER["balance_cents"] -= amount_cents
    LEDGER["payouts"].append(
        {
            "refund_order": order_id,
            "amount_cents": amount_cents,
        }
    )
    return {
        "refunded": order_id,
        "amount_cents": amount_cents,
        "balance_cents": LEDGER["balance_cents"],
    }


def build_pay_intent(args: dict[str, Any]) -> dict[str, Any]:
    return _intent(
        "payment.release",
        "payment.release",
        args,
        "vendor",
        args["vendor_id"],
    )


def build_refund_intent(args: dict[str, Any]) -> dict[str, Any]:
    return _intent(
        "payment.refund",
        "payment.refund",
        args,
        "order",
        args["order_id"],
    )


pay_tool = protected_structured_tool(
    gate,
    pay_vendor,
    action_builder=build_pay_intent,
    audience="service:finance-ops-agent",
)

refund_tool = protected_structured_tool(
    gate,
    issue_refund,
    action_builder=build_refund_intent,
    audience="service:finance-ops-agent",
)


def invoke(tool: Any, *, proof: Any, **domain_args: Any) -> dict[str, Any]:
    config = actenon_runnable_config(proof) if proof is not None else {}
    result = tool.invoke(domain_args, config=config)
    return result if isinstance(result, dict) else {}


def main() -> int:
    print("=" * 74)
    print("Actenon developer evaluation on LangChain: financial-ops agent")
    print("=" * 74)

    schema_ok = True

    print("\nModel-facing tool schemas. Proof must be absent:")
    for tool, label in [
        (pay_tool, "pay_vendor"),
        (refund_tool, "issue_refund"),
    ]:
        keys = list(tool.args.keys())
        leaked = any(
            key in keys
            for key in (
                "proof",
                "proof_token",
                "pccb",
                "intent",
                "intent_json",
                "pccb_json",
                "config",
            )
        )
        schema_ok = schema_ok and not leaked
        print(f"  {label:<14} {keys}   proof_in_schema={leaked}")

    print(
        f"\nInitial state: balance=${LEDGER['balance_cents'] / 100:,.2f} "
        f"payouts={LEDGER['payouts']}\n"
    )

    # Control plane authorises exactly one action:
    # pay vendor:acme $250.00.
    approved = build_pay_intent(
        {
            "vendor_id": "vendor:acme",
            "amount_cents": 25_000,
        }
    )
    proof = gate.mint_proof(approved)

    results: list[bool] = []

    def run(
        label: str,
        fn: Any,
        expected_outcome: str,
        expected_reason: str | tuple[str, ...] | None,
    ) -> None:
        try:
            out = fn()
            outcome = out.get("outcome")
            reason = out.get("reason_code")
        except Exception as exc:  # pragma: no cover - defensive evidence path
            outcome = "raised"
            reason = type(exc).__name__

        if expected_reason is None:
            reason_ok = True
        elif isinstance(expected_reason, tuple):
            reason_ok = reason in expected_reason
        else:
            reason_ok = reason == expected_reason

        ok = outcome == expected_outcome and reason_ok
        results.append(ok)

        tail = f" / {reason}" if reason else ""
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<50} -> {outcome}{tail}")

    print("Adversarial battery")
    print("Proof issued only for: pay vendor:acme $250.00\n")

    run(
        "A authorised pay acme $250.00",
        lambda: invoke(
            pay_tool,
            proof=proof,
            vendor_id="vendor:acme",
            amount_cents=25_000,
        ),
        "executed",
        None,
    )

    run(
        "B amount tampering: pay acme $250,000",
        lambda: invoke(
            pay_tool,
            proof=proof,
            vendor_id="vendor:acme",
            amount_cents=25_000_000,
        ),
        "refused",
        "INTENT_MISMATCH",
    )

    run(
        "C payee swap: pay attacker $250.00",
        lambda: invoke(
            pay_tool,
            proof=proof,
            vendor_id="vendor:attacker",
            amount_cents=25_000,
        ),
        "refused",
        "INTENT_MISMATCH",
    )

    run(
        "C2 cross-tool laundering: pay proof into refund tool",
        lambda: invoke(
            refund_tool,
            proof=proof,
            order_id="ord-1",
            amount_cents=25_000,
        ),
        "refused",
        ("SCOPE_CAPABILITY_MISMATCH", "INTENT_MISMATCH"),
    )

    run(
        "D no proof at all",
        lambda: invoke(
            pay_tool,
            proof=None,
            vendor_id="vendor:acme",
            amount_cents=25_000,
        ),
        "refused",
        "PCCB_REQUIRED",
    )

    run(
        "E replay the approved payment",
        lambda: invoke(
            pay_tool,
            proof=proof,
            vendor_id="vendor:acme",
            amount_cents=25_000,
        ),
        "refused",
        "DUPLICATE_REPLAY",
    )

    past = datetime.now(timezone.utc) - timedelta(hours=1)
    gate_past = ActenonGate.local_dev(
        audience="service:finance-ops-agent",
        clock=lambda: past,
    )

    expired_intent = {
        **build_pay_intent(
            {
                "vendor_id": "vendor:globex",
                "amount_cents": 1_000,
            }
        ),
        "issued_at": past.isoformat(),
        "expires_at": (past + timedelta(minutes=5)).isoformat(),
    }
    expired_proof = gate_past.mint_proof(expired_intent)

    run(
        "F expired proof",
        lambda: invoke(
            pay_tool,
            proof=expired_proof,
            vendor_id="vendor:globex",
            amount_cents=1_000,
        ),
        "refused",
        "PROOF_EXPIRED",
    )

    run(
        "G malformed garbage proof",
        lambda: invoke(
            pay_tool,
            proof={"lol": "nope"},
            vendor_id="vendor:globex",
            amount_cents=1_000,
        ),
        "refused",
        "SCHEMA_INVALID",
    )

    print(
        f"\nFinal state: balance=${LEDGER['balance_cents'] / 100:,.2f} "
        f"payouts={LEDGER['payouts']}"
    )

    invariants = {
        "only_one_payout": len(LEDGER["payouts"]) == 1,
        "exactly_250_paid": LEDGER["payouts"]
        == [
            {
                "vendor": "vendor:acme",
                "amount_cents": 25_000,
            }
        ],
        "balance_correct": LEDGER["balance_cents"] == 5_000_000 - 25_000,
        "no_attacker_payee": all(
            "attacker" not in str(payout)
            for payout in LEDGER["payouts"]
        ),
        "no_refund_happened": all(
            "refund_order" not in payout
            for payout in LEDGER["payouts"]
        ),
    }

    print("\nHarm-prevention invariants:")
    for name, ok in invariants.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    all_ok = schema_ok and all(results) and all(invariants.values())

    print("\n" + "=" * 74)
    print(
        f"RESULT: {'ALL CHECKS PASSED' if all_ok else 'CHECKS FAILED'} "
        f"(schema_ok={schema_ok}, "
        f"battery={sum(results)}/{len(results)}, "
        f"invariants={sum(invariants.values())}/{len(invariants)})"
    )
    print("No valid proof, no execution.")
    print("=" * 74)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
