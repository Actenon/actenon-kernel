"""LangChain tool with proof injected through RunnableConfig, not tool args."""

from __future__ import annotations

import argparse
import json
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from actenon import ActenonGate
from actenon.adapters.langchain import (
    actenon_runnable_config,
    protected_structured_tool,
)
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.replay import ReplayProtector, SqliteReplayStore


EXAMPLE_ROOT = Path(__file__).resolve().parent
DEMO_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
TOOL_AUDIENCE = "service:langchain-payout-tool"
SIMULATED_PAYOUTS: list[dict[str, Any]] = []

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    gate = ActenonGate.local_dev(
        audience=TOOL_AUDIENCE,
        replay_protector=ReplayProtector(
            SqliteReplayStore(EXAMPLE_ROOT / "state" / "replay.sqlite3")
        ),
        clock=lambda: DEMO_NOW,
    )


def build_payout_intent(payload: Mapping[str, Any]) -> ActionIntent:
    destination = str(payload["destination"])
    return ActionIntent(
        intent_id=(
            f"intent_langchain_payout_{payload['amount_minor']}_"
            f"{destination.replace(':', '_')}"
        ),
        issued_at=DEMO_NOW,
        expires_at=DEMO_NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_langchain_demo"),
        requester=PartyRef(type="agent", id="langchain-demo-agent"),
        action=ActionSpec(
            name="payout.release",
            capability="payment.release",
            parameters={
                "amount_minor": int(payload["amount_minor"]),
                "currency": str(payload["currency"]),
                "destination": destination,
            },
        ),
        target=TargetRef(
            resource_type="payout_destination",
            resource_id=destination,
        ),
    )


def release_payout(
    amount_minor: int,
    currency: str,
    destination: str,
) -> dict[str, Any]:
    """Release one simulated payout to an exact destination."""

    record = {
        "payout_id": f"payout_local_{len(SIMULATED_PAYOUTS) + 1:04d}",
        "amount_minor": amount_minor,
        "currency": currency,
        "destination": destination,
        "simulated": True,
    }
    SIMULATED_PAYOUTS.append(record)
    return record


# RunnableConfig is injected by LangChain at invocation time and excluded from
# the model-facing schema. The model sees only these three domain fields.
payout_tool = protected_structured_tool(
    gate,
    release_payout,
    action_builder=build_payout_intent,
    audience=TOOL_AUDIENCE,
    name="release_payout",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the native LangChain adapter.")
    parser.add_argument(
        "--scenario",
        choices=("success", "mismatch", "missing-proof"),
        default="success",
    )
    args = parser.parse_args()

    approved = {
        "amount_minor": 1250,
        "currency": "USD",
        "destination": "bank:demo-approved",
    }
    invoked = dict(approved)
    proof = None
    if args.scenario != "missing-proof":
        proof = gate.mint_proof(build_payout_intent(approved))
    if args.scenario == "mismatch":
        invoked["destination"] = "bank:unapproved"

    result = payout_tool.invoke(
        invoked,
        config=actenon_runnable_config(proof),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
