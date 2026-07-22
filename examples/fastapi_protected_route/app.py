"""FastAPI endpoint protected by Actenon's native dependency adapter."""

from __future__ import annotations

import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from actenon import ActenonGate
from actenon.adapters.fastapi import ACTENON_PROOF_HEADER, encode_json_header
from actenon.gate import GateOutcome
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.replay import ReplayProtector, SqliteReplayStore


EXAMPLE_ROOT = Path(__file__).resolve().parent
DEMO_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
PAYOUT_AUDIENCE = "service:fastapi-payout-endpoint"
SIMULATED_PAYOUTS: list[dict[str, Any]] = []

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    gate = ActenonGate.local_dev(
        audience=PAYOUT_AUDIENCE,
        replay_protector=ReplayProtector(
            SqliteReplayStore(EXAMPLE_ROOT / "state" / "replay.sqlite3")
        ),
        clock=lambda: DEMO_NOW,
    )

app = FastAPI(title="Actenon FastAPI Protected Route", version="0.1.0")


class PayoutRequest(BaseModel):
    amount_minor: int
    currency: str
    destination: str


def build_payout_intent(payload: Mapping[str, Any]) -> ActionIntent:
    destination = str(payload["destination"])
    return ActionIntent(
        intent_id=(
            f"intent_fastapi_payout_{payload['amount_minor']}_"
            f"{destination.replace(':', '_')}"
        ),
        issued_at=DEMO_NOW,
        expires_at=DEMO_NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_fastapi_demo"),
        requester=PartyRef(type="agent", id="fastapi-demo-agent"),
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


def simulate_payout(payload: Mapping[str, Any]) -> dict[str, Any]:
    record = {
        "payout_id": f"payout_local_{len(SIMULATED_PAYOUTS) + 1:04d}",
        "amount_minor": int(payload["amount_minor"]),
        "currency": str(payload["currency"]),
        "destination": str(payload["destination"]),
        "simulated": True,
    }
    SIMULATED_PAYOUTS.append(record)
    return record


protected_payout = gate.fastapi_dependency(
    audience=PAYOUT_AUDIENCE,
    action_builder=build_payout_intent,
    side_effect=simulate_payout,
    body_model=PayoutRequest,
)


@app.get("/")
def root() -> dict[str, Any]:
    return {"ok": True, "endpoint": "/payouts", "proof_header": ACTENON_PROOF_HEADER}


@app.post("/payouts")
def create_payout(
    body: PayoutRequest,
    outcome: GateOutcome = Depends(protected_payout),
) -> dict[str, Any]:
    # The dependency has already proof-gated and executed the simulated payout.
    return outcome.to_dict()


def build_demo_request() -> tuple[dict[str, Any], dict[str, str]]:
    """Create one local request body and its out-of-band proof header."""

    body = {
        "amount_minor": 1250,
        "currency": "USD",
        "destination": "bank:demo-approved",
    }
    proof = gate.mint_proof(build_payout_intent(body))
    return body, {ACTENON_PROOF_HEADER: encode_json_header(proof)}
