from __future__ import annotations

import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


pytest.importorskip("langchain_core")

from actenon import ActenonGate
from actenon.adapters.langchain import (
    actenon_runnable_config,
    protected_structured_tool,
)
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.replay import ReplayProtector, SqliteReplayStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _intent(payload: dict[str, object]) -> ActionIntent:
    destination = str(payload["destination"])
    return ActionIntent(
        intent_id=f"intent_langchain_{payload['amount_minor']}_{destination}",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_adapters"),
        requester=PartyRef(type="agent", id="langchain-agent"),
        action=ActionSpec(
            name="payout.release",
            capability="payment.release",
            parameters={
                "amount_minor": int(payload["amount_minor"]),
                "destination": destination,
            },
        ),
        target=TargetRef(
            resource_type="payout_destination",
            resource_id=destination,
        ),
    )


def test_langchain_tool_hides_proof_schema_and_refuses_laundered_proof() -> None:
    side_effects: list[tuple[int, str]] = []

    def release_payout(amount_minor: int, destination: str) -> dict[str, object]:
        """Release one payout to the requested destination."""

        side_effects.append((amount_minor, destination))
        return {"status": "released"}

    with TemporaryDirectory() as tempdir, warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        gate = ActenonGate.local_dev(
            audience="service:langchain-payout-tool",
            replay_protector=ReplayProtector(
                SqliteReplayStore(Path(tempdir) / "replay.sqlite3")
            ),
            clock=lambda: NOW,
        )
        tool = protected_structured_tool(
            gate,
            release_payout,
            action_builder=_intent,
            audience="service:langchain-payout-tool",
        )
        approved = {"amount_minor": 1250, "destination": "bank:approved"}
        diverted = {"amount_minor": 1250, "destination": "bank:diverted"}
        valid_proof = gate.mint_proof(_intent(approved))
        laundered_proof = gate.mint_proof(_intent(approved))

        valid = tool.invoke(
            approved,
            config=actenon_runnable_config(valid_proof),
        )
        refused = tool.invoke(
            diverted,
            config=actenon_runnable_config(laundered_proof),
        )

    assert set(tool.args) == {"amount_minor", "destination"}
    assert "intent_json" not in tool.args
    assert "pccb_json" not in tool.args
    assert valid["outcome"] == "executed"
    assert refused["outcome"] == "refused"
    assert refused["reason_code"] == "INTENT_MISMATCH"
    assert side_effects == [(1250, "bank:approved")]
