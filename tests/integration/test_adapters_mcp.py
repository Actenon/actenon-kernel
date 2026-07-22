from __future__ import annotations

import asyncio
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest


pytest.importorskip("mcp")

from mcp.server.fastmcp import Context, FastMCP

from actenon import ActenonGate
from actenon.adapters.mcp import mcp_authorization_meta, protected_mcp_tool
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.replay import ReplayProtector, SqliteReplayStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _intent(payload: dict[str, object]) -> ActionIntent:
    destination = str(payload["destination"])
    return ActionIntent(
        intent_id=f"intent_mcp_{payload['amount_minor']}_{destination}",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_adapters"),
        requester=PartyRef(type="agent", id="mcp-agent"),
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


def _context(meta: dict[str, object] | None = None) -> Context:
    return Context(request_context=SimpleNamespace(meta=meta or {}))


def test_mcp_wrapper_hides_runtime_context_and_refuses_unproven_calls() -> None:
    side_effects: list[tuple[int, str]] = []
    with TemporaryDirectory() as tempdir, warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        gate = ActenonGate.local_dev(
            audience="service:mcp-payout-tool",
            replay_protector=ReplayProtector(
                SqliteReplayStore(Path(tempdir) / "replay.sqlite3")
            ),
            clock=lambda: NOW,
        )
        server = FastMCP("Actenon adapter test")

        @server.tool(name="payout.release")
        @protected_mcp_tool(
            gate,
            action_builder=_intent,
            audience="service:mcp-payout-tool",
        )
        def release_payout(
            amount_minor: int,
            destination: str,
            ctx: Context,
        ) -> dict[str, str]:
            """Release one payout to the requested destination."""

            side_effects.append((amount_minor, destination))
            return {"status": "released"}

        tool = server._tool_manager.get_tool("payout.release")
        assert tool is not None
        approved = {"amount_minor": 1250, "destination": "bank:approved"}
        proof = gate.mint_proof(_intent(approved))

        missing = asyncio.run(tool.run(approved, context=_context()))
        valid = asyncio.run(
            tool.run(
                approved,
                context=_context(mcp_authorization_meta(proof)),
            )
        )

    properties = tool.parameters["properties"]
    assert set(properties) == {"amount_minor", "destination"}
    assert "proof" not in properties
    assert "pccb" not in properties
    assert missing["outcome"] == "refused"
    assert missing["reason_code"] == "PCCB_REQUIRED"
    assert valid["outcome"] == "executed"
    assert side_effects == [(1250, "bank:approved")]
