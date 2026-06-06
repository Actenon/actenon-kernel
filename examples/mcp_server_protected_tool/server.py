"""FastMCP server using Actenon's native request-context proof adapter."""

from __future__ import annotations

import sys
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from mcp.server.fastmcp import Context, FastMCP

from actenon import ActenonGate
from actenon.adapters.mcp import protected_mcp_tool
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.preflight import build_destructive_actions_policy_pack
from actenon.replay import ReplayProtector, SqliteReplayStore


EXAMPLE_ROOT = Path(__file__).resolve().parent
DEMO_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
MCP_AUDIENCE = "service:actenon-mcp-consequential-tools"

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    gate = ActenonGate.local_dev(
        audience=MCP_AUDIENCE,
        policy_pack=build_destructive_actions_policy_pack(),
        replay_protector=ReplayProtector(
            SqliteReplayStore(EXAMPLE_ROOT / "state" / "native-adapter-replay.sqlite3")
        ),
        clock=lambda: DEMO_NOW,
    )

mcp = FastMCP("Actenon MCP Proof Gate")


def _intent(
    *,
    tool_name: str,
    capability: str,
    resource_type: str,
    resource_id: str,
    parameters: Mapping[str, Any],
) -> ActionIntent:
    environment = str(parameters.get("environment", "unknown"))
    return ActionIntent(
        intent_id=(
            f"intent_mcp_{tool_name.replace('.', '_')}_"
            f"{resource_id.replace(':', '_').replace('/', '_')}"
        ),
        issued_at=DEMO_NOW,
        expires_at=DEMO_NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_mcp_demo"),
        requester=PartyRef(type="agent", id="mcp-agent"),
        action=ActionSpec(
            name=tool_name,
            capability=capability,
            parameters=dict(parameters),
        ),
        target=TargetRef(
            resource_type=resource_type,
            resource_id=resource_id,
            selectors={"environment": environment},
        ),
        context={"environment": environment},
    )


def _simulated(tool_name: str, target: str) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "target": target,
        "simulated": True,
        "real_provider_called": False,
    }


@mcp.tool(name="filesystem.delete")
@protected_mcp_tool(
    gate,
    audience=MCP_AUDIENCE,
    action_builder=lambda args: _intent(
        tool_name="filesystem.delete",
        capability="infrastructure.delete",
        resource_type="filesystem_path",
        resource_id=str(args["path"]),
        parameters=args,
    ),
)
def filesystem_delete(
    path: str,
    recursive: bool,
    environment: str,
    ctx: Context,
) -> dict[str, Any]:
    """Simulate deleting a filesystem path after exact-action proof."""

    return _simulated("filesystem.delete", path)


@mcp.tool(name="database.migrate")
@protected_mcp_tool(
    gate,
    audience=MCP_AUDIENCE,
    action_builder=lambda args: _intent(
        tool_name="database.migrate",
        capability="migration.apply",
        resource_type="database",
        resource_id=str(args["database"]),
        parameters=args,
    ),
)
def database_migrate(
    database: str,
    migration_id: str,
    environment: str,
    ctx: Context,
) -> dict[str, Any]:
    """Simulate applying one database migration after exact-action proof."""

    return _simulated("database.migrate", database)


@mcp.tool(name="iam.grant")
@protected_mcp_tool(
    gate,
    audience=MCP_AUDIENCE,
    action_builder=lambda args: _intent(
        tool_name="iam.grant",
        capability="iam.permission.grant",
        resource_type="iam_principal",
        resource_id=str(args["principal"]),
        parameters=args,
    ),
)
def iam_grant(
    principal: str,
    role: str,
    environment: str,
    ctx: Context,
) -> dict[str, Any]:
    """Simulate granting one IAM role after exact-action proof."""

    return _simulated("iam.grant", principal)


@mcp.tool(name="data.export")
@protected_mcp_tool(
    gate,
    audience=MCP_AUDIENCE,
    action_builder=lambda args: _intent(
        tool_name="data.export",
        capability="data.export",
        resource_type="dataset",
        resource_id=str(args["dataset"]),
        parameters=args,
    ),
)
def data_export(
    dataset: str,
    row_count: int,
    destination: str,
    sensitive_data: bool,
    environment: str,
    ctx: Context,
) -> dict[str, Any]:
    """Simulate exporting one dataset after exact-action proof."""

    return _simulated("data.export", dataset)


@mcp.tool(name="payment.release")
@protected_mcp_tool(
    gate,
    audience=MCP_AUDIENCE,
    action_builder=lambda args: _intent(
        tool_name="payment.release",
        capability="payment.release",
        resource_type="payment_batch",
        resource_id=str(args["batch_id"]),
        parameters=args,
    ),
)
def payment_release(
    batch_id: str,
    amount_minor: int,
    currency: str,
    environment: str,
    ctx: Context,
) -> dict[str, Any]:
    """Simulate releasing one payment batch after exact-action proof."""

    return _simulated("payment.release", batch_id)


def main() -> int:
    print(
        "Actenon protected MCP tools use request metadata for proof; "
        "proof is absent from every tool schema.",
        file=sys.stderr,
    )
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
