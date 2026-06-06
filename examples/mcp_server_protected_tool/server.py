"""Protected MCP server for consequential local tool examples.

The important property of this server is not transport. It is execution-edge
placement: each MCP tool calls the Actenon proof gate before the simulated
side effect can run.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from actenon.core import ContractValidationError, RefusalException  # noqa: E402
from examples.mcp_server_protected_tool.proof_gate import (  # noqa: E402
    invoke_protected_tool,
    supported_tool_names,
)

try:  # noqa: E402
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - optional integration dependency
    raise SystemExit("Install MCP first: pip install -r requirements.txt") from exc


EXAMPLE_ROOT = Path(__file__).resolve().parent
mcp = FastMCP("Actenon MCP Proof Gate")


def _call_tool(
    tool_name: str,
    *,
    intent_json: str | None,
    pccb_json: str | None,
    preflight_evidence_json: str | None,
) -> dict[str, Any]:
    try:
        outcome = invoke_protected_tool(
            tool_name,
            example_root=EXAMPLE_ROOT,
            intent_payload=intent_json,
            pccb_payload=pccb_json,
            preflight_evidence=preflight_evidence_json,
        )
        return outcome.to_dict()
    except (ContractValidationError, RefusalException) as exc:
        return {
            "ok": False,
            "error": exc.refusal_code,
            "message": exc.message,
            "details": exc.details,
        }


@mcp.tool(name="filesystem.delete")
def filesystem_delete(
    intent_json: str | None = None,
    pccb_json: str | None = None,
    preflight_evidence_json: str | None = None,
) -> dict[str, Any]:
    """Delete a filesystem path only after Actenon proof-gate admission."""

    return _call_tool(
        "filesystem.delete",
        intent_json=intent_json,
        pccb_json=pccb_json,
        preflight_evidence_json=preflight_evidence_json,
    )


@mcp.tool(name="database.migrate")
def database_migrate(
    intent_json: str | None = None,
    pccb_json: str | None = None,
    preflight_evidence_json: str | None = None,
) -> dict[str, Any]:
    """Apply a database migration only after Actenon proof-gate admission."""

    return _call_tool(
        "database.migrate",
        intent_json=intent_json,
        pccb_json=pccb_json,
        preflight_evidence_json=preflight_evidence_json,
    )


@mcp.tool(name="iam.grant")
def iam_grant(
    intent_json: str | None = None,
    pccb_json: str | None = None,
    preflight_evidence_json: str | None = None,
) -> dict[str, Any]:
    """Grant IAM permission only after Actenon proof-gate admission."""

    return _call_tool(
        "iam.grant",
        intent_json=intent_json,
        pccb_json=pccb_json,
        preflight_evidence_json=preflight_evidence_json,
    )


@mcp.tool(name="data.export")
def data_export(
    intent_json: str | None = None,
    pccb_json: str | None = None,
    preflight_evidence_json: str | None = None,
) -> dict[str, Any]:
    """Export data only after Actenon proof-gate admission."""

    return _call_tool(
        "data.export",
        intent_json=intent_json,
        pccb_json=pccb_json,
        preflight_evidence_json=preflight_evidence_json,
    )


@mcp.tool(name="payment.release")
def payment_release(
    intent_json: str | None = None,
    pccb_json: str | None = None,
    preflight_evidence_json: str | None = None,
) -> dict[str, Any]:
    """Release a payment only after Actenon proof-gate admission."""

    return _call_tool(
        "payment.release",
        intent_json=intent_json,
        pccb_json=pccb_json,
        preflight_evidence_json=preflight_evidence_json,
    )


def main() -> int:
    print("Actenon protected MCP tools: " + ", ".join(supported_tool_names()), file=sys.stderr)
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
