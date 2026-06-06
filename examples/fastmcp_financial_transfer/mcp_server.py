from __future__ import annotations

from typing import Any

try:
    from mcp.server.fastmcp import Context, FastMCP
except Exception:  # keeps tests usable when FastMCP is not installed
    Context = Any
    FastMCP = None

from examples.financial_agent_protected_transfer.financial_agent import FinancialAgent


if FastMCP is not None:
    mcp = FastMCP("ActenonFinancial")
else:
    mcp = None


secure_agent = FinancialAgent()


def _proof_from_context(ctx: Context | None) -> Any | None:
    """Extract proof supplied by a trusted MCP runtime/client context.

    In production, proof should be injected by the trusted host/runtime after
    user approval, not invented by the model and not treated as ordinary prompt
    text.
    """

    if ctx is None:
        return None

    for attr in ("metadata", "session", "request_context"):
        value = getattr(ctx, attr, None)
        if isinstance(value, dict) and "actenon_proof" in value:
            return value["actenon_proof"]

    return None


def transfer_funds_impl(amount: int, destination: str, proof: Any | None) -> dict[str, Any]:
    """Shared implementation used by MCP and tests."""

    return secure_agent.attempt_transfer(
        amount=amount,
        destination=destination,
        proof=proof,
    )


if mcp is not None:

    @mcp.tool()
    def transfer_funds(amount: int, destination: str, ctx: Context) -> str:
        """
        Transfer funds to a destination.

        The model can request the transfer, but proof is supplied by the trusted
        runtime context. If Actenon cannot verify exact proof for this action,
        the transfer is refused before the ledger mutates.
        """

        proof = _proof_from_context(ctx)
        result = transfer_funds_impl(amount=amount, destination=destination, proof=proof)

        if result["status"] == "executed":
            receipt = result["receipt"]
            return (
                "EXECUTED: transfer completed once.\n"
                f"transfer_id: {result['payload']['transfer_id']}\n"
                f"receipt_id: {getattr(receipt, 'receipt_id', 'receipt_emitted')}"
            )

        refusal = result["refusal"]
        return (
            "REFUSED: transfer blocked before side effect.\n"
            f"reason_code: {result['reason_code']}\n"
            f"refusal_id: {getattr(refusal, 'refusal_id', 'refusal_emitted')}"
        )


if __name__ == "__main__":
    if mcp is None:
        raise SystemExit(
            "FastMCP is not installed. Install MCP/FastMCP to run this server."
        )
    mcp.run(transport="stdio")
