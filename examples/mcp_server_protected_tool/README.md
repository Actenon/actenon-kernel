# MCP Server Protected Tools

This FastMCP server uses Actenon's native MCP decorator. Each tool schema
contains domain fields only. The PCCB and optional Preflight evidence arrive in
MCP request metadata under the `actenon` key.

```python
@mcp.tool(name="payment.release")
@protected_mcp_tool(
    gate,
    action_builder=build_payment_intent,
    audience="service:actenon-mcp-consequential-tools",
)
def payment_release(
    batch_id: str,
    amount_minor: int,
    currency: str,
    environment: str,
    ctx: Context,
):
    return simulate_payment_release(batch_id)
```

FastMCP injects `Context` and excludes it from the tool schema. Actenon reads:

```json
{
  "actenon": {
    "proof": {"contract": {"name": "pccb", "version": "v1"}},
    "evidence": {"change_ticket": "CHG-2026-0042"}
  }
}
```

Use `mcp_authorization_meta(proof, evidence=...)` to construct that metadata.
The model-facing tool arguments never include proof blobs.

## Tools

- `filesystem.delete`
- `database.migrate`
- `iam.grant`
- `data.export`
- `payment.release`

Every handler is a safe local simulation. No filesystem, database, IAM,
provider, export, or payment side effect is performed.

## Run

```bash
python3 -m pip install -e ".[asymmetric,mcp]"
python3 examples/mcp_server_protected_tool/server.py
```

The transport-free hero demo remains available:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool database.migrate \
  --scenario refuse
```

That demo writes local Receipt/Refusal artifacts. The native server demonstrates
the production-facing schema pattern: domain arguments in the tool call, proof
in framework runtime context.
