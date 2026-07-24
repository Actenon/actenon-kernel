# MCP Hero Path

Actenon sits inside the MCP handler, immediately before the consequential side
effect:

```text
agent -> domain-only MCP tool call -> protected handler -> execute or refuse
```

Proof is runtime authorization metadata. It is not a tool argument.

## Native Pattern

```python
from mcp.server.fastmcp import Context, FastMCP

from actenon.adapters.mcp import protected_mcp_tool

mcp = FastMCP("Protected tools")

@mcp.tool(name="filesystem.delete")
@protected_mcp_tool(
    gate,
    action_builder=build_delete_intent,
    audience="service:filesystem-tool",
)
def delete_path(path: str, recursive: bool, ctx: Context):
    return filesystem.delete(path, recursive=recursive)
```

FastMCP hides `ctx` from the tool schema. The agent sees `path` and `recursive`,
not `intent_json`, `pccb_json`, or approval evidence.

The MCP client/runtime attaches:

```python
from actenon.adapters.mcp import mcp_authorization_meta

request_meta = mcp_authorization_meta(
    proof,
    evidence={"change_ticket": "CHG-2026-0042"},
)
```

The protected wrapper:

1. binds validated domain arguments
2. builds the exact Action Intent
3. reads PCCB and evidence from MCP request metadata
4. verifies exact-action proof and local policy
5. enforces replay and configured escrow
6. brokers endpoint authority
7. executes once or refuses
8. emits a Receipt or Refusal

## Local Examples

Install and run the native FastMCP server:

```bash
python3 -m pip install -e ".[asymmetric,mcp]"
python3 examples/mcp_server_protected_tool/server.py
```

Its five schemas contain domain fields only:

- `filesystem.delete`
- `database.migrate`
- `iam.grant`
- `data.export`
- `payment.release`

For a deterministic transport-free run:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool database.migrate \
  --scenario refuse
```

The local handlers are synthetic. They do not call real filesystems, databases,
IAM providers, export destinations, or payment providers.

## CLI Wrapper

Print the native wrapper shape:

```bash
actenon-kernel mcp wrap --tool filesystem.delete
```

The output keeps domain fields in the tool schema and proof in FastMCP request
metadata.

## Boundary

Verifying proof in the agent or SDK is insufficient. The MCP handler is the
component that can cause the side effect, so it must independently verify the
proof and exact domain arguments.

The adapter does not block alternate provider paths. Remove standing production
credentials from the agent runtime and route consequential actions through the
protected handler.

See [Framework Adapters](FRAMEWORK_ADAPTERS.md),
[Preflight Evidence](PREFLIGHT_EVIDENCE.md), and
[Credential Broker Deployment](CREDENTIAL_BROKER_DEPLOYMENT.md).
