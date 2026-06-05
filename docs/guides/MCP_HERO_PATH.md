# MCP Hero Path

Actenon should sit where the MCP tool can actually cause the side effect.

```text
agent -> MCP tool call -> Actenon proof gate -> tool executes/refuses -> VAR emitted
```

This guide is local-only. It does not require Actenon Cloud, a hosted gateway,
or a hosted approval service.

If you want the smallest copyable version first, start with the
[MCP quickstart](../integrations/MCP_QUICKSTART.md) and
[minimal protected-tool example](../../examples/mcp_protected_tool/README.md).

## The Pattern

For a consequential MCP tool, the MCP handler should be the protected execution
edge:

1. The agent sends an MCP tool call with an Action Intent and PCCB.
2. The MCP handler parses the Action Intent and PCCB.
3. The handler builds verifier context for its own MCP tool audience.
4. Actenon verifies exact proof binding before any side effect.
5. Preflight or endpoint policy runs before credential brokering.
6. The Credential Broker issues a short-lived reference only after allow.
7. The tool executes or refuses.
8. The handler emits the VAR surface: a canonical Receipt, and a linked Refusal
   when execution is blocked.

That is the boundary to copy. Do not put proof verification only in the agent
or orchestrator. The tool handler is the component that can delete files, apply
migrations, grant IAM roles, export data, or release payments.

## Consequential Tool Examples

The local example covers:

| MCP tool | Actenon capability |
| --- | --- |
| `filesystem.delete` | `infrastructure.delete` |
| `database.migrate` | `migration.apply` |
| `iam.grant` | `iam.permission.grant` |
| `data.export` | `data.export` |
| `payment.release` | `payment.release` |

The tool names are MCP-facing names. The capability is what Actenon binds into
the Action Intent, proof scope, Preflight decision, Credential Broker scope, and
Receipt.

## Run The Local Example

From the repository root:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool filesystem.delete \
  --scenario allow
```

Run a refusal path:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool database.migrate \
  --scenario refuse
```

Run the proof-required path:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool payment.release \
  --scenario missing-proof
```

The demo prints the flow and writes artifacts under:

```text
examples/mcp_server_protected_tool/artifacts/
```

The simulated handlers do not delete real files, migrate real databases, grant
real IAM permissions, export real data, or release real payments.

## Run The MCP Server

Install the optional MCP package:

```bash
cd examples/mcp_server_protected_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

The server registers one protected MCP handler per consequential tool. Each
handler accepts:

- `intent_json`
- `pccb_json`
- `preflight_evidence_json`

If `intent_json` and `pccb_json` are both omitted, the handler generates a local
allow fixture so developers can inspect the successful path quickly. A real
deployment should pass the Action Intent and PCCB from its issuer path.

## CLI Wrapper Helper

Use the optional helper to print a wrapper pattern:

```bash
actenon mcp wrap --tool filesystem.delete
```

Emit JSON:

```bash
actenon mcp wrap --tool data.export --json
```

The helper does not mutate source files. It prints the proof-gate sequence,
required MCP inputs, and a small Python wrapper shape.

## Minimal Wrapper Shape

```python
from examples.mcp_server_protected_tool.proof_gate import invoke_protected_tool


def filesystem_delete(intent_json: str, pccb_json: str, preflight_evidence_json: str | None = None):
    outcome = invoke_protected_tool(
        "filesystem.delete",
        intent_payload=intent_json,
        pccb_payload=pccb_json,
        preflight_evidence=preflight_evidence_json,
    )
    return outcome.to_dict()
```

In a production MCP server, replace the simulated side-effect handler with the
real filesystem, database, IAM, export, or payment adapter. Keep the Actenon
proof gate immediately before that adapter and keep raw credentials out of the
agent runtime.

## What Preflight Does Here

Preflight is local policy before execution. In the example:

- sandbox actions are allowed
- production destructive actions require evidence such as a change ticket
- broad or sensitive exports require approval
- admin or wildcard grants require approval

Preflight does not replace proof verification. The MCP handler still verifies
the PCCB, exact action binding, audience, target, capability, expiry, and
signature before the Credential Broker issues execution authority.

## What The Credential Broker Does Here

The Credential Broker keeps consequential authority at the protected endpoint.
The agent asks for a tool call. The handler verifies proof and policy. Only then
does the broker issue a short-lived local credential reference to the handler.

The Receipt records the public-safe reference. It does not record raw credential
material.

## What VAR Emission Means Here

VAR means Verifiable Action Receipt. In this local kernel example:

- executed tools emit an execution Receipt
- refused tools emit a Refusal plus a refused Receipt
- a small local `var/` pointer records which Receipt is the emitted VAR surface
- all artifacts remain local

This does not claim hosted anchoring, provider finality, or that the upstream
business decision was inherently correct.

## Common Mistakes

- Verifying proof in the agent but not in the MCP tool handler.
- Letting an MCP handler execute with parameters that differ from the Action
  Intent and PCCB.
- Treating Preflight as a substitute for proof verification.
- Giving the agent a standing production credential and calling the MCP wrapper
  voluntary.
- Returning ad hoc errors instead of a Refusal plus refused Receipt.

## Reference Files

- [MCP quickstart](../integrations/MCP_QUICKSTART.md)
- [Minimal MCP protected tool](../../examples/mcp_protected_tool/README.md)
- [MCP server example](../../examples/mcp_server_protected_tool/README.md)
- [Proof gate implementation](../../examples/mcp_server_protected_tool/proof_gate.py)
- [MCP server transport](../../examples/mcp_server_protected_tool/server.py)
- [Preflight guide](./PREFLIGHT.md)
- [Credential Broker deployment](./CREDENTIAL_BROKER_DEPLOYMENT.md)
- [Protected endpoint spec](../../spec/protected-endpoint/SPEC.md)
