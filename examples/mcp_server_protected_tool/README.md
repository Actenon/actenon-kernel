# MCP Server Protected Tool Example

This example makes Actenon the execution gate for consequential MCP tools.

It stays fully local:

- no hosted dependency
- no Actenon Cloud dependency
- no real filesystem, database, IAM, data export, or payment side effects

The simulated MCP tools are:

- `filesystem.delete`
- `database.migrate`
- `iam.grant`
- `data.export`
- `payment.release`

## Hero Flow

```text
agent
  -> MCP tool call
  -> Actenon proof gate
  -> tool executes/refuses
  -> VAR emitted
```

In this local example, VAR means the canonical Verifiable Action Receipt surface.
An executed tool emits an execution Receipt. A refused tool emits a Refusal plus
a refused Receipt that links to that Refusal.

## Files

- `server.py`: MCP server transport and tool registration
- `proof_gate.py`: reusable proof-gate wrapper for each consequential tool
- `demo.py`: local runner that exercises the same wrapper without an MCP client
- `requirements.txt`: optional MCP Python package dependency

Generated artifacts are written under:

- `examples/mcp_server_protected_tool/artifacts/outcomes/receipts/`
- `examples/mcp_server_protected_tool/artifacts/outcomes/refusals/`
- `examples/mcp_server_protected_tool/artifacts/var/`

## Run Locally Without MCP

From the repository root:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool filesystem.delete \
  --scenario allow
```

That prints:

```text
Flow: agent -> MCP tool call -> Actenon proof gate -> tool executes/refuses -> VAR emitted
Preflight: allow (...)
Outcome: executed
VAR: receipt ...
```

Run a refusal path:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool database.migrate \
  --scenario refuse
```

That path uses a production migration Action Intent without the required change
ticket evidence. The MCP proof gate verifies the proof, runs local Preflight
policy, refuses before the simulated migration handler receives a credential,
and emits a Refusal plus refused Receipt.

Run the proof-missing path:

```bash
python3 -m examples.mcp_server_protected_tool.demo \
  --tool payment.release \
  --scenario missing-proof
```

That path refuses with `PCCB_REQUIRED`.

## Run As An MCP Server

Install the optional MCP package:

```bash
cd examples/mcp_server_protected_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

`FastMCP` uses stdio by default. The server registers one protected handler per
consequential tool.

Each handler accepts:

- `intent_json`: Action Intent JSON
- `pccb_json`: PCCB JSON
- `preflight_evidence_json`: optional local evidence context JSON

If `intent_json` and `pccb_json` are both omitted, the handler generates a local
allow fixture so you can inspect the successful Receipt path quickly. Real MCP
deployments should pass the Action Intent and PCCB from their issuer path.

## What To Copy

Copy the proof-gate placement, not the simulated side effects:

1. Receive the Action Intent, PCCB, and optional Preflight evidence with the MCP
   tool call.
2. Parse and validate the Action Intent and PCCB.
3. Build verifier context for the MCP tool audience.
4. Verify exact proof binding inside the MCP tool handler.
5. Run Preflight or endpoint policy before brokering authority.
6. Acquire a short-lived Credential Broker reference only after verification and
   policy pass.
7. Execute the real side effect or refuse.
8. Emit a Receipt on execution, or a Refusal plus refused Receipt when blocked.

The key file is `proof_gate.py`, especially `invoke_protected_tool`.

## Why The Credential Broker Is In The Example

The agent should not hold standing production credentials for consequential
systems. In this example the handler receives only a brokered local credential
reference after proof verification and Preflight allow. The Receipt records the
public-safe `secret_reference`; it never records raw credential material.

## What This Does Not Claim

This example does not claim that:

- the upstream business decision was correct
- a real provider side effect reached finality
- the simulated handler is a production adapter
- side-door execution is blocked if an agent still has standing credentials
- Actenon Cloud or any hosted service is involved

It demonstrates the local proof-gate pattern for MCP tool handlers.

## More Context

- [MCP hero path guide](../../docs/guides/MCP_HERO_PATH.md)
- [Preflight guide](../../docs/guides/PREFLIGHT.md)
- [Credential Broker deployment guide](../../docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md)
- [Execution gap scanner remediation](../../docs/guides/SCANNER_REMEDIATION.md)

