# MCP Quickstart

MCP tools are where agent decisions meet real actions. Actenon belongs at that
tool execution boundary: no valid proof, no side effect, and every allow/refuse
decision leaves a Receipt or Refusal artifact.

This guide is local-only. It does not require Actenon Cloud, a hosted gateway,
or a live MCP server.

## The Execution Gap

An unprotected MCP handler lets a model-selected tool call reach the side
effect directly:

```python
# Unprotected sketch: do not copy for consequential tools.
@server.tool("filesystem.delete")
def filesystem_delete(path: str) -> dict[str, str]:
    delete_path(path)
    return {"state": "deleted"}
```

For consequential tools, put Actenon between the tool call and the side effect:

```python
from actenon.execution import ProtectedExecutor

protected = ProtectedExecutor(proof_verifier=verifier, credential_broker=broker, outcome_writer=writer)
result = protected.execute(request, filesystem_delete_handler, policy_decision=policy_decision)
```

The protected handler receives a brokered credential reference only after the
Action Intent and PCCB verify for the exact MCP tool audience, action, target,
scope, parameters, expiry, and nonce.

## Run The Minimal Example

From the repository root:

```bash
python3 -m examples.mcp_protected_tool.demo --scenario missing-proof
python3 -m examples.mcp_protected_tool.demo --scenario allow
```

The missing-proof path refuses before the simulated tool handler runs:

```text
Outcome: REFUSED
Handler called: false
Side effect executed: false
Refusal code: PCCB_REQUIRED
Receipt outcome: refused
```

The allowed path verifies proof, brokers a local credential reference, runs the
simulated side effect, and emits an execution Receipt:

```text
Outcome: ALLOWED
Handler called: true
Side effect executed: true
Receipt outcome: executed
```

Artifacts are written locally under:

```text
artifacts/mcp_protected_tool/outcomes/receipts/
artifacts/mcp_protected_tool/outcomes/refusals/
```

## What The MCP Handler Should Do

1. Accept tool arguments plus an Action Intent and PCCB.
2. Build verifier context for the MCP tool server, not the agent.
3. Verify proof at the final tool handler before the side effect.
4. Run Preflight or endpoint policy where needed.
5. Broker credentials only after proof and policy pass.
6. Execute or refuse.
7. Emit Receipt/Refusal artifacts.

## Scanner-To-MCP Bridge

When scanner finds MCP tool side effects, wrap those handlers with the protected
executor.

Scanner output such as `MCP_TOOL_SIDE_EFFECT`, `FILE_MUTATION_SIDE_EFFECT`,
`EXTERNAL_API_SIDE_EFFECT`, or `CREDENTIAL_AUTHORITY_SIGNAL` should lead a
maintainer to ask:

```text
Can a model-selected MCP tool call reach this side effect before proof,
policy, credential brokering, replay/idempotency, and Receipt/Refusal emission?
```

If yes, move the side effect behind `ProtectedExecutor` or an equivalent
protected execution boundary.

## What This Does Not Claim

- It does not prove the upstream business decision was correct.
- It does not prove downstream provider finality.
- It does not protect side-door calls where the agent still holds raw
  production credentials.
- It does not require or imply a hosted Actenon service.

## Related Docs

- [Minimal MCP protected tool example](../../examples/mcp_protected_tool/README.md)
- [Full MCP hero path](../guides/MCP_HERO_PATH.md)
- [Credential Broker deployment](../guides/CREDENTIAL_BROKER_DEPLOYMENT.md)
- [Scanner methodology](../guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md)

