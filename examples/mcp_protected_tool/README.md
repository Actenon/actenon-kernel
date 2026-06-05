# Minimal MCP Protected Tool

This is the smallest local Actenon adoption example for an MCP-style tool
handler.

It does not require an MCP client, network, Cloud account, hosted service, or
real filesystem mutation. It models the important boundary:

```text
agent -> MCP tool call -> Actenon proof gate -> tool executes/refuses -> Receipt/Refusal emitted
```

## Run It

From the repository root:

```bash
python3 -m examples.mcp_protected_tool.demo --scenario missing-proof
python3 -m examples.mcp_protected_tool.demo --scenario allow
```

The missing-proof path refuses before the handler runs:

```text
Outcome: REFUSED
Handler called: false
Side effect executed: false
Refusal code: PCCB_REQUIRED
```

The allowed path verifies a local demo PCCB before the simulated side effect:

```text
Outcome: ALLOWED
Handler called: true
Side effect executed: true
Receipt outcome: executed
```

Artifacts are written under:

```text
artifacts/mcp_protected_tool/outcomes/
```

## Three-Line Integration Shape

Use the actual kernel API:

```python
from actenon.execution import ProtectedExecutor

protected = ProtectedExecutor(proof_verifier=verifier, credential_broker=broker, outcome_writer=writer)
result = protected.execute(request, consequential_tool_handler, policy_decision=policy_decision)
```

The MCP handler should build `request` from the Action Intent, PCCB, and local
verifier context for that exact tool boundary.

## What To Copy

- Keep proof verification inside the MCP tool handler, not only in the agent.
- Refuse missing or mismatched proof before the side-effect handler runs.
- Broker credentials only after proof and policy pass.
- Emit a Receipt on allow and a Refusal plus refused Receipt on block.
- Keep scanner findings as adoption cues: when scanner finds MCP tool side
  effects, wrap those handlers with the protected executor.

For the fuller five-tool example, see
[examples/mcp_server_protected_tool](../mcp_server_protected_tool/README.md).

