# Claude Managed Agents Protected Tool Example

This example shows the Actenon protected-endpoint pattern on Anthropic's managed agent surface without turning the OSS kernel into an Anthropic-specific control plane.

It is an Anthropic-specific compatibility example, not a partnership signal, not an endorsement claim, and not the repository's primary hero path.

Why this example matters:

- Claude Managed Agents is a high-signal Anthropic surface because it is a managed agent runtime, not just a raw model call
- that makes it a useful place to show the category boundary clearly: orchestration can be hosted, but proof verification still belongs at the execution edge
- the example demonstrates the same kernel rule as the neutral MCP path: the tool that can cause the consequential action must verify proof itself
- MCP still remains the primary hero path in this repository because it is the neutral, ecosystem-wide tool protocol
- this example exists to prove kernel compatibility on one managed platform surface without coupling the kernel to Anthropic-specific hosted behavior

Read these first if you are new to the kernel:

- [../../THE_EXECUTION_GAP.md](../../THE_EXECUTION_GAP.md)
- [../../spec/protected-endpoint/SPEC.md](../../spec/protected-endpoint/SPEC.md)
- [../../CONFORMANCE.md](../../CONFORMANCE.md)
- [../../MCP_HERO_PATH.md](../../MCP_HERO_PATH.md)

## Where The Protected Execution Edge Sits

In this example, the protected execution edge is the custom tool implementation in:

- `examples/claude_managed_agents_protected_tool/tool.py`
- specifically `protected_hello_tool_impl(...)`

Anthropic's managed agent may decide when to call the tool, but it is not the trust boundary. The tool is the place that can actually perform the protected action, so the tool is where verification must happen.

That boundary is what makes the example kernel-compatible rather than platform-defined: Anthropic-specific orchestration may vary, but the verifier-first execution rule stays the same.

## Why Verification Belongs Inside The Tool Boundary

Managed planning does not bind execution.

If proof is checked in an upstream planner, session bootstrapper, or approval wrapper, but the tool can still run without re-verifying the exact Action Intent and PCCB at call time, the real execution boundary is unprotected.

This example keeps the ordering correct:

1. the managed agent requests the custom tool
2. the custom tool loads or parses the Action Intent and PCCB
3. the custom tool verifies proof inside the execution path
4. the protected action executes only after verification succeeds
5. the tool returns a canonical Receipt on success or a structured Refusal on blocked execution

That is the pattern to preserve on Anthropic's managed surface.

## Anthropic Beta Positioning

Claude Managed Agents is currently an Anthropic-managed beta surface.

- the Anthropic Python SDK uses `client.beta.*` managed-agents methods for this surface
- this example does not make Actenon depend on Anthropic-specific approval, policy, or hosted control-plane behavior
- the managed mode is here to show the boundary on a real Anthropic agent surface, not to replace the repository's neutral MCP-first launch hierarchy
- this example should not be read as partnership, endorsement, or product-coupling language

## Files

- `tool.py`
- `requirements.txt`
- `artifacts/` after the first local run

## Install

```bash
cd /absolute/path/to/repo
make install
bash ./scripts/first_run.sh
cd examples/claude_managed_agents_protected_tool
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run In Local Direct Mode

This is the recommended first run. It does not require Anthropic credentials or network access. It proves the protected-tool pattern before you involve any provider-managed runtime.

Success path:

```bash
python3 tool.py --mode direct
```

Audience-mismatch refusal path:

```bash
python3 tool.py --mode direct --scenario audience-mismatch
```

## Run Through Claude Managed Agents

This path exercises Anthropic's managed beta surface while keeping verification in the tool implementation.

Use this mode only after the direct path. The managed path is strategically useful because it shows the same protected-endpoint rule on a real Anthropic surface, but it is still secondary to the neutral MCP story in this repository.

What you need first:

- `ANTHROPIC_API_KEY`
- an Anthropic Managed Agents environment ID passed with `--environment-id` or set as `ANTHROPIC_MANAGED_AGENTS_ENVIRONMENT_ID`

The example assumes that environment setup already exists. Anthropic runtime configuration is outside the kernel example.

Success path:

```bash
export ANTHROPIC_API_KEY=...
export ANTHROPIC_MANAGED_AGENTS_ENVIRONMENT_ID=env_...
python3 tool.py --mode managed
```

Audience-mismatch refusal path:

```bash
python3 tool.py --mode managed --scenario audience-mismatch
```

The managed mode creates an example agent when needed, runs one session, handles the `agent.custom_tool_use` to `user.custom_tool_result` handshake locally, and then cleans up the temporary session and example-created agent unless you pass `--keep-session` or `--keep-agent`.

## What Success Looks Like

Direct mode prints the raw protected-tool result. Managed mode prints the Anthropic session metadata plus the raw tool invocation result.

The successful tool result contains:

- `ok: true`
- `protected_response`
- `receipt`

That receipt is the canonical Actenon execution Receipt. Local artifact copies are also written under:

- `examples/claude_managed_agents_protected_tool/artifacts/outcomes/receipts/`

## What Failure Looks Like

When verification blocks execution, the tool returns:

- `ok: false`
- `refusal`
- a refused `receipt` when the Action Intent and PCCB were valid enough to bind execution before the refusal

In this example the deterministic refusal path is `audience-mismatch`, which shows that a managed agent having a plan is not enough. The protected tool still rejects execution when the proof does not bind to the audience at the real execution edge.

Refusal artifacts are written locally under:

- `examples/claude_managed_agents_protected_tool/artifacts/outcomes/refusals/`

## What Stays Outside This Example

This is an OSS kernel integration example only.

It does not add:

- proof minting workflows
- approval workflows
- evidence collection
- policy editing
- reconciliation operations
- provider runtime services
- tenant administration
- operational dashboards

The example exists to show the verifier-first execution-edge boundary on Anthropic's managed agent surface, while keeping the repository's public abstraction neutral and MCP-first.
