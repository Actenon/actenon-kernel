# Framework Adapters

Actenon's native adapters keep proof material out of model-facing and
domain-facing schemas. The protected endpoint reconstructs the exact Action
Intent from validated domain fields, obtains proof from framework runtime
context, and calls `ActenonGate.protect(...)` immediately before the side
effect.

## Install

Install only the adapters used by the application:

```bash
python -m pip install "actenon-kernel[fastapi]"
python -m pip install "actenon-kernel[langchain]"
python -m pip install "actenon-kernel[mcp]"
```

Core installation does not pull in any framework dependency. Importing an
adapter without its extra raises an `ImportError` that names the required
extra.

## FastAPI

The request body remains domain-only. Proof is base64url-encoded JSON in
`X-Actenon-Proof`; optional local Preflight evidence may use
`X-Actenon-Evidence`.

```python
from fastapi import Depends

protected_payout = gate.fastapi_dependency(
    audience="service:payout-api",
    action_builder=build_payout_intent,
    side_effect=release_payout,
    body_model=PayoutRequest,
)

@app.post("/payouts")
def payout(body: PayoutRequest, outcome=Depends(protected_payout)):
    return outcome.to_dict()
```

The adapter validates `body_model` before proof-gated execution. The dependency
then executes before the route handler. A refusal raises HTTP `403`
with the canonical Refusal, refused Receipt, and Preflight
`unmet_requirements`. The route handler and side effect are not reached on
refusal.

## LangChain

`protected_structured_tool` infers the model schema from a plain domain
function. Proof is supplied through `RunnableConfig.configurable`, which
LangChain does not include in `tool.args`.

```python
tool = protected_structured_tool(
    gate,
    release_payout,
    action_builder=build_payout_intent,
)

result = tool.invoke(
    {"amount_minor": 1250, "destination": "bank:approved"},
    config=actenon_runnable_config(proof),
)
```

Do not add `intent_json`, `pccb_json`, or proof fields to the Pydantic tool
schema. The model should select domain arguments, not authorization material.

## FastMCP

`protected_mcp_tool` reads proof from MCP request metadata. The wrapped function
declares FastMCP's injected `Context`; FastMCP omits that parameter from the
published tool schema.

```python
@mcp.tool(name="payout.release")
@protected_mcp_tool(gate, action_builder=build_payout_intent)
def release_payout(amount_minor: int, destination: str, ctx: Context):
    return provider.release(amount_minor, destination)
```

Attach runtime metadata with:

```python
meta = mcp_authorization_meta(proof, evidence={"change_ticket": "CHG-2026-0042"})
```

The current MCP decorator supports synchronous FastMCP tool functions. It fails
at setup for coroutine functions rather than creating a Receipt before an
awaited side effect has completed.

## Security Boundary

Out-of-band means outside the model-facing tool schema. It does not make a PCCB
secret or automatically trusted. Each adapter still verifies the signature,
exact action, parameters, target, audience, tenant, subject, expiry, policy,
and replay state at the protected execution boundary.

Framework adapters do not protect alternate routes that bypass the wrapped
endpoint or tool. Remove standing provider credentials from the agent path and
route consequential actions through the protected boundary.

For resource-owner adoption across framework boundaries, use the hardened
[`ProtectedEdge`](EDGE_DEPLOYMENT.md) adapter. It binds the complete raw request
before proof verification and gives the backend only the verified intent and a
brokered credential.
