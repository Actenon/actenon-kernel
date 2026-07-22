# OpenAI Agents SDK Protected Tool Example

This example shows how to wrap a protected action as an OpenAI Agents SDK tool without introducing any hosted control plane.

It uses the repository's local proof mode:

1. load or generate a local Action Intent and PCCB
2. verify proof inside the tool before any protected action runs
3. execute the protected hello-world action only after verification
4. return a canonical receipt on success or a refusal plus refused receipt on failure

## Files

- `app.py`
- `requirements.txt`
- `artifacts/` after the first run

## Install

```bash
cd examples/openai_agents_sdk_protected_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Without Network

This path does not require `OPENAI_API_KEY`. It executes the exact protected tool logic directly.

```bash
python3 app.py --mode direct
```

## Run Through The OpenAI Agents SDK

This path requires `OPENAI_API_KEY` because it actually runs an agent.

```bash
export OPENAI_API_KEY=...
python3 app.py --mode agent
```

## Where Verification Happens

Proof verification happens inside `protected_hello_tool_impl`, before the protected hello-world action executes:

- `examples/openai_agents_sdk_protected_tool/app.py`
- `examples/integration_support.py`

## Receipt And Refusal Handling

The tool returns JSON with:

- `protected_response` and `receipt` on success
- `refusal` and refused `receipt` when verification or execution is blocked

Outcome artifacts are also written locally under:

- `examples/openai_agents_sdk_protected_tool/artifacts/outcomes/receipts/`
- `examples/openai_agents_sdk_protected_tool/artifacts/outcomes/refusals/`

## Boundary

This example demonstrates verifier-edge protection only. It does not add orchestration, approval routing, or any hosted execution service.
