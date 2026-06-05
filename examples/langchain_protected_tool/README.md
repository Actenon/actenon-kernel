# LangChain Protected Tool Example

This example shows the highest-leverage framework integration pattern for the OSS kernel: the LangChain tool itself is the protected execution edge.

Why this example matters:

- many agent applications express consequential actions as framework tools
- that makes the tool execution path the real trust boundary
- the example shows how to keep Actenon's verifier checks inside that boundary instead of in an upstream orchestrator
- it returns the kernel's canonical Receipt and Refusal artifacts without adding a hosted layer

Read the problem definition first if you are new to the repository:

- [../../THE_EXECUTION_GAP.md](../../THE_EXECUTION_GAP.md)
- [../../spec/protected-endpoint/SPEC.md](../../spec/protected-endpoint/SPEC.md)

## Where The Protected Endpoint Sits

In this example, the protected endpoint is not a web route or a separate gateway. It is the LangChain tool implementation itself:

- `examples/langchain_protected_tool/tool.py`
- specifically `ProtectedHelloLangChainTool._run(...)`

That is the point that can cause a consequential action. So that is where proof verification must happen.

## Why Verification Belongs Inside `_run`

If proof is verified upstream but the tool can still execute without re-checking the exact Action Intent and PCCB, the framework boundary is not protected.

This example keeps the ordering correct:

1. parse or load the Action Intent and PCCB
2. verify proof inside `_run`
3. execute the protected action only after verification succeeds
4. return a Receipt on success or a structured Refusal on failure

That is the pattern to copy into a real LangChain integration.

## Files

- `tool.py`
- `requirements.txt`
- `artifacts/` after the first run

## Install

LangChain currently requires Python `3.10+`.

```bash
cd /absolute/path/to/repo
make install
bash ./scripts/first_run.sh
cd examples/langchain_protected_tool
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Without An LLM

This is the recommended first run. It invokes the LangChain tool directly and does not require network access or model credentials.

Success path:

```bash
python3 tool.py --mode direct
```

Audience-mismatch refusal path:

```bash
python3 tool.py --mode direct --scenario audience-mismatch
```

## Optional Agent-Driven Mode

This mode is intentionally minimal. It is only here to show that the same protected tool can sit behind a LangChain agent loop without moving verification upstream.

It requires a provider-backed LangChain model string and matching credentials. The default example uses OpenAI-style credentials:

```bash
export OPENAI_API_KEY=...
python3 tool.py --mode agent --model openai:gpt-4.1-mini
```

For deterministic success and refusal inspection, prefer direct mode.

## What Success Looks Like

The tool returns JSON with:

- `ok: true`
- `protected_response`
- `receipt`

The receipt is the canonical Actenon execution Receipt. Local artifact copies are also written under:

- `examples/langchain_protected_tool/artifacts/outcomes/receipts/`

## What Failure Looks Like

When verification blocks execution, the tool returns JSON with:

- `ok: false`
- `refusal`
- refused `receipt` when the Action Intent and PCCB parsed successfully

If the caller sends malformed JSON that cannot be parsed into the public contracts, the tool still returns a structured Refusal. In that case no receipt is emitted because the tool could not bind execution to a valid Action Intent.

Refusal artifacts are written locally under:

- `examples/langchain_protected_tool/artifacts/outcomes/refusals/`

## Boundary

This is an OSS verifier-edge integration example only.

It does not add:

- approval logic
- provider runtime operations
- orchestration control planes
- hosted execution services

The example exists to show exactly where proof verification, Receipt emission, and Refusal emission belong in a LangChain tool path.
