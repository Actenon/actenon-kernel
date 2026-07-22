# Semantic Kernel Protected Tool Example

This example shows the Semantic Kernel Python plugin pattern for the OSS kernel: a plugin class with a `@kernel_function` method whose method body is the protected execution edge.

Why Semantic Kernel matters:

- it is a strategic framework in enterprise Microsoft-aligned environments
- it is used across agent, plugin, and orchestration scenarios where tool boundaries can get abstracted away behind framework plumbing
- that makes it important to show clearly that proof verification still belongs inside the plugin function that can actually trigger the protected action

If you are new to the kernel boundary, start here:

- [../../THE_EXECUTION_GAP.md](../../THE_EXECUTION_GAP.md)
- [../../spec/protected-endpoint/SPEC.md](../../spec/protected-endpoint/SPEC.md)

## Where The Protected Boundary Is

In this example, the protected boundary lives in the plugin function itself:

- `examples/semantic_kernel_protected_tool/tool.py`
- specifically `ProtectedHelloPlugin.protected_hello_read(...)`

The plugin is registered on a `Kernel`, but registration is not the security boundary. The method body is.

## What A Protected Semantic Kernel Function Looks Like

The example uses Semantic Kernel's Python plugin/function style:

```python
class ProtectedHelloPlugin:
    @kernel_function(name="protected_hello_read", description="...")
    def protected_hello_read(...) -> str:
        # verify proof here
        # execute only after verification succeeds
        # return Receipt or Refusal artifacts
```

The function returns JSON text so the protected result is easy to inspect in a local run and easy to surface through a tool-calling flow.

## How This Generalizes

This example is Python-only, but the architectural rule generalizes across Semantic Kernel language SDKs:

- the plugin or native function that can trigger the consequential action is the execution edge
- proof verification must happen inside that function body
- upstream orchestration, planning, or prompt flow is not a substitute for verifier-side checks at execution time

That principle is the same whether the surrounding Semantic Kernel application is Python-first, .NET-heavy, or mixed-language.

## Files

- `tool.py`
- `requirements.txt`
- `artifacts/` after the first run

## Install

Semantic Kernel currently documents Python `3.10+`.

```bash
cd /absolute/path/to/repo
make install
bash ./scripts/first_run.sh
cd examples/semantic_kernel_protected_tool
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run The Example

Success path:

```bash
python3 tool.py
```

Audience-mismatch refusal path:

```bash
python3 tool.py --scenario audience-mismatch
```

## What The Function Returns

On success, the function returns JSON with:

- `ok: true`
- `protected_response`
- `receipt`

On blocked execution, it returns:

- `ok: false`
- `refusal`
- refused `receipt` when the Action Intent and PCCB parsed successfully

If malformed JSON is supplied, the function still returns a structured schema refusal and does not emit a receipt.

Local artifact copies are written under:

- `examples/semantic_kernel_protected_tool/artifacts/outcomes/receipts/`
- `examples/semantic_kernel_protected_tool/artifacts/outcomes/refusals/`

## Boundary

This is an OSS verifier-edge example only.

It does not add:

- hosted orchestration services
- provider runtime operations
- approval logic
- control-plane features

The example exists to show that Semantic Kernel plugin registration does not move the proof boundary upstream. The function that can act must verify before it acts.
