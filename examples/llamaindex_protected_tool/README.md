# LlamaIndex Protected Tool Example

This example shows the second high-leverage framework pattern for the OSS kernel: a plain Python function wrapped as a LlamaIndex tool, with the function itself remaining the protected execution edge.

Why this framework matters strategically:

- LlamaIndex is widely used for agent and retrieval-driven Python applications
- those applications often expose consequential actions as wrapped Python functions
- that makes it easy to accidentally move trust decisions upstream unless proof verification stays inside the wrapped function

If you are new to the kernel boundary, start here:

- [../../THE_EXECUTION_GAP.md](../../THE_EXECUTION_GAP.md)
- [../../spec/protected-endpoint/SPEC.md](../../spec/protected-endpoint/SPEC.md)

## Where The Execution Edge Is

In this model, the execution edge is not the framework object by itself. It is the wrapped function that can actually trigger a consequential action:

- `examples/llamaindex_protected_tool/tool.py`
- specifically `protected_hello_read(...)`

The `FunctionTool` wrapper exposes that function to LlamaIndex, but the security boundary still lives inside the function body.

## What A Protected Tool Looks Like

The example uses LlamaIndex's native function-wrapper pattern:

```python
tool = FunctionTool.from_defaults(
    fn=protected_hello_read,
    name="protected_hello_read",
    return_direct=True,
)
```

The important part is what `protected_hello_read(...)` does:

1. load or accept an Action Intent and PCCB
2. verify proof inside the wrapped function
3. execute the protected action only after verification succeeds
4. return a Receipt on success or a structured Refusal on failure

That is the pattern to copy into a real LlamaIndex tool path.

## Files

- `tool.py`
- `requirements.txt`
- `artifacts/` after the first run

## Install

`llama-index-core` currently requires Python `3.10+`.

```bash
cd /absolute/path/to/repo
make install
bash ./scripts/first_run.sh
cd examples/llamaindex_protected_tool
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

## What The Tool Returns

On success, the wrapped function returns JSON with:

- `ok: true`
- `protected_response`
- `receipt`

On blocked execution, it returns:

- `ok: false`
- `refusal`
- refused `receipt` when the Action Intent and PCCB parsed successfully

If the caller supplies malformed JSON that cannot be parsed into the public contracts, the example still returns a structured Refusal and does not emit a receipt.

Local artifact copies are written under:

- `examples/llamaindex_protected_tool/artifacts/outcomes/receipts/`
- `examples/llamaindex_protected_tool/artifacts/outcomes/refusals/`

## Boundary

This is an OSS verifier-edge integration example only.

It does not add:

- approval logic
- provider runtime operations
- hosted orchestration
- control-plane features

The example exists to show exactly where proof verification belongs when LlamaIndex turns a Python function into a tool.
