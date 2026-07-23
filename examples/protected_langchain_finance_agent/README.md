# Protected LangChain Finance Agent Example

This example demonstrates a LangChain agent that performs financial
operations protected by Actenon proof verification.

## What it shows

- A LangChain finance agent tool wrapped with Actenon protection
- Proof verification inside the tool's `_run` method
- Receipt/Refusal artefacts returned to the agent

## Running

```bash
cd examples/protected_langchain_finance_agent
python protected_langchain_finance_agent.py --mode direct
```

## Files

- `protected_langchain_finance_agent.py` — the protected agent tool
- `test_protected_langchain_finance_agent.py` — tests
