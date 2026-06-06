# LangChain Protected Tool

This example wraps a plain domain function as a LangChain `StructuredTool`.
The model-facing schema contains only:

- `amount_minor`
- `currency`
- `destination`

Proof is attached at invocation through `RunnableConfig`, not through tool
arguments:

```python
tool = protected_structured_tool(
    gate,
    release_payout,
    action_builder=build_payout_intent,
    audience="service:langchain-payout-tool",
)

result = tool.invoke(
    {
        "amount_minor": 1250,
        "currency": "USD",
        "destination": "bank:demo-approved",
    },
    config=actenon_runnable_config(proof),
)
```

The model cannot see, choose, rewrite, or hallucinate `intent_json` or
`pccb_json` because neither field exists in `tool.args`. Actenon rebuilds the
exact Action Intent from validated domain arguments at execution time.

## Run

```bash
python3 -m pip install -e ".[asymmetric,langchain]"
python3 examples/langchain_protected_tool/tool.py --scenario success
python3 examples/langchain_protected_tool/tool.py --scenario mismatch
python3 examples/langchain_protected_tool/tool.py --scenario missing-proof
```

All payouts are local simulations. No LLM, network call, model credential, or
payment provider is required.
