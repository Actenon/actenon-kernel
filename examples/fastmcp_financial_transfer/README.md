# FastMCP Financial Transfer Example

This example demonstrates proof-bound execution of a financial transfer
through an MCP server tool, using the FastMCP framework.

## What it shows

- An MCP server tool that performs a financial transfer
- Actenon proof verification at the tool boundary (inside the tool handler,
  not in orchestration)
- Canonical Receipt or Refusal artefacts returned from the tool

## Running

```bash
cd examples/fastmcp_financial_transfer
python mcp_server.py --mode direct
```

## Files

- `mcp_server.py` — the MCP server with a protected transfer tool
- `test_fastmcp_financial_transfer.py` — tests
