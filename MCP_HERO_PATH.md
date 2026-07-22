# MCP Hero Path

The canonical MCP hero path guide now lives at:

- [docs/guides/MCP_HERO_PATH.md](docs/guides/MCP_HERO_PATH.md)

The short version:

```text
agent -> domain-only MCP tool call -> Actenon proof gate -> tool executes/refuses
```

Use the local example at:

- [examples/mcp_server_protected_tool/README.md](examples/mcp_server_protected_tool/README.md)

Proof is attached through MCP request metadata, not exposed as a tool argument.
