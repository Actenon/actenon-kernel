# Integrations

This page is the root index for adopting the OSS kernel from current agent and application stacks.

Use these examples when you want to keep proof verification at the protected edge without pulling this repository into orchestration or a hosted control plane.

Not every example here carries the same strategic weight. The current framework and platform sequence is:

1. MCP
2. LangChain
3. Claude Managed Agents
4. LlamaIndex
5. CrewAI
6. Semantic Kernel

That sequence is intentional:

- MCP is the neutral hero path for the repository
- Claude Managed Agents is a strong Anthropic-specific secondary path
- the remaining framework examples support category distribution and adoption, but they are not equal launch stories

If you are starting from the repo root, the cleanest sequence is:

1. [QUICKSTART.md](QUICKSTART.md)
2. [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
3. [TRACE_VIEWER.md](TRACE_VIEWER.md)
4. [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
5. then choose the integration or SDK path below

If your integration includes delegated tools or cooperating agents, read [MULTI_AGENT_EXECUTION_MODEL.md](MULTI_AGENT_EXECUTION_MODEL.md) before treating orchestration state, approvals, or forwarded proof as execution authority.

## Inspect Before You Integrate

If you have just run the kernel locally, use the trace viewer before choosing a framework path:

- [TRACE_VIEWER.md](TRACE_VIEWER.md)
- [docs/guides/TRACE_VIEWER_LOCAL.md](docs/guides/TRACE_VIEWER_LOCAL.md)

That viewer helps you inspect:

- Action Intent
- PCCB
- Receipt
- Refusal
- replay entries
- protected-endpoint state

It is a local read-only viewer for kernel artifacts, not the operational product.

## Recommended Agent-Tool Path

If you are choosing one agent-tool example to evaluate first, start with the protected MCP tool path:

- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [examples/mcp_server_protected_tool/README.md](examples/mcp_server_protected_tool/README.md)

That path is strategically important because it shows the core model in a neutral tool protocol:

- proof verification happens inside the tool implementation, not in an upstream workflow
- the protected tool returns canonical Receipt and Refusal artifacts
- the example stays fully local and does not depend on a hosted control plane
- the same execution-edge pattern maps cleanly into other agent and app stacks

## Strategic Framework Order

### 1. MCP

Why this matters: it is the clearest neutral protected-tool story in the repo and the strongest category-distribution path because it is not tied to one hosted platform.

### 2. LangChain

Why this matters: many consequential agent actions are exposed as framework tools, so LangChain is the first framework-specific place where the protected execution boundary has to survive abstraction.

### 3. Claude Managed Agents

Why this matters: it is a high-signal Anthropic-specific platform example that demonstrates the same execution-edge rule on a managed agent surface without replacing MCP as the hero path or coupling the kernel to Anthropic-specific hosted behavior.

### 4. LlamaIndex

Why this matters: it shows that even function-wrapper abstractions in a widely used retrieval-and-agent framework still need proof verification at the wrapped execution boundary.

### 5. CrewAI

Why this matters: multi-agent delegation increases the number of execution boundaries in play, so CrewAI is a good example of why proofs must not be casually shared across tool boundaries.

### 6. Semantic Kernel

Why this matters: enterprise Microsoft-aligned teams often use plugin and function abstractions, and the proof boundary must remain in the plugin function that can actually execute.

The examples below follow that order for framework and platform paths. They are useful distribution channels for the category, but only MCP is the primary launch story and only Claude Managed Agents is positioned as a strong secondary platform-specific story.

## Choose Your Starting Point

| If you are integrating into... | Start here | First command | Why |
| --- | --- | --- | --- |
| the smallest possible verifier-first demo | [docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md](docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md) | `python3 -m actenon.demo.portable_local_proof --artifacts-dir artifacts/portable_local_proof` | Fastest way to see a protected endpoint verify proof before execution. |
| an MCP server tool | [examples/mcp_server_protected_tool/README.md](examples/mcp_server_protected_tool/README.md) | `cd examples/mcp_server_protected_tool && python3 server.py` | Strongest tool-integration story in the repo: proof verification happens inside the tool handler, not in orchestration. |
| a LangChain tool | [examples/langchain_protected_tool/README.md](examples/langchain_protected_tool/README.md) | `cd examples/langchain_protected_tool && python3 tool.py --mode direct` | Shows the framework-tool pattern directly: `_run` is the protected endpoint and returns canonical Receipt or Refusal artifacts. |
| a Claude Managed Agents custom tool | [examples/claude_managed_agents_protected_tool/README.md](examples/claude_managed_agents_protected_tool/README.md) | `cd examples/claude_managed_agents_protected_tool && python3 tool.py --mode direct` | Strongest platform-specific follow-on after MCP: shows the same protected-endpoint rule on Anthropic's managed agent surface without changing the repo's neutral hero path or implying hosted control-plane coupling. |
| a LlamaIndex tool | [examples/llamaindex_protected_tool/README.md](examples/llamaindex_protected_tool/README.md) | `cd examples/llamaindex_protected_tool && python3 tool.py` | Shows the native function-wrapper pattern directly: the wrapped function is still the protected endpoint and returns canonical Receipt or Refusal artifacts. |
| a CrewAI tool | [examples/crewai_protected_tool/README.md](examples/crewai_protected_tool/README.md) | `cd examples/crewai_protected_tool && python3 tool.py` | Shows the multi-agent tool boundary directly: `_run` is the protected endpoint, and delegated handoffs do not replace verifier-side checks. |
| a Semantic Kernel plugin function | [examples/semantic_kernel_protected_tool/README.md](examples/semantic_kernel_protected_tool/README.md) | `cd examples/semantic_kernel_protected_tool && python3 tool.py` | Shows the plugin/function boundary directly: the `@kernel_function` method is the protected endpoint and returns canonical Receipt or Refusal artifacts. |
| an existing Python service | [examples/fastapi_protected_route/README.md](examples/fastapi_protected_route/README.md) | `cd examples/fastapi_protected_route && uvicorn app:app --reload` | Shows a real protected route with receipt and refusal handling. |
| an existing Node or TypeScript service | [examples/express_protected_route/README.md](examples/express_protected_route/README.md) | `cd examples/express_protected_route && npm start` | Shows the verifier-edge path with the TypeScript SDK. |
| an OpenAI Agents SDK tool | [examples/openai_agents_sdk_protected_tool/README.md](examples/openai_agents_sdk_protected_tool/README.md) | `cd examples/openai_agents_sdk_protected_tool && python3 app.py --mode direct` | Shows proof verification inside tool execution without needing a hosted layer. |
| a Go protected endpoint | [sdk/go/README.md](sdk/go/README.md) | `cd sdk/go && go run ./examples/http-protected-endpoint` | Shows verifier-edge proof checking in a Go HTTP service. |

## What Every Integration Path Has In Common

Every practical adoption path in this repository keeps the same boundary:

- the Protected Endpoint receives an Action Intent, PCCB, and local verification context
- proof verification happens before any protected side effect
- success returns a Receipt
- blocked execution returns a Refusal and a refused Receipt where the example path supports it
- no example requires a hosted control plane

## Framework And Tool Examples

### Primary And Secondary Distribution Paths

| Rank | Surface | Example | Why this matters | Where proof verification happens |
| --- | --- | --- | --- | --- |
| 1 | MCP server | [`examples/mcp_server_protected_tool/`](examples/mcp_server_protected_tool/README.md) | Neutral hero path for the category: strongest public story for protected tools without platform lock-in. | inside the MCP tool implementation |
| 2 | LangChain | [`examples/langchain_protected_tool/`](examples/langchain_protected_tool/README.md) | First framework-specific follow-on: many agent actions are exposed as tools here, so the protected endpoint must survive the framework abstraction. | inside the tool `_run` implementation |
| 3 | Claude Managed Agents | [`examples/claude_managed_agents_protected_tool/`](examples/claude_managed_agents_protected_tool/README.md) | Strongest Anthropic-specific platform example: same principle on a managed agent surface while MCP remains first and the kernel stays platform-neutral. | inside the custom tool implementation that answers `agent.custom_tool_use` |
| 4 | LlamaIndex | [`examples/llamaindex_protected_tool/`](examples/llamaindex_protected_tool/README.md) | Distribution-supporting framework path for function-wrapper agent tools. | inside the wrapped function exposed through `FunctionTool` |
| 5 | CrewAI | [`examples/crewai_protected_tool/`](examples/crewai_protected_tool/README.md) | Distribution-supporting multi-agent path that makes execution-boundary discipline visible. | inside the tool `_run` implementation |
| 6 | Semantic Kernel | [`examples/semantic_kernel_protected_tool/`](examples/semantic_kernel_protected_tool/README.md) | Distribution-supporting enterprise plugin/function path for Microsoft-aligned environments. | inside the `@kernel_function` plugin method |

Each ranked example returns canonical receipt or refusal artifacts, plus refused receipt paths where the bound execution example supports them.

### Additional Implementation Examples

These examples are useful adoption surfaces, but they are not part of the primary framework ranking above.

| Surface | Example | Why this matters | Where proof verification happens |
| --- | --- | --- | --- |
| OpenAI Agents SDK | [`examples/openai_agents_sdk_protected_tool/`](examples/openai_agents_sdk_protected_tool/README.md) | Shows proof verification inside tool execution on another agent-tool surface without hosted control-plane dependency. | inside the tool implementation |
| FastAPI | [`examples/fastapi_protected_route/`](examples/fastapi_protected_route/README.md) | Shows the protected-endpoint pattern in a normal Python HTTP service. | inside the route's protected execution helper |
| Express | [`examples/express_protected_route/`](examples/express_protected_route/README.md) | Shows the verifier-edge route pattern in a Node or TypeScript service. | inside the route before the action runs |

## SDK Paths

| SDK | Use it when you want... | Scope |
| --- | --- | --- |
| [Python verifier and kernel path](docs/guides/INTEGRATION_QUICKSTART.md) | the full OSS kernel reference path, local proof mode, CLI verification, and protected-endpoint examples | kernel plus verifier-first adoption |
| [TypeScript verifier SDK](sdk/typescript/README.md) | verifier-edge proof checking in Node or TypeScript services | verifier-only |
| [Go verifier SDK](sdk/go/README.md) | verifier-edge proof checking in Go services | verifier-only |
| [Rust verifier SDK](sdk/rust/README.md) | verifier-edge proof checking in Rust services or systems components | verifier-only |

Use [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md) if you want a fast chooser instead of reading each SDK README.

## Smallest Starting Point

If you only need verifier-edge proof checking, start here:

- [docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md](docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md)
- [docs/reference/verifier/VERIFIER_SDK_REFERENCE.md](docs/reference/verifier/VERIFIER_SDK_REFERENCE.md)
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [spec/replay/SPEC.md](spec/replay/SPEC.md)

## What These Examples Intentionally Do Not Add

- hosted approval routing
- hosted evidence collection
- orchestration frameworks
- control-plane APIs
- provider-backed execution adapters

The examples are meant to show where proof verification, receipt creation, and refusal handling belong in common adoption surfaces, not to turn the OSS kernel into an orchestrator.
