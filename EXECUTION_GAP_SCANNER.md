# Execution Gap Scanner

Actenon includes a local advisory scanner for candidate AI-controlled consequential action paths.

The scanner maps possible action surfaces such as tool side effects, browser submits, file writes, data exports, shell execution, deployment actions, database mutations, IAM changes, and MCP tool side effects.

It does **not** claim that a repository is vulnerable.

It does **not** prove runtime reachability, exploitability, production exposure, or business impact.

Scanner output should be read as a consequence-class advisory:

If this path is reachable by an agent or model-controlled workflow, the protected endpoint should require proof bound to the exact action before execution.

## Start Here

Read the full scanner methodology:

- [Execution Gap Scanner Methodology](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md)

## Quick Commands

Run:

    python3 -m actenon.cli scan --target replay-harness
    python3 -m actenon.cli scan repo --path .
    python3 -m actenon.cli scan mcp --path examples/mcp_server_protected_tool

## Report Language

Preferred:

    Critical-impact candidate action path, if reachable and ungated.

Avoid:

    Critical vulnerability detected.

Consequence Class is not Vulnerability Severity. A critical-impact candidate means an action surface could have critical consequences if reachable, agent-controlled, and ungated. It does not mean a critical vulnerability has been proven.
