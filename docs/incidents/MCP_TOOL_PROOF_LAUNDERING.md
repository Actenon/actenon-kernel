# MCP Tool Proof Laundering

This is a generic pattern simulation, not a named factual incident report.

## Pattern Summary

An agent or framework obtains approval or proof for one tool, then attempts to use that authority at a different tool handler with a different audience or side effect.

## Consequential Action

```json
{
  "capability": "infrastructure.delete",
  "source_tool_id": "staging-cleanup-tool",
  "presented_tool_id": "prod-infra-delete-tool"
}
```

## Execution Gap

The gap appears when a tool handler treats upstream approval as execution authority instead of verifying exact audience, action hash, and target at the handler boundary.

## What Actenon Would Require

- Tool-specific proof audience.
- Exact action hash binding.
- Preflight on production destructive actions.
- Credential brokering inside the protected tool handler.
- Refusal if proof minted for tool A is attempted at tool B.

## Sample Decision

```json
{
  "outcome": "approval_required",
  "reason_code": "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED"
}
```

## What Actenon Does Not Claim

Actenon does not claim the upstream planner made the right decision or that all MCP servers are safe. It claims only that the protected handler can verify and refuse the exact side effect before execution.

## Simulate

```bash
actenon-kernel simulate --scenario mcp-tool-proof-laundering
```

