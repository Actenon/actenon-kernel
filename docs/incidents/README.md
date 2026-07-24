# Incident Library

The Actenon incident library teaches execution-gap patterns for consequential agent actions. The pages in this directory are source-disciplined: they are generic pattern simulations unless a named incident is independently verified and cited.

Hero line:

```text
No receipt, no prod delete.
```

Run the hero simulation:

```bash
actenon-kernel simulate --incident prod-delete
```

Run the additional pattern scenarios:

```bash
actenon-kernel simulate --scenario mcp-tool-proof-laundering
actenon-kernel simulate --scenario iam-escalation
actenon-kernel simulate --scenario data-export
```

## Pattern Pages

- [Production Destructive Action](./PRODUCTION_DESTRUCTIVE_ACTION.md)
- [Replit-Style Database Delete](./REPLIT_STYLE_DATABASE_DELETE.md)
- [MCP Tool Proof Laundering](./MCP_TOOL_PROOF_LAUNDERING.md)
- [IAM Privilege Escalation Pattern](./IAM_PRIVILEGE_ESCALATION_PATTERN.md)
- [Data Export Exfiltration Pattern](./DATA_EXPORT_EXFILTRATION_PATTERN.md)

## Source Discipline

These pages do not claim private forensic knowledge, regulator findings, provider finality, or business-policy correctness. They show where the execution gap appears and how a protected Actenon boundary can require preflight, proof, credential brokering, and Receipt/Refusal artifacts before side effects.

