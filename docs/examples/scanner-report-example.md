# Actenon Agentic Action Scan

## Executive Summary

Actenon found candidate consequential action surfaces where static analysis could not verify a proof-bound execution gate.

- Runtime-source candidate paths: 2
- Additional test/example/context findings: 3, downgraded by context
- Consequence Class: High-impact candidate, if reachable and ungated
- Gating Status: Not verified
- Runtime Reachability: Not proven
- Vulnerability Claim: No
- Manual Review Required: Yes
- Confidence: High
- Categories Detected: MCP tool side effect, File mutation side effect

This is not a vulnerability severity rating. It is a consequence-class map of candidate action surfaces found by static analysis.

Runtime reachability, exploitability, production exposure and business impact are not proven by this scan.

Actenon Scanner maps agent authority. It does not accuse your repo of being vulnerable.

## What This Means

The scanner found runtime-source locations where an agent, workflow, MCP tool, browser/computer-use controller, or tool handler may be able to reach side effects such as file mutation, database writes, external API calls, browser actions, operational workflows, access changes, communications, or data transfer.

## What This Does Not Mean

This scan does not prove runtime reachability, exploitability, production exposure, business impact, or vulnerability.

## Useful Even If You Do Not Use Actenon

You can use this report even without Actenon. At minimum, review each runtime-source candidate path and confirm there is an equivalent approval, authorization, audit, replay/idempotency and credential-boundary control before execution.

- Approval gate: the side-effecting call cannot execute until a separate authorization step has run.
- Proof/authorization gate: the exact action and parameters are bound to a verifiable approval.
- Audit receipt: the allowed or refused decision leaves a durable record.
- Replay/idempotency control: the same approval cannot be reused to execute twice.
- Credential boundary: the agent does not hold standing production credentials.

## Action Surface Map

| Surface | Runtime-source candidates | Test/context findings | Highest consequence class | Confidence | Runtime reachability | Gating status | Generic control | Actenon implementation |
| --- | ---: | ---: | --- | --- | --- | --- | --- | --- |
| MCP tool side effect | 1 | 1 | High-impact candidate, if reachable and ungated | High | Not proven | Not verified | add a proof/authorization check before execution; emit an audit receipt/log for allowed and refused decisions. | ActionIntent/PCCB proof gate; ProtectedExecutor; Receipt/Refusal. |
| File mutation side effect | 1 | 2 | High-impact candidate, if reachable and ungated | High | Not proven | Not verified | add a proof/authorization check before execution; add replay/idempotency protection. | ActionIntent/PCCB proof gate; ProtectedExecutor; replay/escrow protection. |

## Priority Fixes

1. Add proof-bound ActionIntent/PCCB verification before consequential actions execute.
2. Emit Receipt/Refusal records for every allowed or blocked consequential action.
3. Add replay/idempotency protection so reused proof cannot trigger duplicate execution.
4. Broker credentials inside protected endpoints after proof and policy verification.

## Top Runtime-Source Findings

- MCP tool handler detected without visible proof-bound execution gate.
- File mutation capability detected without visible approval/evidence policy.
- Tool execution path detected without visible Receipt/Refusal emission.

## Findings

### Runtime-Source Findings

### Finding 1: MCP tool may reach file mutation

- Finding ID: `aa-001`
- Category: MCP tool side effect (`MCP_TOOL_SIDE_EFFECT`)
- Surface: `S10` / `AGENT_ORCHESTRATION_AND_DELEGATION`
- Consequence class: High-impact candidate, if reachable and ungated
- Gating status: Not verified
- Runtime reachability: Not proven
- Vulnerability claim: No
- Confidence: High
- File path: `src/server/filesystem.ts:42`
- Line: `42`
- Function/class/tool: `write_file`
- Source context: `runtime_source`
- Primitive: `tool_invocation`
- Agent-control context: `yes`
- Evidence snippet:

```text
   39 | const server = new McpServer({ name: "filesystem", version: "1.0.0" });
   40 |
   41 | server.tool("write_file", async ({ path, content }) => {
>  42 |   await fs.writeFile(path, content, "utf8");
   43 |   return { ok: true };
   44 | });
```

- Nearby controls found: none visible nearby
- Missing controls: missing proof gate, missing Receipt/Refusal emission, missing replay/idempotency protection
- Why this matters: This appears to be an MCP/tool-exposed handler where a model-selected tool call may reach file mutation via `tool_invocation`. Static analysis did not find a visible proof gate, Receipt/Refusal emission, or replay/idempotency protection between the decision source and the side effect. This is the scanner's model/agent decision -> side effect -> no visible proof gate shape. Runtime reachability, exploitability, production exposure, and business impact are not proven by this scan.
- Generic control: add a proof/authorization check before execution; emit an audit receipt/log for allowed and refused decisions; add replay/idempotency protection.
- Actenon implementation: ActionIntent/PCCB proof gate; ProtectedExecutor; Receipt/Refusal; replay/escrow protection.
- Caveat: Static advisory execution-surface finding; runtime reachability, exploitability, production exposure, and business impact are not proven.

### Test / Example / Context Findings

Context findings were detected in test and example paths. They are useful validation evidence, but they do not drive the headline consequence class by default.

## Recommended Integration Points

Generic controls come first; Actenon is one open proof-bound implementation path.

- Require proof/authorization before mutation and emit an audit record.
- Add approval/evidence requirements for high-impact actions.
- Use replay/idempotency controls for single-use authority.
- Move standing credentials out of agent runtime and broker least-privilege authority after approval.
- With Actenon: wrap the handler with `ProtectedExecutor`, require an `ActionIntent`/`PCCB`, use `CredentialBroker` where credentials are needed, and emit Receipt/Refusal artifacts.

## Scanner Limitations

- Reports are static advisory and each finding requires maintainer review.
- Consequence Class is not Vulnerability Severity.
- Runtime reachability not proven by static analysis.
- Runtime exploitability not proven by static analysis.
- Test, example, migration, generated, and documentation paths may reduce confidence.
- Receipts prove artifact origin and integrity, not business correctness or downstream finality.
- This scanner does not upload source code or reports by default and does not publish target grades.

## Technical Appendix

- Report mode: `executive`
- Scanner mode: `mcp`
- Target: `example-mcp-filesystem`
- Status: `EXECUTION_GAP_PRESENT`
- Scanner version: `2.1.0`
- Registry version: `capability_registry.v1`
- Legacy compatibility grade: `D`
- Total candidate findings including context: `5`
- Highest overall consequence class including context: `High-impact candidate, if reachable and ungated`
