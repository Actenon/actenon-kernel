# Scanner Remediation

Use scanner findings as a local punch list for closing candidate execution gaps.

Scanner findings are advisory and require maintainer review. A finding means a candidate consequential action path was statically visible and one or more controls were not visible near that path.

Actenon Scanner maps agent authority. It does not accuse your repo of being vulnerable. A Critical-impact candidate means the action surface could have critical consequences if reachable, agent-controlled and ungated. It does not mean a critical vulnerability has been proven.

## Useful Even Without Actenon

You can use scanner output even if you do not adopt Actenon. Review each runtime-source candidate path and confirm there is an equivalent control before execution:

- Approval gate: the side-effecting call cannot execute until a separate authorization step has run.
- Proof/authorization gate: the exact action and parameters are bound to a verifiable approval.
- Audit receipt/log: the allowed or refused decision leaves a durable record.
- Replay/idempotency control: the same approval cannot be reused to execute twice.
- Credential boundary: the agent does not hold standing production credentials.

Actenon provides one open proof-bound implementation of those controls through `PreflightEngine`, an `ActionIntent`/`PCCB` proof gate, `ProtectedExecutor`, `CredentialBroker`, Receipt/Refusal artifacts, and replay/escrow protection.

## Consequential Action Without Proof Gate

Add a protected endpoint or tool handler that verifies the exact `ActionIntent` and `PCCB` before the side effect. The execution edge should reject wrong audience, expired proof, mutated action hash, malformed artifacts, replay, and missing execution authority before calling the downstream system.

## Missing Credential Broker

Remove standing production authority from agent runtime paths. Put authority inside a protected endpoint, vault, or `CredentialBroker`. The agent should request an action; it should not hold raw production credentials.

Use `BrokeredCredential.secret_reference` or an equivalent safe reference in receipts and refusals. Do not store raw credential material in artifacts.

## Missing Preflight Or Evidence Policy

Add `PreflightEngine` or an equivalent policy gate before high-impact actions. Require approval and evidence for broad exports, destructive writes, privileged grants, payments, operational dispatch, regulated decisions, public communications, browser actions in authenticated portals, and legal or contractual commitments.

## Missing Receipt/Refusal Emission

Emit a `Receipt` for allowed execution and a `Refusal` for blocked execution. Receipt/Refusal artifacts should describe the action, policy outcome, proof identifiers, brokered credential reference, and public-safe execution result. They should not contain raw secrets, tokens, provider response bodies, or traceback text.

## Missing Replay Or Idempotency Protection

Add replay protection and single-use escrow for proof-bearing requests. Proof verification alone can validate the same artifact more than once unless the execution edge keeps state. For external APIs, also use provider idempotency keys where available.

## Browser And Computer-Use Actions

Treat authenticated browser clicks, fills, submits, uploads, downloads, session-state changes, and portal actions as consequential action paths. Put the final browser action behind proof and Preflight, broker portal credentials, and emit Receipt/Refusal for the outcome.

Treat desktop/computer-use actions such as mouse clicks, keyboard input, clipboard use, VNC/noVNC sessions, application launch, shell-through-desktop, and file movement the same way when an agent controls them.

Navigation-only context is usually lower severity, but it still deserves review when paired with login, cookies, session state, form submission, file transfer, or external systems.

## External API And SaaS Mutations

Mutating HTTP, GraphQL, gRPC, webhook, queue, CRM, ticketing, ERP, ecommerce, and SaaS calls should be proof-gated when agent-controlled. Broker credentials, bind the proof audience to the execution edge, apply idempotency/replay protection, and receipt the external side effect.

## MCP And Delegated Tools

Move proof verification into the MCP tool handler or delegated tool boundary. Framework approval is not execution authority. The handler should verify exact audience, target, capability, and single-use state before calling the side-effecting system.

When scanner finds MCP tool side effects, wrap those handlers with the protected executor. The minimal local path is [MCP_QUICKSTART.md](../integrations/MCP_QUICKSTART.md) and the fuller five-tool path is [MCP_HERO_PATH.md](MCP_HERO_PATH.md).

For tool orchestration, avoid proof laundering: a parent agent's approval should not be treated as proof that every downstream tool action is authorized.

## Standing Credential Signal

Strong runtime secret evidence should be reviewed even if it appears in a low-confidence path. Move production secrets out of agent-visible runtime code, sanitize provider SDK errors, and keep raw material out of logs, receipts, refusals, and serialized outputs.

API-key configuration and environment-variable credential lookup are reported as credential authority signals. They should not be treated as hardcoded secret exposure unless raw secret material is actually present, but they still matter when the same runtime can drive agent tools, browsers, desktops, APIs, or workflows.

Direct API client construction, database URL use, cloud SDK sessions, browser cookie/session-state loading, and MCP tools that combine direct credentials with side effects are also credential-boundary review signals. Move those authorities behind a protected endpoint or equivalent brokered boundary before enabling autonomous execution.

Bare enum or migration strings such as `api_key`, `token`, and `auth_type` are suppressed in offline migration contexts unless strong runtime secret access is visible.

## Unknown Capability Signal

When a report says the specific action type was not classified, review the path manually. The scanner saw high-capability signals such as authenticated clients, generic run/execute/invoke/submit/update/delete calls, or agent/model output coupled to a possible side effect.

If the path can act on the world, add proof-bound execution, Preflight/policy, credential brokering, idempotency/replay protection, and Receipt/Refusal emission.
