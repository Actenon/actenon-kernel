# Actenon Agentic Action Scan Methodology

Actenon Scanner is a local advisory tool for finding candidate agent-controlled consequential action paths. It maps authority; it does not accuse your repo of being vulnerable.

It looks for this shape:

```text
model / agent decision -> consequential side effect -> no visible proof gate
```

The scanner is private by default. It does not upload source code, submit grades, publish rankings, run a hosted trust network, or create an Actenon conformance result.

This is not a vulnerability severity rating. It is a consequence-class map of candidate action surfaces found by static analysis. Runtime reachability, exploitability, production exposure, business impact, and vulnerability are not proven by scanner output.

## Commands

```bash
actenon scan local
actenon scan repo --path .
actenon scan mcp --path examples/mcp_server_protected_tool
actenon scan endpoint --path examples/fastapi_protected_route
```

Reports can be emitted as terminal text, JSON, Markdown, and badge Markdown:

```bash
actenon scan repo \
  --path . \
  --report-json .actenon-scan/report.json \
  --report-markdown .actenon-scan/report.md \
  --badge-output .actenon-scan/badge.md
```

Reports cite the scanner version and capability registry version.

For a public-safe sample of the intended scanner UX, see
[docs/examples/scanner-report-example.md](../examples/scanner-report-example.md),
[docs/examples/scanner-report-example.json](../examples/scanner-report-example.json), and
[docs/assets/scanner-output-summary.md](../assets/scanner-output-summary.md).

Large repositories can be scanned with practical controls:

```bash
actenon scan repo \
  --path ../target-agent \
  --exclude node_modules \
  --exclude dist \
  --extensions py,ts,tsx,js,go,rs,java \
  --max-files 20000 \
  --max-file-size 1000000 \
  --timeout-seconds 120 \
  --progress \
  --partial-report-on-timeout
```

Progress is emitted on stderr. JSON and Markdown reports include discovered/scanned/skipped file counts plus partial/timeout status when applicable.

## What The Scanner Looks For

The scanner does not only scan for narrow high-impact action keywords. It scans for candidate consequential action paths:

- external or persistent state mutation
- sensitive data export, transformation, publication, or transmission
- money movement or financial commitment
- access, secret, identity, or permission changes
- outbound communication
- browser or computer-use actions
- code, infrastructure, deployment, or supply-chain changes
- operational workflow and regulated decisioning actions
- agent delegation, MCP tool invocation, and long-running autonomous workflows

The detector distinguishes:

- side-effect primitive found
- consequential surface found
- agent-control context found
- candidate agent-controlled consequential path found
- visible control found or not found

The detector category names are:

- `BROWSER_AGENT_SIDE_EFFECT`
- `COMPUTER_USE_AGENT_SIDE_EFFECT`
- `CODING_AGENT_SIDE_EFFECT`
- `SHELL_EXECUTION_SIDE_EFFECT`
- `FILE_MUTATION_SIDE_EFFECT`
- `DATABASE_MUTATION_SIDE_EFFECT`
- `CLOUD_INFRASTRUCTURE_SIDE_EFFECT`
- `EXTERNAL_API_SIDE_EFFECT`
- `MCP_TOOL_SIDE_EFFECT`
- `WORKFLOW_AUTOMATION_SIDE_EFFECT`
- `CREDENTIAL_AUTHORITY_SIGNAL`
- `AGENT_TOOL_REGISTRY_SIGNAL`

Path types classify where the signal appears: runtime agent loop, tool handler, action registry, browser controller, desktop controller, API endpoint, webhook handler, background worker, workflow executor, CLI command, integration connector, database migration, test, example, documentation, config, or generated file.

## Universal Taxonomy

The scanner registry currently maps findings to surfaces S1 through S15:

| Surface | Name |
| --- | --- |
| S1 | DATA_AND_STORAGE_MUTATION |
| S2 | INFRASTRUCTURE_AND_COMPUTE_CONTROL |
| S3 | IDENTITY_ACCESS_AND_SECRETS |
| S4 | MONEY_AND_FINANCE |
| S5 | OUTBOUND_COMMUNICATION_AND_PUBLICATION |
| S6 | BROWSER_AND_COMPUTER_USE |
| S7 | CODE_AND_SOFTWARE_SUPPLY_CHAIN |
| S8 | EXTERNAL_API_AND_THIRD_PARTY_MUTATION |
| S9 | PHYSICAL_CYBER_PHYSICAL_IOT_ROBOTICS |
| S10 | AGENT_ORCHESTRATION_AND_DELEGATION |
| S11 | MODEL_MEMORY_AND_KNOWLEDGE_BASE |
| S12 | LEGAL_CONTRACTUAL_AND_CONSENT |
| S13 | GOVERNANCE_ADMIN_AND_OPERATIONAL_POLICY |
| S14 | OPERATIONAL_WORKFLOW_AND_DISPATCH |
| S15 | REGULATED_DECISIONING |

See [UNIVERSAL_CONSEQUENTIAL_ACTION_TAXONOMY.md](UNIVERSAL_CONSEQUENTIAL_ACTION_TAXONOMY.md) for the full taxonomy.

## Capability Registry

Scanner rules are data-backed by `actenon/scanner_capability_registry.v1.json`.

Each registry entry includes signal patterns, import patterns, call patterns, path patterns, severity defaults, confidence hints, recommended Actenon controls, remediation text, and caveats. New SDKs and tool surfaces should be added to the registry before hard-coding detector logic.

Unknown high-capability paths can still be flagged through reachability signals such as authenticated clients, mutating outbound calls, shell execution, generic execute/run/invoke/submit/update/delete calls, or agent/model output coupled to side effects.

When the scanner cannot classify a specific action type, it uses this wording:

```text
Actenon Scanner found a candidate consequential action path detected via capability signals; specific action type not classified; runtime reachability not proven; runtime exploitability not proven; maintainer review recommended.
```

## Controls

For every emitted consequential surface, the scanner looks nearby and file-wide for visible controls.

Actenon-specific controls:

- `ActionIntent`
- `PCCB`
- `proof_verifier`
- `ProtectedEndpointMiddleware`
- `ProtectedExecutor`
- `CredentialBroker`
- `BrokeredCredential`
- `PreflightEngine`
- `Receipt`
- `Refusal`
- replay protection
- escrow consume
- Actenon imports

Generic controls:

- human approval or override
- policy engine and allow/deny decision
- evidence requirement
- RBAC/IAM check
- audit log
- idempotency or replay protection
- dry-run
- environment guard
- transaction limit
- change ticket
- backup or rollback path
- escalation

Typical control gaps include missing proof gate, missing credential broker, missing Preflight/policy, missing evidence requirement, missing Receipt/Refusal emission, missing replay/idempotency protection, standing credential risk, wrong/no audience binding, and external side effect not receipted.

## Consequence Class, Gating, Reachability, And Confidence

Consequence Class is not Vulnerability Severity.

Every finding includes category, surface id, primitive, agent-control context, side-effect type, consequence class, confidence, evidence lines, path, function/class/tool name where available, path type, source context, why-this-matters rationale, nearby controls found, missing controls, generic control, Actenon implementation, caveat, context classification, and legacy internal severity.

Allowed consequence classes are displayed conditionally:

- Low-impact candidate, if reachable and ungated
- Medium-impact candidate, if reachable and ungated
- High-impact candidate, if reachable and ungated
- Critical-impact candidate, if reachable and ungated

Critical-impact candidate means the action surface could have critical consequences if reachable, agent-controlled and ungated. It does not mean a critical vulnerability has been proven.

Reports separate:

- `Consequence Class`
- `Gating Status`
- `Runtime Reachability`
- `Vulnerability Claim`
- `Manual Review Required`
- `Confidence`
- `Runtime-source candidate paths`
- `Additional test/example/context findings`
- `Categories Detected`

`vulnerability_claim` is `false` for static advisory scans. `vulnerability_severity` is `null` unless a future dedicated runtime proof mode supports a confirmed security finding.

Confidence values are `low`, `medium`, and `high`.

Markdown reports support:

- executive mode for a plain-English action-risk summary
- developer mode for detailed finding metadata, file paths, evidence snippets, recommended integration points, and technical appendix fields
- JSON mode for machine-readable automation

Legacy A-F grades remain for CI compatibility, but should not be read alone and should not be presented as vulnerability grades:

| Grade | Meaning |
| --- | --- |
| A | Candidate consequential actions are proof-gated; credential broker, Receipt/Refusal, replay/idempotency, and approval/evidence controls are visible where needed. |
| B | Proof/policy and receipts are visible, with minor or unassessed gaps. |
| C | Partial controls are visible, often Preflight/advisory only or weak credential-broker evidence. |
| D | Candidate consequential actions were found with weak or missing proof-bound controls. |
| F | High-confidence agent-controlled side-effect path in runtime code with no visible proof gate, credential broker, or Receipt/Refusal path. |

Consequence Class and legacy grade are advisory static analysis, not a certification or exploitability proof.

## Context Suppression

The scanner classifies code context before emitting findings:

- `OFFLINE_MIGRATION`
- `TEST_OR_EXAMPLE`
- `DOCS_OR_GENERATED`
- `ENUM_CONSTANT_OR_TYPE_CONTEXT`
- `CONFIG`
- `RUNTIME_CODE`

Offline Alembic migrations, tests, docs, generated files, config files, comments, type declarations, and enum-like constants suppress bare credential words such as `api_key`, `token`, `secret`, `credential`, `caller_type`, and `auth_type` when those words appear as metadata rather than runtime credential access.

Headline counts and headline consequence class are based on runtime-source candidates by default. Test, fixture, example, docs, generated and migration findings are reported separately and downgraded by context. Runtime tool handlers, server files, `index.*`, `lib.*`, tool registration files, and tool handler files are prioritized in report ordering.

Strong runtime credential evidence is not suppressed, including environment reads, private key blocks, provider secret variables, vault/secret-manager access, `keyring.get_password`, `decrypt_text(...)`, and obvious long token literals.

API-key configuration is reported as `CREDENTIAL_AUTHORITY_SIGNAL` and distinguished from hardcoded secret material. It is a standing-authority review signal, not a claim that a secret was leaked.

The scanner also reports candidate direct-credential bypass signals when they appear in agent, tool, workflow, browser, desktop, API, or MCP paths:

- API client construction with API-key, token, credential, or authorization parameters
- cloud SDK client/session construction in agent paths
- database URLs, DSNs, or connection strings in agent tool paths
- browser cookies or session-state files loaded directly by an agent
- MCP tool handlers that combine credentials with side-effecting tool execution
- consequential paths where a Credential Broker or protected endpoint boundary is not visible

These findings mean "review the authority boundary." They do not prove runtime reachability, exploitability, or that the repository is unsafe.

Suppression metadata appears in JSON reports as `credential_keyword_suppressed_in_migration`, `offline_migration_context`, `test_or_example_context`, `runtime_source_finding_count`, `test_or_example_finding_count`, and the backward-compatible `downgraded_test_fixture_context`.

## Scan Modes

`local` runs the built-in local harness. It proves the scanner can observe proof binding, audience enforcement, expiry enforcement, replay refusal, and structured Refusal/Receipt behavior. Credential brokering remains deployment-specific and is reported as unassessed in this mode.

`repo` performs static advisory heuristics over code files under the selected path.

`mcp` performs the same local static scan but labels the report as MCP-focused for tool-handler review.

`endpoint` performs the same local static scan but labels the report as endpoint-focused for protected route review.

Legacy `--target artifact-pair` and `--target replay-harness` remain supported.

## Field-Test Commands

When these repositories are available locally, run private reports only:

```bash
actenon scan repo --path ../skyvern --report-json PRIVATE_SCANNER_FIELD_TEST_SKYVERN.json --report-markdown PRIVATE_SCANNER_FIELD_TEST_SKYVERN.md
actenon scan repo --path ../browser-use --report-json PRIVATE_SCANNER_FIELD_TEST_BROWSER_USE.json --report-markdown PRIVATE_SCANNER_FIELD_TEST_BROWSER_USE.md
actenon scan repo --path ../stagehand --report-json PRIVATE_SCANNER_FIELD_TEST_STAGEHAND.json --report-markdown PRIVATE_SCANNER_FIELD_TEST_STAGEHAND.md
actenon scan repo --path ../OpenHands --report-json PRIVATE_SCANNER_FIELD_TEST_OPENHANDS.json --report-markdown PRIVATE_SCANNER_FIELD_TEST_OPENHANDS.md
actenon scan repo --path ../AutoGPT --report-json PRIVATE_SCANNER_FIELD_TEST_AUTOGPT.json --report-markdown PRIVATE_SCANNER_FIELD_TEST_AUTOGPT.md
actenon scan mcp --path ../example-mcp-server --report-json PRIVATE_SCANNER_FIELD_TEST_MCP_SERVER.json --report-markdown PRIVATE_SCANNER_FIELD_TEST_MCP_SERVER.md
```

Classify each private field-test finding as true signal, weak signal, false positive, or scanner improvement needed. Do not publish target grades without maintainer consent.

## Limits

The scanner is path-centered and heuristic. It does not prove runtime reachability, business-policy correctness, downstream provider finality, adapter honesty, exploitability, harm, compliance status, or production impact. It also does not replace the conformance suite.

Use scanner findings to decide where maintainers should review proof-bound execution, Preflight, credential brokering, and Receipt/Refusal integration.
