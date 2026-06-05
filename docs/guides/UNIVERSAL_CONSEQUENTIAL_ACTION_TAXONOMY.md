# Universal Consequential Action Taxonomy

Actenon Scanner detects candidate consequential action paths, not only known high-impact keywords.

A consequential action is any action that can change external or persistent state, expose or transmit sensitive data, spend or move money, create legal or operational commitments, grant or revoke access, communicate externally, alter infrastructure or code, act through a browser/computer interface, delegate to another agent/tool/workflow, or affect customers, employees, patients, students, citizens, suppliers, vendors, drivers, users, or counterparties.

Findings are advisory static analysis and require maintainer review. Actenon Scanner maps agent authority; it does not accuse your repo of being vulnerable.

Consequence Class is not Vulnerability Severity. A Critical-impact candidate means the action surface could have critical consequences if reachable, agent-controlled and ungated. It does not mean a critical vulnerability has been proven. Headline counts and headline consequence class are based on runtime-source candidates by default; test, fixture, example, docs, generated and migration findings are reported separately and downgraded by context.

## Detector Categories

S1-S15 describe consequential action surfaces. Scanner findings also emit a detector category that describes the agentic-action path shape:

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

Reports also include a path type such as `browser controller`, `desktop controller`, `tool handler`, `workflow executor`, `database migration`, `config`, `test`, `example`, or `documentation`.

## S1 - DATA_AND_STORAGE_MUTATION

Detects database writes/deletes/schema changes, insert/update/delete/upsert, `DELETE`/`TRUNCATE`/`ALTER`/`DROP`, runtime migrations, object/blob storage mutation, filesystem mutation, cache/queue purge, search-index mutation, and backup delete/restore.

Recommended controls: `PreflightEngine`, `ProtectedExecutor`, `CredentialBroker`, Receipt/Refusal, replay/idempotency protection.

## S2 - INFRASTRUCTURE_AND_COMPUTE_CONTROL

Detects Terraform, Pulumi, Kubernetes, Docker, Helm, cloud-resource create/update/delete, serverless deploy/delete, scale/restart/shutdown, DNS/domain/CDN/firewall changes, CI/CD deploy/release triggers, and environment/config changes.

Recommended controls: proof gate, Preflight, brokered cloud authority, human approval/evidence, Receipt/Refusal.

## S3 - IDENTITY_ACCESS_AND_SECRETS

Detects create/delete user, grant/revoke role, admin permission grant, API key creation, token/session generation, password reset, MFA/SSO changes, group membership changes, service account changes, OAuth grants, document/resource sharing changes, and secret access/rotation/exfiltration.

Recommended controls: `CredentialBroker`, Preflight, proof gate, Receipt/Refusal, audit logging.

## S4 - MONEY_AND_FINANCE

Detects payment release, refund, transfer, payout, trade/order, crypto transaction signing, smart-contract call, invoice approval, payroll change, subscription/billing change, bank-detail update, purchase/order, price change, tax/filing submission, and financial record posting.

Recommended controls: Preflight, approval/evidence, brokered payment authority, proof gate, idempotency, Receipt/Refusal.

## S5 - OUTBOUND_COMMUNICATION_AND_PUBLICATION

Detects email, SMS, WhatsApp, Slack, Teams, Discord, voice call, push notification, customer notification, support reply, social post, comment/review/message, calendar invite, website/content publish, and legal/compliance communication.

Recommended controls: Preflight/policy, approval where needed, audit log, Receipt/Refusal.

## S6 - BROWSER_AND_COMPUTER_USE

Detects Playwright, Selenium, Puppeteer, browser-use, Stagehand, Browserbase, Skyvern-style workflows, Chromium/browser contexts, pyautogui/RPA/computer-use actions, page click/fill/press/evaluate, form submit, file upload/download, login, cookies/session state, authenticated portals, and CAPTCHA solving.

Recommended controls: proof gate at the browser action boundary, Preflight, brokered portal credentials, Receipt/Refusal.

## S7 - CODE_AND_SOFTWARE_SUPPLY_CHAIN

Detects git commit/push/merge, PR create/merge, CI/CD trigger, package publish, dependency update, container image push, arbitrary code execution, generated code applied to a repo, and self-modification of agent config/code/approval settings.

Recommended controls: Preflight, approval gate, dry-run where possible, audit log, Receipt/Refusal.

## S8 - EXTERNAL_API_AND_THIRD_PARTY_MUTATION

Detects mutating HTTP `POST`/`PUT`/`PATCH`/`DELETE`, GraphQL mutations, gRPC mutating calls, webhook send, queue publish/event emit, and CRM/ticketing/ERP/ecommerce/SaaS writes such as Salesforce, Jira, Linear, NetSuite, Shopify, HubSpot, and ServiceNow.

Recommended controls: proof gate, `CredentialBroker`, Receipt/Refusal, replay/idempotency protection.

## S9 - PHYSICAL_CYBER_PHYSICAL_IOT_ROBOTICS

Detects unlock/lock, open/close, start/stop machine, robot/drone/vehicle action, building access, alarm/security control, HVAC/energy control, fleet action, sensor-triggered actuation, SCADA/manufacturing commands, and medical device commands.

Recommended controls: proof gate, Preflight, operator approval, brokered authority, Receipt/Refusal.

## S10 - AGENT_ORCHESTRATION_AND_DELEGATION

Detects spawning another agent, delegating to sub-agents, A2A calls, MCP tool calls, autonomous workflow runs, scheduled/recurring agent tasks, background tasks, toolchain chaining, tool-call proof laundering, available/execute/run/invoke tool APIs, memory writes that steer future action, and policy/goal updates.

Recommended controls: proof at delegated tool boundaries, Preflight, Receipt/Refusal, audience binding for tool calls.

## S11 - MODEL_MEMORY_AND_KNOWLEDGE_BASE

Detects long-term memory writes/deletes, vector DB ingestion, retrieval-source updates, system/policy prompt changes, tool-instruction updates, sensitive document ingestion, fine-tuning/training-job triggers, and model deployment.

Recommended controls: Preflight, evidence requirement, audit log, Receipt/Refusal.

## S12 - LEGAL_CONTRACTUAL_AND_CONSENT

Detects DocuSign/signature flows, terms acceptance, consent acceptance/withdrawal, legal filing/submission, regulatory filing, contract/order commitment, and binding acceptance on behalf of a user or organization.

Recommended controls: explicit proof, human approval, evidence, Preflight, Receipt/Refusal.

## S13 - GOVERNANCE_ADMIN_AND_OPERATIONAL_POLICY

Detects account-setting changes, plan/subscription changes, data-retention policy changes, compliance configuration, approval/override disablement, escalation threshold changes, policy suppression, and alert suppression.

Recommended controls: Preflight, human approval, audit log, Receipt/Refusal.

## S14 - OPERATIONAL_WORKFLOW_AND_DISPATCH

Detects dispatching drivers/engineers/technicians, assigning cases/orders/tickets, routing tasks, changing priority, altering SLA/escalation, exposing workflow state to third parties, changing fulfillment/delivery timing, approving/rejecting applications, scheduling/canceling appointments, and canceling bookings/orders/accounts.

Recommended controls: Preflight, human override where needed, audit log, Receipt/Refusal.

## S15 - REGULATED_DECISIONING

Detects healthcare/patient record updates, prescriptions/referrals/orders, education/student record updates, safeguarding/escalation, benefits/claims/eligibility decisions, credit/risk decisions, employment/hiring decisions, and public-sector eligibility actions.

Recommended controls: Preflight, human approval/evidence, proof gate, audit log, Receipt/Refusal.

## Unknown Capability Signals

If the scanner sees an authenticated client, agent/model-controlled execution, generic `run`/`execute`/`invoke`/`submit`/`update`/`delete` calls, shell execution, mutating network calls, or side-effect primitives that do not match a known surface, it may emit `UNKNOWN_CAPABILITY`.

That means the specific action type was not classified and static reachability is not proven. Maintainer review determines whether the path needs Actenon controls.
