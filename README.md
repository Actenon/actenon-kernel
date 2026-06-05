# Actenon

**The open proof gate and receipt standard for consequential AI actions.**

> **No valid proof, no execution.**

Actenon stops AI agents, MCP tools, browser agents, coding agents, workflow automations, and tool-calling systems from taking consequential actions unless the protected endpoint can verify proof bound to the exact action being attempted.

It sits at the execution boundary, refuses unproven actions before side effects happen, and emits verifiable Receipt or Refusal artifacts for audit, compliance, and trust.

![Actenon demo: unproven agent action refused before side effect](docs/assets/actenon-hero-devops.gif)

[Release gate: local command](scripts/verify_release_gate.sh) · [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) · [![Python: 3.9-3.12](https://img.shields.io/badge/python-3.9--3.12-blue)](pyproject.toml) · [Conformance tests](CONFORMANCE.md) · [Adversarial tests](docs/security/SECURITY_TESTING.md)

---

## See It In 60 Seconds

```bash
git clone https://github.com/Actenon/actenon.git
cd actenon

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[asymmetric]"

bash scripts/demo_hero.sh
```

This is a safe local simulation. It does not contact a cloud account, use external secrets, or perform a real destructive action.

Expected shape:

```text
ACTENON HERO DEMO

Action requested:
  database.delete_table production_customers

Proof status:
  invalid or missing

Decision:
  REFUSED

Reason:
  no valid proof bound to this exact action

Side effect:
  not executed

Artifact:
  refusal emitted
```

Run the detailed version:

```bash
bash scripts/demo_hero.sh --details
```

---

## Expected Local Warnings

The local demo and conformance commands may print warnings about the local HMAC signer. These warnings are expected in demo mode and are intentionally explicit.

The default local proof secret is public and must not be used for production. Production deployments should use asymmetric well-known verification material, KMS, or HSM-backed signing custody.

## Choose Your Path

| If you are... | Start here |
| --- | --- |
| Just curious | Watch the GIF and run `bash scripts/demo_hero.sh` |
| Building agents or MCP tools | [Protect an MCP Tool In 3 Steps](#protect-an-mcp-tool-in-3-steps) |
| Reviewing security | [Why This Is Not Just Middleware](#why-this-is-not-just-middleware), [Threat Model](THREAT_MODEL.md), [Security Testing](docs/security/SECURITY_TESTING.md) |
| Designing enterprise architecture | [Architecture](#architecture), [Trust Boundaries](docs/architecture/TRUST_BOUNDARIES.md), [Deployment Architectures](docs/architecture/DEPLOYMENT_ARCHITECTURES.md) |
| Maintaining an open-source agent repo | [Scanner Advisory Language](#scanner-advisory-language) |
| Evaluating governance or standards | [Standard And Governance](#standard-and-governance), [Conformance](CONFORMANCE.md), [Governance](GOVERNANCE.md) |
| Considering contribution | [Best First Contributions](#best-first-contributions), [Contributing](CONTRIBUTING.md) |

---

## The Execution Gap

AI systems are no longer only choosing words. They are calling tools, touching provider APIs, changing state, and initiating irreversible actions.

Most stacks already have authentication, policy, approval, or workflow state. Those controls matter, but they do not always guarantee that the execution edge performs the exact approved action exactly once.

That missing boundary is the **execution gap**.

Actenon closes that gap with **proof-bound execution**:

> The protected endpoint independently verifies proof for the exact action, audience, tenant, subject, target, scope, expiry, and replay identity before side effects happen.

Read the canonical problem statement in [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md).

---

## Why This Is Not Just Middleware

Actenon is not a client-side safety wrapper.

The agent and SDK are not the trust boundary. **The protected endpoint is the enforcement boundary.**

A consequential action is only allowed when the endpoint verifies proof bound to the exact action parameters, tenant, subject, audience, expiry, and replay or escrow state.

If the proof is missing, expired, replayed, audience-mismatched, action-mismatched, parameter-mismatched, tenant-mismatched, or policy-denied, the endpoint refuses before the side effect and emits a Refusal artifact.

This matters because prompt injection can make an agent want to act, but it should not make the action execute.

```text
Untrusted Agent
   ↓
SDK / Client Helper
   ↓
Protected Endpoint      ← enforcement boundary
   ↓
Proof Verifier
   ↓
Policy / Replay / Credential Boundary
   ↓
Side Effect
   ↓
Receipt or Refusal Artifact
```

The SDK can help create, attach, or verify proof objects, but the SDK is not the security boundary. A deployment is only meaningfully Actenon-protected when the side-effecting endpoint refuses execution unless valid, action-bound proof is verified at the protected boundary.

---

## Architecture

```text
┌──────────────────┐
│  Untrusted Agent │
└────────┬─────────┘
         │ wants to act
         ▼
┌──────────────────┐
│ SDK / Tool Client │
└────────┬─────────┘
         │ sends action + proof
         ▼
┌──────────────────────┐
│ Protected Endpoint   │  ← trust / enforcement boundary
└────────┬─────────────┘
         │ verifies proof before side effect
         ▼
┌──────────────────────┐
│ Proof Verifier       │
│ Policy Boundary      │
│ Replay / Escrow      │
│ Credential Broker    │
└────────┬─────────────┘
         │ allowed only if valid
         ▼
┌──────────────────────┐
│ Consequential Action │
└────────┬─────────────┘
         ▼
┌──────────────────────┐
│ Receipt / Refusal    │
└──────────────────────┘
```

The strongest deployment pattern removes standing production credentials from the agent path:

```text
agent -> protected endpoint -> brokered single-use credential -> production system
no standing agent credential
```

If the agent still has a raw production credential that can reach the provider directly, Actenon can still produce useful proof, receipts, and refusals for the protected path, but it cannot stop side-door execution on the unprotected path.

Read more:

- [docs/architecture/TECHNICAL_ARCHITECTURE.md](docs/architecture/TECHNICAL_ARCHITECTURE.md)
- [docs/architecture/TRUST_BOUNDARIES.md](docs/architecture/TRUST_BOUNDARIES.md)
- [docs/architecture/BYPASS_RESISTANCE.md](docs/architecture/BYPASS_RESISTANCE.md)
- [docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md)

---

## Protect An MCP Tool In 3 Steps

Actenon can protect MCP tools that perform consequential actions such as file writes, database changes, payment actions, deployment changes, email sends, browser submits, or data exports.

### Step 1: Identify the side effect

Before:

```python
@mcp.tool()
def delete_customer(customer_id: str):
    db.execute("DELETE FROM customers WHERE id = ?", [customer_id])
    return {"status": "deleted"}
```

This tool allows execution whenever the MCP server receives the tool call.

### Step 2: Require proof at the protected endpoint

After:

```python
@mcp.tool()
def delete_customer(customer_id: str, proof: dict):
    action = {
        "type": "database.delete",
        "resource": "customers",
        "parameters": {
            "customer_id": customer_id
        }
    }

    verification = actenon.verify(
        proof=proof,
        action=action,
        audience="mcp://customer-admin/delete_customer"
    )

    if not verification.allowed:
        return actenon.refuse(
            reason=verification.reason,
            action=action
        )

    db.execute("DELETE FROM customers WHERE id = ?", [customer_id])

    return actenon.receipt(
        status="executed",
        action=action,
        proof=proof
    )
```

### Step 3: Test the refusal path

A protected MCP tool should refuse when proof is:

- missing
- expired
- replayed
- audience-mismatched
- action-mismatched
- parameter-mismatched
- issued for a different tenant, subject, or policy boundary

The rule is simple:

> The tool must verify proof before the side effect executes.

The MCP client, agent, or model may request the action, but the protected endpoint decides whether the action is allowed.

Start with:

- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [examples/mcp_protected_tool/](examples/mcp_protected_tool/)
- [examples/mcp_server_protected_tool/README.md](examples/mcp_server_protected_tool/README.md)
- [INTEGRATIONS.md](INTEGRATIONS.md)

---

## For Security Leaders

### Problem

Agents can now act with standing authority. They can submit forms, change records, export data, modify code, deploy software, send emails, move money, delete files, or call privileged APIs.

The risk is not only what the model says. It is what the connected system lets the model do.

### Control

Actenon requires proof-bound execution at the protected endpoint.

The endpoint only executes a consequential action when it can verify proof bound to the exact action being requested.

### Evidence

Actenon emits:

- **Receipt**: evidence that a specific action was executed under a defined proof and policy boundary.
- **Refusal**: evidence that a requested action was blocked because proof verification failed.

### Limit

Actenon only protects actions routed through a protected endpoint.

It does not claim to prevent all prompt injection, all unsafe model behaviour, all misuse, or all unrouted actions.

The narrow claim is:

> If a consequential action is routed through an Actenon-protected endpoint, it cannot execute unless valid proof is verified for that exact action.

---

## Where Actenon Would Have Changed the Outcome

Actenon is built for the execution gap exposed by real AI-agent failure patterns: the moment an agent moves from suggesting an action to actually causing one.

| Failure pattern | Consequential action | What Actenon would enforce |
| --- | --- | --- |
| [Production database deletion](docs/incidents/REPLIT_STYLE_DATABASE_DELETE.md) | Agent attempts a destructive database action | No exact signed proof → refused before execution; Refusal artifact emitted |
| [Destructive production action](docs/incidents/PRODUCTION_DESTRUCTIVE_ACTION.md) | Agent reaches a high-impact production side effect | Proof must bind the exact action, subject, tenant, audience, and expiry |
| [Data export / exfiltration](docs/incidents/DATA_EXPORT_EXFILTRATION_PATTERN.md) | Agent attempts to export sensitive data | Export requires scoped proof, policy approval, audience binding, and receipt |
| [IAM privilege escalation](docs/incidents/IAM_PRIVILEGE_ESCALATION_PATTERN.md) | Agent attempts access, role, or permission changes | Access mutation requires proof-bound approval and credential brokering |
| [MCP/tool proof laundering](docs/incidents/MCP_TOOL_PROOF_LAUNDERING.md) | Agent routes a consequential action through a tool boundary | Tool execution requires proof at the protected endpoint |
| Browser / computer-use form submission | Agent clicks, submits, updates, uploads, or exports through a UI | Submit/update/export actions require proof before side effect |

Actenon does not claim every historical incident would automatically have been prevented in every deployment. The claim is narrower and testable: **if a consequential action is routed through a protected endpoint, it cannot execute without valid proof bound to that exact action.**

---

## How Actenon Can Be Bypassed

Actenon only protects actions routed through the protected execution boundary.

It cannot protect an action if the agent still has direct standing credentials, if the provider API can be called outside the protected endpoint, if replay is not enforced at the endpoint, or if proof verification happens only upstream.

The strongest deployment pattern removes standing production credentials from the agent path and requires the protected endpoint to verify proof before brokering a single-use credential or performing the side effect.

## Artifact Snippet

The demo writes local artifacts under `artifacts/hero_demo_runtime/`.

Refused-action summary:

```json
{
  "outcome": "refused",
  "reason_code": "ACTION_HASH_MISMATCH",
  "side_effect_executed": false,
  "pccb_id": "pccb_incident_replit",
  "action_hash": "badc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffe",
  "artifact_digest": "sha256:9408f4573e097f38d38a483280ec70b3737df74d4119e09af4615b19840ff121"
}
```

Allowed-path receipt:

```json
{
  "outcome": "executed",
  "side_effect_executed": true,
  "receipt_id": "rcpt_sim_replay_0002",
  "pccb_id": "pccb_sim_replay_001",
  "artifact_digest": "sha256:353c73da14c3a6884c5308cf7d3826d8faeda8413a80ada9a1e2aab879fbfc71"
}
```

---

## Consequential Action Gallery

Actenon is not limited to database deletes. The same proof-before-execution pattern applies anywhere an AI agent can cause a real side effect.

| Surface | Demo | What Actenon shows |
| --- | --- | --- |
| DevOps / Database | ![Actenon DevOps demo](docs/assets/actenon-hero-devops.gif) | Unproven destructive data action is refused before execution. |
| Fintech / Payments | ![Actenon Fintech demo](docs/assets/actenon-demo-fintech.gif) | Unapproved money movement is refused; approved payment executes once with a receipt. |

All demos are safe local simulations. They do not perform real database, payment, email, cloud, or browser actions.

---

## Scanner Advisory Language

The scanner maps candidate AI-controlled consequential action paths. It does not accuse maintainers of shipping vulnerabilities.

Use this wording when interpreting scanner output:

```text
Candidate consequential action path.
Not a vulnerability claim.
Runtime reachability not proven.
Exploitability not proven.
Production exposure not proven.
Suggested neutral control: add approval or proof gate before submit/delete/export/update/payment/deploy.
Actenon equivalent: ProtectedExecutor or protected endpoint with action-bound proof verification.
```

Preferred report language:

```text
Critical-impact candidate action path, if reachable and ungated.
```

Avoid:

```text
Critical vulnerability detected.
```

Consequence Class is not Vulnerability Severity. A critical-impact candidate means an action surface could have critical consequences if reachable, agent-controlled, and ungated. It does not mean a critical vulnerability has been proven.

Start with:

- [docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md)
- [docs/examples/scanner-report-example.md](docs/examples/scanner-report-example.md)
- [Execution Gap Scanner Methodology](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md)

Quick scanner path:

```bash
python3 -m actenon.cli scan --target replay-harness
python3 -m actenon.cli scan repo --path .
python3 -m actenon.cli scan mcp --path examples/mcp_server_protected_tool
```

---

## What Actenon Does / Does Not Do

Actenon does:

- refuse unproven consequential actions at a protected endpoint
- bind proof to exact action parameters
- bind proof to tenant, subject, audience, expiry, scope, and replay identity
- consume replay or escrow where configured
- broker credentials after verification
- emit Receipt and Refusal artifacts
- support local verification, conformance tests, and copied Cloud-issued artifact verification without requiring a hosted service

Actenon does not:

- stop a model from trying to act
- make a bad-but-authorized action good
- protect paths not routed through a protected endpoint
- prove downstream business finality
- replace IAM, OAuth, service mesh, API gateways, or human approval workflows
- certify that a repo is vulnerable
- guarantee that every historical incident would have been prevented
- claim insurer endorsement, regulator recognition, hosted transparency, or production KMS/HSM custody in the OSS kernel

---

## Standard And Governance

Actenon provides verifiable evidence that a specific consequential action was approved, refused, executed, or blocked under a defined proof and policy boundary.

The standards doctrine is simple:

> Neutralize the standard, monetize the operation.

You do not need Actenon Cloud to issue, verify, or test compatible receipts. You do not need to ask Actenon's permission to implement the neutral Verifiable Action Receipt surface or verify artifacts that conform to the open specs.

The open kernel, specs, conformance suite, SDKs, and examples in this repository are licensed under Apache-2.0. Apache-2.0 keeps the surface permissive while adding an explicit contributor patent grant, which supports neutral infrastructure adoption by implementers, competitors, platforms, and standards-oriented users.

Read:

- [GOVERNANCE.md](GOVERNANCE.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [SPEC_INDEX.md](SPEC_INDEX.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)
- [VERSIONING_POLICY.md](VERSIONING_POLICY.md)

---

## Cloud Neutrality

You do not need Actenon Cloud to issue, verify, or test compatible receipts.

The open-source Actenon verifier, receipt semantics, conformance vectors, and local examples are designed to work without a hosted dependency.

A hosted control plane may provide enterprise policy management, approval workflows, dashboards, credential brokering, audit storage, tenant administration, and evidence operations, but receipt verification and conformance testing remain open.

---

## Cloud-Issued Artifacts Verified By The Open Kernel

The accepted v2 keystone proves the two-repo story:

- Actenon Cloud issues a pilot invoice-payment proof.
- Cloud exports a real kernel-compatible PCCB.
- Cloud emits copied Receipt and Refusal attestation envelopes.
- The open Kernel verifies those artifacts through well-known key discovery.
- Mutating signed fields, wrong key ids, wrong key purpose, expiry, and hard-revoke-without-anchor cases fail verification.

Start with:

- [docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md](docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md)
- [conformance/vectors/cloud_invoice_payment_v1/](conformance/vectors/cloud_invoice_payment_v1/)

Finance and invoice payment are one high-stakes proof point for consequential action receipts. The kernel remains horizontal: the same receipt standard applies to destructive infrastructure operations, privileged access grants, sensitive data exports, payments, refunds, and protected agent tools when those wedges are implemented and enforced.

---

## What This Proves

- external verification of Cloud-issued proof artifacts
- origin and integrity verification for copied Receipt/Refusal attestation envelopes
- mutation and tampering failure for signed proof and outcome fields
- purpose-bound key discovery for proof issuance versus outcome attestation

## What This Does Not Prove

- that the upstream business decision was correct
- that a downstream provider action reached finality
- that an adapter or external provider behaved honestly after handoff
- that replay protection is active unless it is deployed and enforced at the protected endpoint
- that hosted transparency, long-term archive, RFC-3161-style timestamping, or production KMS/HSM custody exists in the OSS kernel

---

## What This Repository Is

This repository is the public open kernel for proof-bound consequential execution.

It owns:

- canonical public contracts under [`/spec`](spec)
- versioned public schemas under [`/schemas`](schemas)
- the reference verifier implementation and protected endpoint pattern
- the complete local single-node trust runtime
- local proof mode and replay/refusal/receipt primitives
- verifier-edge SDKs
- conformance tests and reusable examples
- local advisory scanner for candidate AI-controlled consequential action paths

This repository is meant to be the default developer product for the category. It should read like serious execution infrastructure, not like an internal implementation dump and not like a thin open wrapper around a closed service.

---

## What The Kernel Publishes

- `Action Intent`: the public request contract for a consequential action
- `Intent Record`: the additive bounded-delegation artifact for local issuer, simulator, and future runtime-enforcement paths
- `PCCB`: the proof artifact a protected endpoint verifies before execution
- `Receipt`: the canonical structured outcome artifact
- `Refusal`: the canonical structured failure artifact
- `Protected Endpoint`: the execution-edge behavior that verifies proof before side effects
- `Replay`: the duplicate-execution defense surface

Start here:

- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [CATEGORY.md](CATEGORY.md)
- [QUICKSTART.md](QUICKSTART.md)
- [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [TRACE_VIEWER.md](TRACE_VIEWER.md)
- [SPEC_INDEX.md](SPEC_INDEX.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)
- [docs/reference/EXECUTION_SEMANTICS.md](docs/reference/EXECUTION_SEMANTICS.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [INTEGRATIONS.md](INTEGRATIONS.md)

---

## What `No Proof, No Action` Means

`No proof, no action` means a protected endpoint does not execute a consequential side effect just because:

- the caller is authenticated
- an internal service said "allow"
- a workflow step completed
- an approval happened somewhere upstream
- the model, agent, or tool requested it

It executes only after verifier-side checks succeed against portable proof bound to the exact execution attempt.

That exactness matters because many consequential failures are not simple "unauthenticated caller" failures. They are "approved upstream, executed differently downstream" failures:

- wrong parameters
- wrong target
- wrong audience
- wrong tenant or subject
- duplicate execution through replay
- stale proof reuse
- proof forwarded across the wrong tool boundary

Replay protection only helps when the replay path is actually enforced at that protected endpoint. If a host bypasses or disables replay enforcement, the kernel cannot prevent duplicate execution.

For storage, SQLite is the default local and single-node replay backend. For production OSS deployments with multiple workers, processes, containers, or nodes, use `PostgresReplayStore` so every protected endpoint instance claims against the same transactional replay table:

```bash
pip install "actenon-kernel[postgres]"
```

```python
from actenon.replay import PostgresReplayStore, ReplayProtector

replay_protector = ReplayProtector(
    PostgresReplayStore(dsn="postgresql://actenon:secret@db.example/actenon")
)
```

The normative behavior for that edge lives in:

- [spec/pccb/SPEC.md](spec/pccb/SPEC.md)
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [spec/replay/SPEC.md](spec/replay/SPEC.md)

---

## First Run

The shortest credible first run is:

```bash
python3 -m pip install -e ".[asymmetric]"
python3 -m actenon.cli up
actenon doctor
actenon simulate --incident replit
python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime
actenon bundle export --runtime-dir artifacts/local_runtime
actenon bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon
```

That path is intentionally product-shaped:

- `python3 -m actenon.cli up` starts a complete local trust machine
- `actenon doctor` tells you whether it is healthy
- `actenon simulate --incident replit` makes the execution gap memorable
- the protected refund endpoint proves you can guard a dangerous endpoint now
- `actenon bundle export` creates a `.actenon` portable execution evidence bundle
- `actenon bundle verify` proves the bundle is internally consistent and tamper-evident relative to its manifest, while staying explicit that v1 is not attestation-of-origin

If you want the exact walkthrough, start with [QUICKSTART.md](QUICKSTART.md) and then [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md).

---

## Try It Locally

Single-node runtime path:

```bash
python3 -m pip install -e ".[asymmetric]"
python3 -m actenon.cli up
```

In another terminal:

```bash
actenon doctor
actenon simulate --incident replit
```

`python3 -m actenon.cli up` starts the local single-node trust runtime. By default it serves:

- `POST /v1/intents` on `http://127.0.0.1:8787/v1/intents`
- `GET /.well-known/actenon/keys.json` and `GET /.well-known/actenon-keys.json`
- `GET /healthz`
- the local read-only trace viewer on `http://127.0.0.1:8421` when that port is available

In default local `HS256` trust mode, the key-discovery URLs are present but return an explicit unavailable response until you place a publishable key-discovery document at `artifacts/local_runtime/keys/actenon-keys.json`.

`actenon simulate` is the fastest way to make the execution gap legible:

```bash
actenon simulate --incident replit
```

Each incident run is an educational simulation inspired by public incidents, not an exact forensic reconstruction. The simulator writes an `INCIDENT_SUMMARY.md` into each incident or scenario directory and shows:

- the counterfactual outcome without execution-edge verification
- what proof verification catches directly
- what still requires protected-endpoint runtime state, such as replay enforcement
- what the persisted Action Intent plus Receipt or Refusal lets you prove afterward

If the local runtime is serving with the trace viewer enabled, refresh the viewer after a simulation run and open the `Incident Simulator` run to inspect those same incident artifacts interactively.

---

## Authorization, Intent, Proof, Evidence

Actenon separates four things explicitly:

- **authorization**: who may ask for something
- **intent**: what bounded machine action is actually being delegated, including prohibited actions, abort conditions, blast-radius limits, required approvals, and required evidence
- **proof**: the `PCCB` that a protected endpoint verifies before side effects
- **execution evidence**: the `Receipt`, `Refusal`, receipt chain, and evidence query surfaces that show what actually happened

The draft Intent Record layer is additive. It does not replace `Action Intent` or `PCCB`, and it does not change active v1 proof semantics. It makes bounded delegation inspectable in the local issuer and simulator paths now, while leaving broader enforcement work for future versions.

The current draft artifact shape and semantics live in [spec/intent-record/SPEC.md](spec/intent-record/SPEC.md).

---

## Compatibility And Conformance

This repository is a public compatibility target, not only a reference implementation.

Compatibility means honoring the active public contracts and behavior for:

- Action Intent
- PCCB
- Protected Endpoint
- Replay
- Receipt
- Refusal

Current compatibility does not include Reconciliation or Policy Bundle. Those remain reserved public surfaces, not active v1 standards.

The Protected Endpoint is the central behavioral compatibility surface. A system is not meaningfully compatible if proof verification happens only upstream while the execution edge can still act without re-checking proof and replay requirements.

Fastest compatibility path:

```bash
python3 -m pip install -e ".[asymmetric]"
python3 -m actenon.cli conformance run
```

Start here:

- [CONFORMANCE.md](CONFORMANCE.md)
- [SPEC_INDEX.md](SPEC_INDEX.md)
- [docs/guides/CONFORMANCE_TESTS_GUIDE.md](docs/guides/CONFORMANCE_TESTS_GUIDE.md)
- [docs/guides/COMPATIBILITY_FAQ.md](docs/guides/COMPATIBILITY_FAQ.md)

---

## Specs, SDKs, And Integrations

Python is the reference kernel path. TypeScript and Go are verifier-edge SDK paths; the current tested support posture lives in [SUPPORT_AND_COMPATIBILITY_STATUS.md](SUPPORT_AND_COMPATIBILITY_STATUS.md).

Framework example sequence:

1. MCP
2. LangChain
3. Claude Managed Agents
4. LlamaIndex
5. CrewAI
6. Semantic Kernel

MCP remains the neutral hero path. Claude Managed Agents is a strong secondary platform example. The other framework examples support category distribution and adoption, but they are not equal launch stories.

The Claude Managed Agents example is Anthropic-specific but kernel-compatible. It is there to show the same verifier-first execution boundary on one managed agent surface, not to imply partnership, endorsement, or hosted control-plane coupling.

Read:

- [docs/reference/verifier/VERIFIER_SDK_REFERENCE.md](docs/reference/verifier/VERIFIER_SDK_REFERENCE.md)
- [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [SUPPORT_AND_COMPATIBILITY_STATUS.md](SUPPORT_AND_COMPATIBILITY_STATUS.md)
- [sdk/typescript/README.md](sdk/typescript/README.md)
- [sdk/go/README.md](sdk/go/README.md)
- [sdk/rust/README.md](sdk/rust/README.md)
- [INTEGRATIONS.md](INTEGRATIONS.md)
- [docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md](docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md)

---

## Docs Navigation

| Start here | Why |
| --- | --- |
| [Quickstart](QUICKSTART.md) | Run the local proof-gate demo path. |
| [First 10 Minutes](docs/guides/FIRST_10_MINUTES.md) | Walk through the first local runtime and inspection flow. |
| [Execution Gap](THE_EXECUTION_GAP.md) | Understand the problem Actenon exists to solve. |
| [Scanner Methodology](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md) | Understand the advisory scanner and consequence-class wording. |
| [Preflight](docs/guides/PREFLIGHT.md) | See the local policy/evidence decision surface. |
| [Credential Broker](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md) | Remove standing credentials from agent runtime paths. |
| [MCP Hero Path](MCP_HERO_PATH.md) | Wrap consequential MCP tools with a proof gate. |
| [External Anchors](docs/guides/EXTERNAL_ANCHORS.md) | Add local durability evidence outside signed payloads. |
| [Threat Model](THREAT_MODEL.md) | Review assets, attacker classes, mitigations, and limits. |
| [Open Source Boundary](OPEN_SOURCE_BOUNDARY.md) | Understand what is public kernel versus private/commercial scope. |
| [Governance](GOVERNANCE.md) | Read the open standard and stewardship posture. |
| [Conformance](CONFORMANCE.md) | Run and interpret the compatibility test surface. |

---

## Who This Is For

- platform teams protecting consequential tools, routes, or provider calls
- security teams that want execution-edge guarantees instead of policy-only claims
- SDK and framework teams integrating protected tools or protected routes into agent stacks
- open-source maintainers who want neutral advisory scanner output rather than vulnerability theatre
- enterprise architects composing agent controls with IAM, OAuth, gateways, service mesh, approval systems, and credential brokers
- teams that need portable receipts and refusals, not only internal logs
- open-source adopters who want a verifier-first path without committing to a hosted layer

---

## What The Kernel Guarantees

When integrated correctly, the OSS kernel guarantees:

- public, versioned contracts instead of hidden request shapes
- exact proof binding to action, target, tenant, subject, audience, scope, expiry, and nonce at the protected endpoint
- protected-endpoint refusal of mutated, expired, mis-addressed, mis-scoped, or replayed requests before side effects when the relevant checks are actually enforced
- optional local PCCB mint audit records for retrospective issuer-side inspection when a minter is configured with an audit sink
- structured Receipt and Refusal artifacts with stable public meaning
- opt-in signed Receipt/Refusal attestation envelopes for deployments that need portable origin checks on copied outcome artifacts
- deterministic local proof mode and a public conformance target for compatible implementations

It does not guarantee provider truthfulness, hosted workflow correctness, production key custody, long-term archive, or enterprise operations. Read the exact line in [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

---

## What This Does Not Solve

- a compromised issuer, signer, or external control plane can still mint or cause minting of valid proof for the wrong action
- mint audit records improve detectability after the fact; they do not prevent bad proof issuance or prove the upstream business decision was correct
- a malicious or buggy adapter can still lie about downstream side effects after control passes to it
- replay defense only exists where the protected endpoint actually enforces the replay path
- v1 Receipt and Refusal artifacts by themselves are canonical structured artifacts, not portable cryptographic attestations of origin
- provider-backed reconciliation or finality is not part of active v1
- reserved surfaces such as Reconciliation and Policy Bundle are named extension boundaries, not active v1 standards

For portable origin checks, use the opt-in Outcome Attestation v2alpha1 envelope in [spec/outcome-attestation/SPEC.md](spec/outcome-attestation/SPEC.md). The attestation envelope signs an embedded v1 Receipt or Refusal; it does not change v1 outcome semantics or add hosted trust services.

---

## Where The Paid Layer Begins

This repository is not the hosted control plane and must not become it.

The paid control plane begins where the product requires:

- approvals and workflow routing
- evidence intake and review
- provider runtime services
- reconciliation operations
- hosted transparency or network-scale audit services
- long-term archive and dashboards
- audit operations
- billing, tenant administration, and enterprise multi-tenancy

The exact boundary is defined in [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md).

---

## Best First Contributions

Actenon is suitable for contributors interested in AI agents, security tooling, MCP, open standards, developer experience, and execution governance.

Good first contribution areas:

### Scanner Rules

Add or improve detection rules for consequential action paths, including:

- shell execution
- file writes and deletes
- browser submit actions
- email sends
- data exports
- payment actions
- deployment actions
- IAM or permission changes
- database mutations
- MCP tool side effects

### Framework Examples

Add minimal proof-gated examples for:

- MCP servers
- LangChain tools
- CrewAI tools
- LlamaIndex tools
- browser-use agents
- OpenAI tool-calling agents
- GitHub automation agents

### Documentation

Improve:

- quickstart clarity
- architecture diagrams
- threat model examples
- scanner report wording
- receipt/refusal examples
- security leader explanations

### SDK Conformance

Add conformance tests for language SDKs and receipt verification.

### Test Fixtures

Add intentionally unsafe example repos or fixtures that demonstrate candidate action paths and expected scanner output.

Useful labels:

```text
good first issue
scanner
docs
sdk
mcp
conformance
examples
security
architecture
```

---

## Community

If you want to contribute, report a bug, ask a compatibility question, or review project expectations, start here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [LICENSE](LICENSE)

---

## Release Checklist

Before a public release or launch archive, run:

```bash
bash scripts/verify_release_gate.sh
```

That gate blocks on the focused keystone suite, full `pytest tests/`, Ruff, public boundary validation, and public archive creation/validation.
