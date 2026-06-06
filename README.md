# actenon-kernel

**The open proof gate and receipt standard that protects your systems from any agent's actions.**

> **No valid proof, no execution.**

Actenon sits at your execution boundary — your database, your payments rail, your cloud control plane, your internal APIs, your deploy pipeline — and refuses any consequential action unless the caller presents a cryptographic proof bound to the exact action being attempted.

It doesn't matter whether the action comes from your own AI agent, a third-party agent, an MCP tool, a browser or coding agent, a workflow automation, or a compromised one: if the proof is missing, expired, replayed, or bound to a different action, the action is refused before the side effect, and every decision leaves a verifiable **Receipt** or **Refusal** artifact.

**Actenon gates explicit execution-edge actions; it does not inspect or filter
prompts, model output, or in-band response content.**

**It can require proof for an explicit export or transmit action, but it does
not stop data disclosed inside ordinary output unless that disclosure is itself
modeled and routed as a protected action.**

**You protect your boundary. The agent does not have to cooperate, trust you, or even know Actenon exists.**

[![Actenon demo: an unproven agent action is refused before the side effect](docs/assets/actenon-hero-devops.gif)](docs/assets/actenon-hero-devops.gif)

[![CI](https://github.com/Actenon/actenon/actions/workflows/ci.yml/badge.svg)](https://github.com/Actenon/actenon/actions/workflows/ci.yml) · [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) · [![Python 3.9–3.12](https://img.shields.io/badge/python-3.9--3.12-blue)](pyproject.toml) · [Conformance suite](CONFORMANCE.md) · [Adversarial security tests](docs/security/SECURITY_TESTING.md) · [Release gate](scripts/verify_release_gate.sh)

---

## The shift: agents now touch systems you don't control

AI agents no longer just produce text. They call your APIs, hit your provider endpoints, change your state, and trigger irreversible actions — deleting data, moving money, changing access, deploying code, exporting records.

And increasingly, the agent reaching your system was not built by you. It's a partner's agent, a customer's agent, an autonomous workflow, an open-source tool, or an agent that has been prompt-injected or otherwise compromised. You cannot make every agent that touches your systems adopt your safety library. You cannot review their prompts. You cannot trust their reasoning.

So the only place you can enforce safety is your own boundary — the endpoint, gateway, or resource the action actually hits. That is what Actenon protects: it lets the resource owner demand proof from any agent, and refuse anything unproven, before a single side effect occurs.

This is the edge-protection model: like a WAF or an API gateway, you adopt it once at your boundary and you are protected against the entire agent ecosystem — cooperative, third-party, or hostile.

**The edge guarantee applies only when the protected edge is the only path to
the resource, the backend accepts only brokered credentials issued after
verification, and the agent has no standing credential or alternate route.**

Read the full problem statement in [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md).

---

## Quickstart

```bash
git clone https://github.com/Actenon/actenon.git
cd actenon

python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[asymmetric]"

python examples/quickstart_min.py
```

This local-only quickstart uses the packaged `ActenonGate` API. It executes the valid exact action once, refuses a mismatched action, and refuses replay:

```text
ACTENON QUICKSTART
valid: EXECUTED
mismatch: REFUSED (INTENT_MISMATCH)
replay: REFUSED (DUPLICATE_REPLAY)
side_effects: 1

No valid proof, no execution.
```

It does not contact a cloud account, use external secrets, or perform a real destructive action. The local HMAC signer is for development only.

---

## See Actenon stop money movement

The simplest way to understand Actenon is a financial agent.

The agent can reason about a transfer. It can ask to transfer funds. It can even be prompt-injected into trying the wrong transfer.

But the ledger does not move unless the protected financial boundary receives valid proof bound to the exact amount, destination, tenant, subject, audience, expiry, and replay identity.

Run the example:

```bash
python3 -m pytest examples/financial_agent_protected_transfer -q

---

## See it in 60 seconds

For the cinematic refusal-before-side-effect demo:

```bash
bash scripts/demo_hero.sh
```

You will see:

```text
ACTENON
No valid proof, no execution.

Agent attempts:
  database.delete_table production_customers

WITHOUT proof gate:
  WOULD EXECUTE
  side_effect_executed: true

WITH ACTENON:
  REFUSED
  reason_code: ACTION_HASH_MISMATCH
  side_effect_executed: false
  refusal artifact: artifacts/hero_demo_runtime/live/simulations/replit/refusal.json

VALID PROOF:
  EXECUTED ONCE
  side_effect_executed: true
  receipt artifact: artifacts/hero_demo_runtime/live/simulations/replay-refused/execution_receipt.json

Done: unproven action refused; valid proof executed once.
```
---

# FastMCP Financial Transfer Example

This example shows the developer experience Actenon should make default:

> simple MCP tool, deterministic execution boundary.

The LLM can request a financial transfer, but the ledger mutation is protected by Actenon. Missing, mismatched, replayed, expired, or policy-denied proof is refused before the side effect.

This example is intentionally focused on developer ergonomics:

- FastMCP exposes the tool with a simple decorator.

- Actenon protects the execution boundary.

- The ledger does not trust the model.

- Valid proof executes once.

- Invalid proof emits refusal evidence.

## Why this matters

Developers choose the path of least resistance.

If secure agent tools require complex boilerplate, they will eventually be bypassed. The secure path must be the easy path.

FastMCP gives the simple tool surface. Actenon gives the deterministic proof gate.

## Run

```bash

python3 -m pytest examples/fastmcp_financial_transfer -q

---

For the incident-style walkthrough and local runtime:

```bash
python3 -m actenon.cli simulate --incident replit
python3 -m actenon.cli up
python3 -m actenon.cli doctor
```

The full walkthrough is in [QUICKSTART.md](QUICKSTART.md) and [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md).

---

## Choose your path

| If you are… | Start here |
| --- | --- |
| Protecting a system agents can reach | [The resource-side edge model](#protect-your-resource-boundary) |
| Just curious | Watch the GIF, run `bash scripts/demo_hero.sh` |
| Building agents or MCP tools | [Protect an MCP tool in 3 steps](#protect-an-mcp-tool-in-3-steps) · [MCP_HERO_PATH.md](MCP_HERO_PATH.md) |
| Reviewing security | [Why this isn't just middleware](#why-this-isnt-just-middleware) · [THREAT_MODEL.md](THREAT_MODEL.md) · [Security testing](docs/security/SECURITY_TESTING.md) |
| Designing enterprise architecture | [docs/architecture/TRUST_BOUNDARIES.md](docs/architecture/TRUST_BOUNDARIES.md) · [docs/architecture/DEPLOYMENT_ARCHITECTURES.md](docs/architecture/DEPLOYMENT_ARCHITECTURES.md) |
| Maintaining an open-source agent repo | [The advisory scanner](#the-advisory-scanner) |
| Evaluating governance or standards | [An open standard, not lock-in](#an-open-standard-not-lock-in) · [CONFORMANCE.md](CONFORMANCE.md) · [GOVERNANCE.md](GOVERNANCE.md) |
| Considering contributing | [Contributing](#contributing) |

---

## The execution gap

Most stacks already have authentication, policy, approval, or workflow state. Those matter — but they don't guarantee that the execution edge performs the exact approved action, exactly once. An action can be approved upstream and then executed with the wrong parameters, the wrong target, the wrong tenant, or executed twice. And none of them stop an action arriving from an agent you never authorized in the first place.

That missing boundary is the execution gap, and Actenon closes it with proof-bound execution: the protected endpoint independently verifies a proof bound to the exact action, audience, tenant, subject, target, scope, expiry, and replay identity before any side effect happens — regardless of who or what sent the request.

---

## Why this isn't just middleware

Actenon is not a client-side safety wrapper. The agent and the SDK are not the trust boundary — the protected endpoint is. This is what makes it work against agents you don't control: enforcement lives on your side.

```text
   Untrusted agent  (yours, a third party's, or hostile — doesn't matter)
        │  wants to act
        ▼
   SDK / tool client
        │  sends action + proof
        ▼
┌─────────────────────────┐
│   Protected endpoint    │  ← enforcement boundary (you own this)
└─────────────────────────┘
        │  verifies proof before any side effect
        ▼
   Proof verifier · policy · replay/escrow · credential broker
        │  allowed only if valid, exact-action proof
        ▼
   Consequential action
        ▼
   Receipt or Refusal artifact
```

A consequential action executes only when the endpoint verifies proof bound to the exact action parameters, tenant, subject, audience, expiry, and replay state. If the proof is missing, expired, replayed, audience-mismatched, action-mismatched, parameter-mismatched, tenant-mismatched, or policy-denied, the endpoint refuses before the side effect and emits a Refusal.

**This is why prompt injection can make an agent want to act, but it should not make a protected action execute without valid proof.**

The strongest deployment removes standing production credentials from the agent path entirely:

```text
agent → protected endpoint → brokered single-use credential → production system
(no standing agent credential)
```

If an agent still holds a raw production credential that reaches the provider directly, Actenon can still produce proof, receipts, and refusals for the protected path — but it cannot stop side-door execution on an unprotected one. The guarantee holds only when your resource is reachable solely through the protected edge.

See [docs/architecture/TRUST_BOUNDARIES.md](docs/architecture/TRUST_BOUNDARIES.md), [docs/architecture/BYPASS_RESISTANCE.md](docs/architecture/BYPASS_RESISTANCE.md), and [docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md).

---

## Protect your resource boundary

You adopt Actenon at the boundary you own, and require proof from every caller. The edge builds the intended action from the incoming request and requires the proof to bind that exact request — so a proof issued for a harmless action cannot be reused to authorize a harmful one.

| Resource boundary you own | Protected against |
| --- | --- |
| Database / data store | An agent dropping, deleting, or mutating production data |
| Payments / financial rails | An agent inflating, redirecting, or duplicating a payout |
| Cloud / infrastructure control plane | An agent terminating fleets or deleting resources |
| IAM / access control | An agent escalating privilege or granting access |
| Object storage / filesystem | An agent deleting backups or exfiltrating objects |
| CI/CD / deploy / source control | An agent shipping untested code or deleting repos |
| Communications / messaging | An agent blasting customers or sending on your behalf |
| Internal / provider APIs | Any consequential call arriving without bound proof |

---

## Protect an MCP tool in 3 steps

If you also build agents or MCP tools, you protect the tool's side effect the same way.

**1. Identify the side effect.** This tool executes whenever the MCP server receives the call:

```python
@mcp.tool()
def delete_customer(customer_id: str):
    db.execute("DELETE FROM customers WHERE id = ?", [customer_id])
    return {"status": "deleted"}
```

**2. Require proof at the endpoint.** Keep proof out of the model-facing tool schema. FastMCP injects `Context`; the runtime attaches proof metadata there:

```python
from actenon import ActenonGate
from actenon.adapters.mcp import protected_mcp_tool
from mcp.server.fastmcp import Context

gate = ActenonGate(
    verifier=proof_verifier,
    audience="service:customer-admin-delete",
    issuer="service:proof-issuer",
)

@mcp.tool()
@protected_mcp_tool(
    gate,
    action_builder=build_delete_customer_intent,
    audience="service:customer-admin-delete",
)
def delete_customer(customer_id: str, ctx: Context):
    db.execute("DELETE FROM customers WHERE id = ?", [customer_id])
    return {"status": "deleted"}
```

**3. Test the refusal path.** A protected tool must refuse when proof is missing, expired, replayed, audience-mismatched, action-mismatched, parameter-mismatched, or issued for a different tenant, subject, or policy boundary.

Run [`examples/quickstart_min.py`](examples/quickstart_min.py) for the smallest high-level API example, then see [`examples/mcp_server_protected_tool/`](examples/mcp_server_protected_tool/) and [INTEGRATIONS.md](INTEGRATIONS.md).

---

## Consequential Action Coverage Matrix

Actenon ships a fast local coverage matrix for representative consequential action surfaces. It exercises hundreds of deterministic local scenarios across DevOps, Fintech, IAM, Database, Browser, MCP, Data Export, Email, and Code Agent operations.

```bash
python3 -m actenon.cli coverage run
```

Example output:

```text
ACTENON CONSEQUENTIAL ACTION COVERAGE MATRIX

Total scenarios: 540
Domains covered: 9

Domain evidence:
- DevOps:                   60 checks
- Fintech:                  60 checks
- IAM / Access Control:     60 checks
- Database:                 60 checks
- Browser / Computer Use:   60 checks
- MCP Tools:                60 checks
- Data Export:              60 checks
- Email / Communications:   60 checks
- Code Agent Operations:    60 checks

Result: PASS

No valid proof, no execution.
```

These are representative local simulations, not live provider integration tests. Read more: [Consequential Action Coverage Matrix](docs/coverage/CONSEQUENTIAL_ACTION_COVERAGE_MATRIX.md).

---

## What a receipt and a refusal look like

Every decision produces a portable, structured artifact. A refusal:

```json
{
  "outcome": "refused",
  "reason_code": "ACTION_HASH_MISMATCH",
  "side_effect_executed": false,
  "pccb_id": "pccb_incident_replit",
  "action_hash": "badc0ffe…",
  "artifact_digest": "sha256:9408f4573e097f38…"
}
```

An executed action:

```json
{
  "outcome": "executed",
  "side_effect_executed": true,
  "receipt_id": "rcpt_sim_replay_0002",
  "pccb_id": "pccb_sim_replay_001",
  "artifact_digest": "sha256:353c73da14c3a688…"
}
```

These are real artifacts written by the demo under `artifacts/hero_demo_runtime/`. For copied Cloud-issued proof and outcome verification, see [docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md](docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md).

---

## Where Actenon changes the outcome

Actenon is built for the execution gap exposed by real AI-agent failure patterns — the moment an agent moves from suggesting an action to causing one against a system you own.

| Failure pattern | What Actenon enforces |
| --- | --- |
| [Production database deletion](docs/incidents/REPLIT_STYLE_DATABASE_DELETE.md) | No exact signed proof → refused before execution; Refusal emitted |
| [Destructive production action](docs/incidents/PRODUCTION_DESTRUCTIVE_ACTION.md) | Proof must bind the exact action, subject, tenant, audience, and expiry |
| [Data export / exfiltration](docs/incidents/DATA_EXPORT_EXFILTRATION_PATTERN.md) | Export requires scoped proof, policy approval, audience binding, and a receipt |
| [IAM privilege escalation](docs/incidents/IAM_PRIVILEGE_ESCALATION_PATTERN.md) | Access mutation requires proof-bound approval and credential brokering |
| [MCP / tool proof laundering](docs/incidents/MCP_TOOL_PROOF_LAUNDERING.md) | Tool execution requires proof at the protected endpoint |

The claim is narrow and testable: **if a consequential action is routed through an Actenon-protected endpoint, it cannot execute without valid proof bound to that exact action.**

---

## What Actenon does — and does not do

Actenon **does**:

- refuse unproven consequential actions at a protected endpoint, before the side effect — from any caller, cooperative or not
- bind proof to exact action parameters, plus tenant, subject, audience, expiry, scope, and replay identity
- enforce replay/single-use by default, consume escrow where configured, and broker credentials after verification
- emit portable Receipt and Refusal artifacts
- run fully locally — verification, conformance tests, and copied Cloud-issued artifact verification need no hosted service

Actenon **does not**:

- stop a model from trying to act, or make a bad-but-authorized action good
- protect actions that are not routed through a protected endpoint
- stop in-band data disclosure — Actenon gates export/transmit actions, not what a model writes into its own output; pair it with output-side DLP for that
- prevent replay unless every protected edge shares the relevant replay state
- prove downstream business finality, or that a provider behaved honestly after handoff
- replace IAM, OAuth, service mesh, API gateways, or human-approval workflows — it composes with them
- certify that a repo is vulnerable
- claim insurer endorsement, regulator recognition, hosted transparency, or production KMS/HSM custody in the open-source kernel

A compromised issuer or signer can still mint valid proof for the wrong action; mint-audit records improve detectability, not prevention. The complete asset/attacker/limit analysis is in [THREAT_MODEL.md](THREAT_MODEL.md), and the exact guarantees are in [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md).

---

## The advisory scanner

`actenon scan` maps candidate AI-controlled consequential action paths in a repo. It is advisory — it does not accuse maintainers of shipping vulnerabilities.

```bash
python3 -m actenon.cli scan repo --path .
python3 -m actenon.cli scan mcp --path examples/mcp_server_protected_tool
```

Findings use consequence-class language, not vulnerability-severity language:

> *Critical-impact candidate action path, if reachable and ungated.* Not a vulnerability claim. Runtime reachability and exploitability not proven. Suggested control: add an approval or proof gate before the side effect.

A *Critical-impact candidate* means an action surface could have critical consequences if reachable, agent-controlled, and ungated — not that a critical vulnerability has been proven. See [docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md).

---

## An open standard, not lock-in

Actenon provides verifiable evidence that a specific consequential action was approved, refused, executed, or blocked under a defined proof and policy boundary.

> The standard stays open. Operational services are built around it.

You do **not** need Actenon Cloud — or anyone's permission — to issue, verify, or test compatible receipts, or to implement the neutral Verifiable Action Receipt surface. The kernel, specs, conformance suite, SDKs, and examples here are **Apache-2.0**, which adds an explicit contributor patent grant so implementers, competitors, platforms, and standards bodies can adopt it as neutral infrastructure.

A hosted control plane may add enterprise policy management, approvals, dashboards, credential brokering, audit storage, and tenant administration — but receipt verification and conformance testing remain open. The exact public/commercial line is in [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md).

Read: [GOVERNANCE.md](GOVERNANCE.md) · [CONFORMANCE.md](CONFORMANCE.md) · [SPEC_INDEX.md](SPEC_INDEX.md) · [VERSIONING_POLICY.md](VERSIONING_POLICY.md)

Current compatibility target: **Actenon Conformance 1.0.0**. The
machine-readable suite and hash-locked vectors cover exact-action verification,
Receipt counter-signatures, transparency proofs, issuer status, and signed
approvals across Python, TypeScript, Go, and Rust.

```bash
python3 -m actenon.cli conformance run --require-complete
```

The scoped self-certification wording is
`Actenon Verified (Conformance 1.0.0)`. It is a versioned compatibility claim,
not an endorsement or deployment audit.

---

## Documentation

| Topic | Document |
| --- | --- |
| Run the local proof-gate demo | [QUICKSTART.md](QUICKSTART.md) |
| First 10 minutes, end to end | [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md) |
| The problem, in depth | [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md) |
| The category | [CATEGORY.md](CATEGORY.md) |
| Threat model, attackers, limits | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Scope boundary and deployment conditions | [docs/SCOPE_AND_GUARANTEES.md](docs/SCOPE_AND_GUARANTEES.md) |
| Conformance version and security assurance | [docs/SECURITY_ASSURANCE.md](docs/SECURITY_ASSURANCE.md) · [conformance/suite.json](conformance/suite.json) |
| Exact kernel guarantees | [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md) |
| Architecture & trust boundaries | [docs/architecture/TECHNICAL_ARCHITECTURE.md](docs/architecture/TECHNICAL_ARCHITECTURE.md) |
| Credential broker deployment | [docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md) |
| Wrap consequential MCP tools | [MCP_HERO_PATH.md](MCP_HERO_PATH.md) |
| Scanner methodology & wording | [docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md) |
| Consequential action coverage | [docs/coverage/CONSEQUENTIAL_ACTION_COVERAGE_MATRIX.md](docs/coverage/CONSEQUENTIAL_ACTION_COVERAGE_MATRIX.md) |
| High-level proof gate API | [docs/guides/HIGH_LEVEL_GATE_API.md](docs/guides/HIGH_LEVEL_GATE_API.md) |
| SDKs | [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md) · [SUPPORT_AND_COMPATIBILITY_STATUS.md](SUPPORT_AND_COMPATIBILITY_STATUS.md) |
| Specs index | [SPEC_INDEX.md](SPEC_INDEX.md) |
| Open-source vs commercial boundary | [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md) |
| Compliance mapping | [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) |

---

## Who it's for

Actenon is for anyone who owns a system an AI agent can reach — and needs to guarantee that no agent, theirs or anyone else's, can take a consequential action against it without proof.

- **Resource and platform owners** running a database, payments rail, cloud control plane, internal API, object store, deploy pipeline, or messaging system that agents now call.
- **Companies exposed to agents they don't control** through third-party agents, partner integrations, customer-built agents, or autonomous workflows.
- **Security and infrastructure teams** composing agent controls with IAM, OAuth, gateways, and approval systems.
- **Regulated and high-stakes operators** who must prove, with verifiable Receipts and Refusals, that consequential actions were authorized and bounded.
- **SDK and framework teams** integrating protected tools into agent stacks.
- **Open-source maintainers** who want neutral advisory scanning instead of vulnerability theatre.

If an agent can reach your system, Actenon lets you make proof the precondition for action — and lets you prove it afterward.

---

## Contributing

Actenon is a good fit for contributors interested in AI agents, security tooling, MCP, open standards, and developer experience. Strong first contributions:

- **Edge templates** — hardened resource-side gateways for databases, payments, cloud control planes, object storage, CI/CD, IAM, and messaging.
- **Scanner rules** — detection for shell execution, file writes/deletes, browser submits, email sends, data exports, payments, deployments, IAM changes, database mutations, and MCP tool side effects.
- **Framework examples** — minimal proof-gated examples for MCP servers, LangChain, CrewAI, LlamaIndex, browser-use, and tool-calling agents.
- **SDK conformance** — conformance tests for language SDKs and receipt verification.
- **Docs** — quickstart clarity, architecture diagrams, threat-model examples, receipt/refusal examples.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Useful labels: `good first issue`, `edge`, `scanner`, `docs`, `sdk`, `mcp`, `conformance`, `examples`, `security`.

---

## Releasing

Before any public release or launch archive:

```bash
bash scripts/verify_release_gate.sh
```

That gate blocks on the focused keystone suite, the full `pytest` run, Ruff, public-boundary validation, and clean public-archive creation.

---

## License

[Apache-2.0](LICENSE). The open kernel, specs, conformance suite, SDKs, and examples are permissively licensed with an explicit contributor patent grant — chosen so the Verifiable Action Receipt surface can become neutral, widely-adopted infrastructure.
