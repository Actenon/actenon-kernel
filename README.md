# Actenon Kernel

**The open proof gate and receipt standard for consequential AI-agent actions.**

> **No valid proof, no execution.**

Actenon Kernel sits at your execution boundary — your database, payments rail, cloud control plane, internal APIs, MCP tools, browser actions, coding-agent tools, and deploy pipeline — and refuses consequential actions unless the caller presents cryptographic proof bound to the **exact action** being attempted.

It does not matter whether the action comes from your own AI agent, a third-party agent, an MCP tool, a browser or coding agent, a workflow automation, or a compromised one. If proof is missing, expired, replayed, policy-denied, or bound to a different action, the protected boundary refuses before the side effect and emits structured evidence.

Actenon gates explicit execution-edge actions. It does not inspect prompts, filter model output, or replace DLP. It can require proof for an explicit export, payment, delete, deploy, update, send, or access-change action — but the action must be routed through the protected boundary.

**You protect your boundary. The agent does not have to cooperate, trust you, or even know Actenon exists.**

[![Actenon demo: an unproven agent action is refused before the side effect](docs/assets/actenon-hero-devops.gif)](docs/assets/actenon-hero-devops.gif)

[![CI](https://github.com/Actenon/actenon-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Actenon/actenon-kernel/actions/workflows/ci.yml) · [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) · [![Python 3.9–3.12](https://img.shields.io/badge/python-3.9--3.12-blue)](pyproject.toml) · [Conformance suite](CONFORMANCE.md) · [Adversarial security tests](docs/security/SECURITY_TESTING.md) · [Release gate](scripts/verify_release_gate.sh)

---

## The shift: agents now touch systems you do not control

AI agents no longer just produce text. They call APIs, hit provider endpoints, change state, and trigger irreversible actions — deleting data, moving money, changing access, deploying code, exporting records, and sending communications.

Increasingly, the agent reaching your system was not built by you. It may be a partner’s agent, a customer’s agent, an autonomous workflow, an open-source tool, or an agent that has been prompt-injected or otherwise compromised.

You cannot make every agent that touches your systems adopt your safety library. You cannot review their prompts. You cannot trust their reasoning.

So the only reliable enforcement point is the boundary you own: the endpoint, gateway, service, tool, or resource where the side effect actually happens.

That is the Actenon model:

> The agent may ask. The protected boundary decides.

This is the edge-protection model: like a WAF or API gateway, you adopt it once at your boundary and protect the resource from cooperative, third-party, or hostile agent callers.

The edge guarantee applies only when the protected edge is the only path to the resource, the backend accepts only brokered credentials issued after verification, and the agent has no standing credential or alternate route.

Read the full problem statement in [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md).

---

## Quickstart

```bash
git clone https://github.com/Actenon/actenon-kernel.git
cd actenon-kernel

python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[asymmetric]"

python examples/quickstart_min.py
```

Expected output:

```text
ACTENON QUICKSTART
valid: EXECUTED
mismatch: REFUSED (INTENT_MISMATCH)
replay: REFUSED (DUPLICATE_REPLAY)
side_effects: 1

No valid proof, no execution.
```

This local-only quickstart uses the packaged `ActenonGate` API. It executes the valid exact action once, refuses a mismatched action, and refuses replay.

It does not contact a cloud account, use external secrets, or perform a real destructive action. The local HMAC signer is for development only.

---

## See Actenon stop money movement

The simplest way to understand Actenon is a financial agent.

The agent can reason about a transfer. It can ask to transfer funds. It can even be prompt-injected into trying the wrong transfer.

But the ledger does not move unless the protected financial boundary receives valid proof bound to the exact amount, destination, tenant, subject, audience, expiry, and replay identity.

Run the example:

```bash
python3 -m pytest examples/financial_agent_protected_transfer -q
```

The tests prove:

| Scenario | Expected result |
| --- | --- |
| Missing proof | Refused before money moves |
| Wrong amount proof | Refused before money moves |
| Wrong destination proof | Refused before money moves |
| Replay of valid proof | Refused before second transfer |
| Valid exact proof | Executes once and emits receipt evidence |

This is the adoption message: developers should not have to invent security logic for every agent tool. The secure path must be the easiest path.

---

## FastMCP financial transfer example

FastMCP makes the secure path easy for MCP tool builders:

> Simple MCP tool, deterministic execution boundary.

The LLM can request a financial transfer, but the ledger mutation is protected by Actenon. Missing, mismatched, replayed, expired, or policy-denied proof is refused before the side effect.

Run the FastMCP-shaped example:

```bash
python3 -m pytest examples/fastmcp_financial_transfer -q
```

This example is intentionally focused on developer ergonomics:

- FastMCP exposes the tool with a simple decorator.
- Actenon protects the execution boundary.
- The ledger does not trust the model.
- Valid proof executes once.
- Invalid proof emits refusal evidence.

The model is not the trust boundary. The protected endpoint is.

---

## See it in 60 seconds

For the cinematic refusal-before-side-effect demo:

```bash
bash scripts/demo_hero.sh
```

You will see an unproven database deletion-style action refused before the side effect, followed by a valid proof-bound action executing once and producing receipt evidence.

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
| Protecting a system agents can reach | [Resource-side edge deployment](docs/guides/EDGE_DEPLOYMENT.md) |
| Just curious | Watch the GIF, run `bash scripts/demo_hero.sh` |
| Building agents or MCP tools | [Protect an MCP tool in 3 steps](MCP_HERO_PATH.md) |
| Reviewing security | [Threat model](THREAT_MODEL.md) · [Security testing](docs/security/SECURITY_TESTING.md) |
| Designing enterprise architecture | [Trust boundaries](docs/architecture/TRUST_BOUNDARIES.md) · [Deployment architectures](docs/architecture/DEPLOYMENT_ARCHITECTURES.md) |
| Maintaining an open-source agent repo | [Execution gap scanner](EXECUTION_GAP_SCANNER.md) |
| Evaluating governance or standards | [Conformance](CONFORMANCE.md) · [Governance](GOVERNANCE.md) |
| Considering contributing | [Contributing](CONTRIBUTING.md) |

---

## The execution gap

Most stacks already have authentication, policy, approval, or workflow state. Those matter — but they do not guarantee that the execution edge performs the exact approved action, exactly once.

An action can be approved upstream and then executed with the wrong parameters, the wrong target, the wrong tenant, or executed twice. An agent can also reach a tool or provider endpoint that was never designed to be called by a non-deterministic system.

That missing boundary is the **execution gap**.

Actenon closes it with proof-bound execution: the protected endpoint independently verifies a proof bound to the exact action, audience, tenant, subject, target, scope, expiry, and replay identity before any side effect happens — regardless of who or what sent the request.

---

## Why this is not just middleware

Actenon is not a client-side safety wrapper. The agent and SDK are not the trust boundary. The protected endpoint is.

```text
Untrusted agent
     │ wants to act
     ▼
SDK / tool client
     │ sends action + proof
     ▼
┌─────────────────────────┐
│   Protected endpoint    │  ← enforcement boundary
└─────────────────────────┘
     │ verifies proof before any side effect
     ▼
Proof verifier · policy · replay/escrow · credential broker
     │ allowed only if valid, exact-action proof
     ▼
Consequential action
     ▼
Receipt or Refusal artifact
```

A consequential action executes only when the endpoint verifies proof bound to the exact action parameters, tenant, subject, audience, expiry, and replay state.

If the proof is missing, expired, replayed, audience-mismatched, action-mismatched, parameter-mismatched, tenant-mismatched, or policy-denied, the endpoint refuses before the side effect and emits a Refusal.

This is why prompt injection can make an agent want to act, but it should not make a protected action execute without valid proof.

The strongest deployment removes standing production credentials from the agent path entirely:

```text
agent → protected endpoint → brokered single-use credential → production system
(no standing agent credential)
```

If an agent still holds a raw production credential that reaches the provider directly, Actenon can still produce proof, receipts, and refusals for the protected path — but it cannot stop side-door execution on an unprotected one.

The guarantee holds only when the resource is reachable solely through the protected edge.

See [docs/architecture/TRUST_BOUNDARIES.md](docs/architecture/TRUST_BOUNDARIES.md), [docs/architecture/BYPASS_RESISTANCE.md](docs/architecture/BYPASS_RESISTANCE.md), and [docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md).

---

## Protect your resource boundary

You adopt Actenon at the boundary you own, and require proof from every caller.

The protected edge builds the intended action from the incoming request and requires the proof to bind that exact request. A proof issued for a harmless action cannot be reused to authorize a harmful one.

| Resource boundary you own | Protected against |
| --- | --- |
| Database / data store | An agent dropping, deleting, or mutating production data |
| Payments / financial rails | An agent inflating, redirecting, or duplicating a payout |
| Cloud / infrastructure control plane | An agent terminating fleets, deleting resources, or disabling monitoring |
| IAM / access control | An agent escalating privilege, disabling MFA, or granting access |
| Object storage / filesystem | An agent deleting backups or exfiltrating objects |
| CI/CD / deploy / source control | An agent shipping unsafe code or deleting repositories |
| Communications / messaging | An agent blasting customers or sending legal/compliance messages |
| Internal / provider APIs | Any consequential call arriving without bound proof |

Start with [docs/guides/EDGE_DEPLOYMENT.md](docs/guides/EDGE_DEPLOYMENT.md) and the examples under `examples/`.

---

## Protect an MCP tool in 3 steps

If you build agents or MCP tools, you protect the tool side effect the same way.

### 1. Identify the side effect

```python
@mcp.tool()
def delete_customer(customer_id: str):
    db.execute("DELETE FROM customers WHERE id = ?", [customer_id])
    return {"status": "deleted"}
```

### 2. Require proof at the endpoint

Keep proof out of the model-facing schema where possible. The runtime or client should attach proof metadata to the tool context.

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

### 3. Test the refusal path

A protected tool must refuse when proof is missing, expired, replayed, audience-mismatched, action-mismatched, parameter-mismatched, policy-denied, or issued for a different tenant, subject, or boundary.

Start with:

```bash
python examples/quickstart_min.py
python3 -m pytest examples/financial_agent_protected_transfer -q
python3 -m pytest examples/fastmcp_financial_transfer -q
```

Then see [MCP_HERO_PATH.md](MCP_HERO_PATH.md), `examples/mcp_server_protected_tool/`, and [INTEGRATIONS.md](INTEGRATIONS.md).

---

## Consequential Action Coverage Matrix

Actenon ships a fast local coverage matrix for representative consequential action surfaces. It exercises deterministic local scenarios across DevOps, Fintech, IAM, Database, Browser, MCP, Data Export, Email, and Code Agent operations.

Run it:

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

Proof-bound execution checks:
- Missing proof refused:                     54/54
- Action hash mismatch refused:              54/54
- Parameter mismatch refused:                54/54
- Audience mismatch refused:                 54/54
- Tenant / subject mismatch refused:         54/54
- Expired proof refused:                     54/54
- Replay attempts refused:                   54/54
- Policy-denied actions refused:             54/54
- Valid proof-bound actions executed once:  108/108

Artifacts:
- Refusal artifacts emitted:  432/432
- Receipt artifacts emitted:  108/108

Result: PASS

No valid proof, no execution.
```

These are representative local simulations, not live provider integration tests.

Read more: [Consequential Action Coverage Matrix](docs/coverage/CONSEQUENTIAL_ACTION_COVERAGE_MATRIX.md).

---

## Critical-domain stress evidence

A real single-session critical-domain evaluation was run against a fresh public clone of the repository. It did not claim two-week observation or production deployment.

The recorded evaluation covered:

- full public-clone test suite
- conformance suite
- release gate
- Ruff
- public-boundary validation
- ten Consequential Action Coverage Matrix runs

Headline result:

```text
463 passed, 3 skipped
Conformance tests passed. Ran 33 test(s).
PASS: Release gate completed.
10 coverage matrix runs.
5,400 representative local scenarios.
4,320 refusal artifact checks.
1,080 receipt artifact checks.
```

Read the evidence document: [docs/evidence/CRITICAL_DOMAIN_STRESS_EVALUATION.md](docs/evidence/CRITICAL_DOMAIN_STRESS_EVALUATION.md).

---

## What a receipt and a refusal look like

Every decision produces a portable, structured artifact.

A refusal:

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

These are real artifacts written by the demo under `artifacts/hero_demo_runtime/`.

For copied Cloud-issued proof and outcome verification, see [docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md](docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md).

---

## Where Actenon changes the outcome

Actenon is built for the execution gap exposed by AI-agent failure patterns: the moment an agent moves from suggesting an action to causing one against a system you own.

| Failure pattern | What Actenon enforces |
| --- | --- |
| Production database deletion | No exact signed proof → refused before execution; Refusal emitted |
| Destructive production action | Proof must bind the exact action, subject, tenant, audience, and expiry |
| Data export / exfiltration | Export requires scoped proof, policy approval, audience binding, and a receipt |
| IAM privilege escalation | Access mutation requires proof-bound approval and credential brokering |
| MCP / tool proof laundering | Tool execution requires proof at the protected endpoint |
| Financial transfer drift | Amount, destination, tenant, and subject must match the proof exactly |

The claim is narrow and testable:

> If a consequential action is routed through an Actenon-protected endpoint, it cannot execute without valid proof bound to that exact action.

---

## What Actenon does — and does not do

Actenon does:

- refuse unproven consequential actions at a protected endpoint, before the side effect
- bind proof to exact action parameters, plus tenant, subject, audience, expiry, scope, and replay identity
- enforce replay/single-use where configured
- consume escrow where configured
- support credential brokering after verification
- emit portable Receipt and Refusal artifacts
- run locally for verification, conformance tests, and copied Cloud-issued artifact verification

Actenon does not:

- stop a model from trying to act
- make a bad-but-authorized action good
- protect actions that bypass the protected endpoint
- protect an agent that still holds raw production credentials and can use a side-door path
- stop ordinary in-band model output disclosure unless that disclosure is routed as a protected action
- prove downstream business finality
- prove that a provider behaved honestly after handoff
- replace IAM, OAuth, service mesh, API gateways, approvals, monitoring, or DLP
- certify that a repo is vulnerable
- claim insurer endorsement, regulator recognition, hosted transparency, external audit approval, or production KMS/HSM custody in the open-source kernel

A compromised issuer or signer can still mint valid proof for the wrong action. Mint-audit records improve detectability, not prevention.

The complete asset, attacker, and limit analysis is in [THREAT_MODEL.md](THREAT_MODEL.md), and the exact guarantees are in [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md).

---

## The advisory scanner

`actenon scan` maps candidate AI-controlled consequential action paths in a repo. It is advisory. It does not accuse maintainers of shipping vulnerabilities.

```bash
python3 -m actenon.cli scan repo --path .
python3 -m actenon.cli scan mcp --path examples/mcp_server_protected_tool
```

Findings use consequence-class language, not vulnerability-severity language:

> Critical-impact candidate action path, if reachable and ungated. Not a vulnerability claim. Runtime reachability and exploitability not proven. Suggested control: add an approval or proof gate before the side effect.

A Critical-impact candidate means an action surface could have critical consequences if reachable, agent-controlled, and ungated — not that a critical vulnerability has been proven.

See [docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md).

---

## Open kernel and Actenon Cloud

Actenon Kernel is the open proof gate, receipt format, verifier, conformance suite, SDK surface, examples, and local evidence tooling.

Actenon Cloud is the private hosted control plane around the open standard: policy management, approval workflows, tenant administration, audit storage, dashboards, credential brokering, managed signing, and hosted evidence workflows.

The doctrine is simple:

> The standard stays open. Operational services are built around it.

You do not need Actenon Cloud — or anyone’s permission — to issue, verify, or test compatible receipts, or to implement the neutral Verifiable Action Receipt surface.

The kernel, specs, conformance suite, SDKs, and examples are Apache-2.0, with an explicit contributor patent grant.

The exact public/commercial boundary is in [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md).

Read: [GOVERNANCE.md](GOVERNANCE.md) · [CONFORMANCE.md](CONFORMANCE.md) · [SPEC_INDEX.md](SPEC_INDEX.md) · [VERSIONING_POLICY.md](VERSIONING_POLICY.md)

---

## Documentation

| Topic | Document |
| --- | --- |
| Protect a resource boundary | [docs/guides/EDGE_DEPLOYMENT.md](docs/guides/EDGE_DEPLOYMENT.md) |
| Run the local proof-gate demo | [QUICKSTART.md](QUICKSTART.md) |
| First 10 minutes, end to end | [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md) |
| Proof issuance and approval | [docs/guides/ISSUANCE_AND_APPROVAL.md](docs/guides/ISSUANCE_AND_APPROVAL.md) |
| Domain policy packs | [docs/guides/POLICY_PACKS.md](docs/guides/POLICY_PACKS.md) |
| The problem, in depth | [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md) |
| The category | [CATEGORY.md](CATEGORY.md) |
| Threat model, attackers, limits | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Exact kernel guarantees | [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md) |
| Architecture and trust boundaries | [docs/architecture/TECHNICAL_ARCHITECTURE.md](docs/architecture/TECHNICAL_ARCHITECTURE.md) |
| Credential broker deployment | [docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md) |
| Wrap consequential MCP tools | [MCP_HERO_PATH.md](MCP_HERO_PATH.md) |
| Scanner methodology and wording | [docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md) |
| SDKs | [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md) · [SUPPORT_AND_COMPATIBILITY_STATUS.md](SUPPORT_AND_COMPATIBILITY_STATUS.md) |
| Specs index | [SPEC_INDEX.md](SPEC_INDEX.md) |
| Open-source vs commercial boundary | [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md) |
| Compliance mapping | [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) |
| Critical-domain evidence | [docs/evidence/CRITICAL_DOMAIN_STRESS_EVALUATION.md](docs/evidence/CRITICAL_DOMAIN_STRESS_EVALUATION.md) |

---

## Who it is for

Actenon is for anyone who owns a system an AI agent can reach — and needs to guarantee that no agent, theirs or anyone else’s, can take a consequential action against it without proof.

Resource and platform owners can use it to protect databases, payments rails, cloud control planes, internal APIs, object stores, deploy pipelines, and messaging systems.

Companies exposed to agents they do not control can require proof at their own boundary without relying on every external agent to adopt their preferred safety library.

Security and infrastructure teams can compose Actenon with IAM, OAuth, gateways, approval systems, SIEM, GRC, monitoring, and DLP.

Regulated and high-stakes operators can use Receipt and Refusal artifacts as portable evidence of bounded authorization and execution decisions.

SDK and framework teams can integrate protected tool execution into agent stacks and MCP servers.

Open-source maintainers can use the scanner to map consequential action surfaces without vulnerability theatre.

---

## Contributing

Actenon is a good fit for contributors interested in AI agents, security tooling, MCP, open standards, and developer experience.

Strong first contributions:

- edge templates for databases, payments, cloud control planes, object storage, CI/CD, IAM, and messaging
- scanner rules for shell execution, file writes/deletes, browser submits, email sends, data exports, payments, deployments, IAM changes, database mutations, and MCP tool side effects
- framework examples for MCP servers, LangChain, CrewAI, LlamaIndex, browser-use, OpenAI Agents SDK, Semantic Kernel, and other tool-calling agents
- SDK conformance tests
- receipt/refusal verification examples
- docs and architecture diagrams

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Useful labels: `good first issue`, `edge`, `scanner`, `docs`, `sdk`, `mcp`, `conformance`, `examples`, `security`.

---

## Releasing

Before any public release or launch archive:

```bash
bash scripts/verify_release_gate.sh
```

That gate blocks on coverage matrix, the focused keystone suite, the full test suite, Ruff, public-boundary validation, and clean public-archive creation.

---

## License

[Apache-2.0](LICENSE).

The open kernel, specs, conformance suite, SDKs, and examples are permissively licensed with an explicit contributor patent grant — chosen so the Verifiable Action Receipt surface can become neutral, widely adopted infrastructure.
