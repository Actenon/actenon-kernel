# actenon-kernel

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Runs locally](https://img.shields.io/badge/runs-locally-brightgreen)
![No cloud required](https://img.shields.io/badge/cloud-not_required-lightgrey)

**Stop AI agents from taking consequential actions they were never authorised to take.**

Actenon Kernel is the open proof gate for agentic execution.

> **No valid proof, no execution.**

Actenon protects the place where AI agents become dangerous: **the execution boundary**.

Models can reason. Agents can ask. Tools can propose. But the protected boundary — an API, MCP tool, service, database, payments rail, IAM control plane, release pipeline, infrastructure endpoint or internal workflow — decides whether the action is allowed to happen.

Actenon refuses consequential actions unless the caller presents cryptographic proof bound to the **exact action** being attempted.

If the proof is missing, expired, replayed, audience-mismatched, policy-denied, malformed or bound to different parameters, the action is refused **before the side effect**.

Actenon is not a prompt filter, output moderator or another layer of “please behave” instructions for an LLM.

It is an execution-edge control:

> **The agent may ask. The protected boundary decides.**

---

## 10-second read

Actenon Kernel is a local, open-source Python execution gate for AI-agent actions.

It verifies proof immediately before a side effect runs.

Use it when an agent, workflow, automation or tool caller can trigger something consequential:

- refunding money;
- sending a payment;
- exporting data;
- deleting a customer;
- changing IAM permissions;
- deploying to production;
- mutating a database;
- running an MCP tool with side effects.

The core idea:

> A model can propose an action. A protected boundary must verify proof before that action can execute.

---

## Run the proof in 60 seconds

Run the local demo and watch one approved action execute while a hallucinated/tampered action, a replay and a no-proof attempt are refused before any side effect.

```bash
git clone https://github.com/Actenon/actenon-kernel.git
cd actenon-kernel

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[asymmetric]"

python examples/interactive_execution_demo.py
```

Expected shape:

```text
✅ approved refund: ord-123 £25.00 -> executed
🛑 hallucinated refund: ord-456 £2,500.00 -> refused / INTENT_MISMATCH
🛑 replay approved refund -> refused / DUPLICATE_REPLAY
🛑 refund with no proof -> refused / PCCB_REQUIRED

Final ledger events: [{'order_id': 'ord-123', 'amount_cents': 2500}]

No valid proof, no execution.
```

The important part is not the demo domain. It is the invariant:

> **The side-effect function only runs for the proof-bound action.**

This repo is designed to be evaluated locally: no cloud account, no external service, no real payment rail and no destructive action.

---

## What just happened

The demo creates one valid proof for one approved refund.

Then it tries four execution paths:

- approved refund: proof matches the exact action, so the side effect executes;
- hallucinated refund: proof does not match the changed order and amount, so execution is refused;
- replay: the same proof is reused, so execution is refused;
- no proof: the action has no proof, so execution is refused.

The ledger only contains the approved action.

That is the guarantee Actenon is built around:

> **No valid proof, no execution.**

---

## Where Actenon sits

Actenon can be used in two complementary places.

### Agent framework boundary

Use Actenon inside an agent/tool framework adapter when you control the tool wrapper.

Examples:

- MCP / FastMCP tool wrappers;
- LangChain or LangGraph tools;
- OpenAI / Claude / CrewAI / LlamaIndex tool adapters;
- browser automation or coding-agent tool registries.

This protects the point where an agent calls a tool.

### Resource boundary

Use Actenon directly at the resource, service or API boundary when you own the system that performs the side effect.

Examples:

- refund API;
- payment service;
- data export endpoint;
- IAM grant service;
- deployment pipeline;
- database mutation service;
- internal workflow API.

This is the stronger deployment pattern.

Even if multiple agents, workflows or frameworks can reach the same resource, the resource itself refuses execution unless valid proof is bound to the exact action.

> **Protect the boundary you own. Do not rely on the agent to be safe.**

---

## The 3-line adoption model

Start here.

```python
from actenon import ActenonGate

gate = ActenonGate.local_dev(audience="service:refunds")

action = gate.build_action(
    "refund.issue",
    "payment.refund",
    {"order_id": "ord-123", "amount_cents": 2500},
    target_type="order",
    target_id="ord-123",
    tenant_id="demo",
    requester_id="support-agent",
)

proof = gate.mint_proof(action)  # Local demo only.

outcome = gate.protect(
    action,
    proof,
    lambda: issue_refund(order_id="ord-123", amount_cents=2500),
    audience="service:refunds",
)
```

The model:

1. Build the action intent.
2. Present proof for that exact action.
3. Protect the side effect.

If the proof does not validate, the lambda is never called.

In production, proof issuance belongs outside the protected tool or resource. Your issuer/control plane decides whether to mint proof after authentication, policy checks, tenant checks, evidence checks and any required approval.

The protected boundary only verifies.

---

## Production trust model

The local examples use `ActenonGate.local_dev(...)` so the repo can be understood and tested without infrastructure.

That is not the production trust model.

In production, the issuer/control plane and protected boundary should be separate trust domains.

```text
agent / workflow / tool caller
        |
        | proposes action intent
        v

issuer / control plane
        |
        | checks auth, policy, approvals, evidence, tenant and audience
        | issues proof for the target protected boundary
        v

protected boundary / Actenon Kernel gate
        |
        | verifier-only
        | cannot mint proof
        | verifies exact action immediately before the side effect
        v

side effect executes
        OR
structured refusal before side effect
        |
        v

receipt / refusal evidence
        |
        v

audit / SIEM / evidence store
```

The issuer decides whether proof may exist.

The protected boundary decides whether the side effect may happen.

Actenon Kernel is the open enforcement layer.

Actenon Cloud is an optional managed issuer and governance layer for teams that do not want to operate issuance, approvals, evidence, receipts, transparency and audit infrastructure themselves.

The security guarantee is not gated behind Actenon Cloud:

> **No valid proof, no execution.**

---

## Try the core examples

Run the smallest proof-bound path:

```bash
python examples/quickstart_min.py
```

Run the interactive demo:

```bash
python examples/interactive_execution_demo.py
```

Run issuer-side policy preflight:

```bash
python -m pytest examples/protected_policy_preflight_refund -q
```

Run core evidence examples:

```bash
python -m pytest \
  examples/protected_policy_preflight_refund \
  examples/financial_agent_protected_transfer \
  examples/fastmcp_financial_transfer \
  examples/protected_multi_agent_swarm \
  examples/protected_iam_control_plane \
  -q
```

---

## Issuer-side policy preflight

Proof should not be minted just because an action has the right shape.

Issuer-side policy is where business and domain rules are checked before proof exists.

Invalid actions should fail at the control plane, not at the side-effect boundary.

A protected refund policy might enforce:

- `amount_cents` must be an integer;
- `amount_cents` must be greater than zero;
- `amount_cents` must be below the policy limit;
- the target order/account must exist;
- the requester must be allowed to request the refund;
- required approval evidence must be present for high-risk actions.

Run the evidence:

```bash
python -m pytest examples/protected_policy_preflight_refund -q
```

It proves:

- positive refund -> proof minted -> side effect executes;
- negative refund -> proof not minted -> no side effect;
- excessive refund -> proof not minted -> no side effect;
- proof for a small refund cannot be reused for a larger refund.

The principle:

> Invalid business actions should die before cryptographic proof exists.

---

## Adoption paths

Actenon is designed to be adopted at the execution boundary with low developer friction.

Common paths:

- Direct Python: protect one function with `gate.protect()`.
- MCP / FastMCP: protect model-visible MCP tools at the server boundary.
- LangChain / LangGraph: pass proof through `RunnableConfig`, outside the model-visible tool schema.
- FastAPI / HTTP: pass proof through an `X-Actenon-Proof` header.
- Resource API: verify proof directly before the backend side effect.
- Multi-agent systems: enforce replay protection with a shared durable replay store.

The proof should not be exposed as a normal model-controlled argument.

See [`INTEGRATIONS.md`](INTEGRATIONS.md) and [`MCP_HERO_PATH.md`](MCP_HERO_PATH.md) for deeper integration patterns.

---

## Evidence examples

Actenon includes runnable, self-verifying examples that demonstrate proof-bound execution across different frameworks, domains and agent topologies.

Core examples:

- `examples/interactive_execution_demo.py`
- `examples/quickstart_min.py`
- `examples/protected_policy_preflight_refund`
- `examples/financial_agent_protected_transfer`
- `examples/fastmcp_financial_transfer`
- `examples/protected_multi_agent_swarm`
- `examples/protected_iam_control_plane`
- `examples/protected_clinical_ehr_agent`

Run the core evidence suite:

```bash
python -m pytest \
  examples/protected_policy_preflight_refund \
  examples/financial_agent_protected_transfer \
  examples/fastmcp_financial_transfer \
  examples/protected_multi_agent_swarm \
  examples/protected_iam_control_plane \
  -q
```

---

## What Actenon protects

Use Actenon when an AI agent, workflow, tool or automation can trigger a consequential side effect.

Good first use cases:

- payments, refunds, payouts, transfers, credits and account adjustments;
- customer deletion, data export, record modification and sensitive data movement;
- IAM grants, role changes, privileged access and production permissions;
- CI/CD deployments, rollbacks, releases and infrastructure changes;
- MCP tools, browser actions, coding-agent tools and workflow automations;
- multi-agent swarms where multiple agents can act against shared resources.

Healthcare, clinical and safety-critical examples in this repository are illustrative evidence examples only.

They are not certification or a recommended first deployment market.

Actenon does not inspect prompts, filter ordinary model responses or replace DLP.

It protects explicit execution-edge actions routed through an Actenon-protected boundary.

If an action is not routed through the protected boundary, Actenon cannot protect it.

---

## What Actenon guarantees

When a consequential action is routed through an Actenon-protected boundary, and the backend has no alternate unprotected route, Actenon can enforce:

- exact-action binding;
- parameter binding;
- audience binding;
- time-bounded execution;
- single-use replay protection;
- structured refusal;
- policy evidence checks;
- receipt/refusal evidence;
- framework-agnostic enforcement.

The guarantee applies at the protected boundary.

It does not rely on the model following instructions.

---

## What Actenon does not guarantee

Actenon does not claim to:

- make an LLM truthful;
- prevent all bad model responses;
- inspect arbitrary natural language responses;
- replace access control, DLP, SIEM, EDR, IAM or application security;
- protect resources reachable through unprotected paths;
- certify production deployments by itself;
- prove real-world adoption, latency under load or third-party audit status.

Actenon protects explicit consequential actions at the boundary you own.

### Scope and boundary statements

Actenon gates explicit execution-edge actions; it does not inspect or filter prompts, model output, or in-band response content.

It can require proof for an explicit export or transmit action, but it does not stop data disclosed inside ordinary output unless that disclosure is itself modeled and routed as a protected action.

The edge guarantee applies only when the protected edge is the only path to the resource, the backend accepts only brokered credentials issued after verification, and the agent has no standing credential or alternate route.

---

## Going to production

The local quickstart uses `ActenonGate.local_dev(...)` because it is the fastest way to understand the model.

It is for development, demos and local tests only.

For production, you need the same guarantee backed by production infrastructure:

- asymmetric signing;
- managed key custody;
- durable replay protection;
- issuer metadata;
- audit logging;
- policy evidence;
- operational monitoring.

You can run all of this yourself with the open kernel.

Actenon Cloud is an optional managed service for teams that want this trust infrastructure operated for them.

It does not unlock a stronger kernel guarantee than the open kernel provides.

---

## Documentation map

Start here:

- [`KERNEL_GUARANTEES.md`](KERNEL_GUARANTEES.md) — exact kernel guarantee.
- [`docs/SCOPE_AND_GUARANTEES.md`](docs/SCOPE_AND_GUARANTEES.md) — project scope and limits.
- [`docs/guides/ISSUANCE_AND_APPROVAL.md`](docs/guides/ISSUANCE_AND_APPROVAL.md) — issuance and approval.
- [`INTEGRATIONS.md`](INTEGRATIONS.md) — integration patterns.
- [`MCP_HERO_PATH.md`](MCP_HERO_PATH.md) — MCP adoption path.
- [`SDK_SELECTION_GUIDE.md`](SDK_SELECTION_GUIDE.md) — SDK path.
- [`CONFORMANCE.md`](CONFORMANCE.md) — conformance.
- [`SECURITY.md`](SECURITY.md) — security posture.

---

## Local development

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[asymmetric]"
```

Run quickstart:

```bash
python examples/quickstart_min.py
```

Run the interactive demo:

```bash
python examples/interactive_execution_demo.py
```

Run package tests:

```bash
python -m pytest -q
```

Check README links:

```bash
python - <<'PY'
from pathlib import Path
import re

root = Path(".")
s = Path("README.md").read_text(encoding="utf-8")
missing = []

for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", s):
    if link.startswith(("http://", "https://", "#", "mailto:")):
        continue

    target = link.split("#")[0]

    if target and not (root / target).exists():
        missing.append(link)

if missing:
    print("Missing README links:")
    print("\n".join(missing))
    raise SystemExit(1)

print("README links OK")
PY
```

---

## FAQ

### Is Actenon an AI safety model?

No. Actenon is an execution-boundary control.

It does not try to make the model safe. It makes the action boundary deterministic.

### Does the agent need to cooperate?

No. The boundary enforces proof before execution.

The agent can ask, but it cannot force the side effect without valid proof.

### Can this work with third-party agents?

Yes, if the third-party agent must use a protected boundary to reach the resource.

### Can Actenon stop data leakage in normal model responses?

No. Actenon can require proof for explicit export/transmit actions, but it does not inspect arbitrary model text unless that text is routed through a protected action.

### What happens if the agent has another credential or route?

Then the resource is not fully protected by Actenon.

The protected edge must be the only route to the side effect, or backend credentials must only be issued after verification.

### Is the local signer production-ready?

No. The local development signer is for development and demos only.

Production should use asymmetric signing under managed key custody.

### Does Actenon Cloud unlock a stronger kernel guarantee?

No. The kernel guarantee is open and self-hostable.

Actenon Cloud is the managed issuer, approval, evidence, receipt and governance layer for teams that do not want to operate that control-plane infrastructure themselves.

### Why not just use IAM?

Use IAM too.

IAM answers who or what has access.

Actenon answers whether this exact agentic action, with these exact parameters, has valid proof at execution time.

### Why does replay protection matter?

Because agents retry, workers scale horizontally and swarms duplicate work.

A valid proof must not become permission to execute the same side effect repeatedly.

---

## Contributing

Focused contributions are welcome around examples, tests, documentation, integrations, benchmark scenarios and developer ergonomics.

Security-sensitive changes to the kernel guarantee should be discussed before implementation.

Good first issues are labelled `good first issue`.

---

## Project status

Actenon Kernel is an open-source execution gate and evidence standard for proof-bound agentic actions.

The goal is to make proof-bound execution a normal default for high-risk AI-agent actions.

> **No valid proof, no execution.**
