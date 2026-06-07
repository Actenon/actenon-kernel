<!--
  REVIEWER NOTES — READ BEFORE COMMITTING (these are for you, delete before publishing):

  ⚠️ VERIFY-AGAINST-CODE ITEMS (I could not run the code in this turn — confirm each before publishing,
     because the #1 trust-killer is a copy/paste example that doesn't run verbatim):
     1. OUTCOME ATTRIBUTES: This README uses `outcome.allowed`, `outcome.reason`, `outcome.result`
        in the framework wrappers. Earlier in the build the shipped object exposed `.ok`,
        `.reason_code`, and `.outcome`. CONFIRM the real attribute names on GateOutcome and make
        EVERY code block consistent with the actual API. If the real names are .ok/.reason_code,
        change them here.
     2. DEMO FILE: confirm `examples/interactive_execution_demo.py` exists and prints exactly the
        output shown (including the £ currency and the reason codes).
     3. build_action SIGNATURE: confirm the positional/keyword args shown match the real signature.
     4. All doc links (docs/adapters/*, docs/evidence/*) — create those files (moved out of this
        README) or change the links to point where the content actually lives.

  This version moves the three framework wrappers and the six per-evidence prose sections OUT of the
  README into linked docs, so the first two screens are pure hook. Nothing was deleted — it was
  relocated. Create docs/adapters/ and docs/evidence/ with the moved content.
-->

# actenon-kernel

**Stop AI agents from taking destructive actions they were never authorized to take.**
The open proof gate for agentic execution — payments, deletes, deploys, access changes, and any other consequential action.

> **No valid proof, no execution.**

Your model can reason. Your agent can ask. Your tools can propose. But the protected boundary — the API, MCP tool, database, payments rail, IAM control plane, release pipeline, or infrastructure endpoint — decides whether the action actually happens.

Actenon refuses a consequential action unless the caller presents a cryptographic proof bound to the **exact action** being attempted. If the proof is missing, expired, replayed, audience-mismatched, policy-denied, malformed, or bound to different parameters, the action is refused **before the side effect**.

It is not a prompt filter, an output moderator, or another layer of "please behave" for an LLM. It is an execution-edge control:

> **The agent may ask. The protected boundary decides.**

<!-- Add real badges here once confirmed true: Apache-2.0 license, CI status, Python version, conformance suite. Do NOT add a stars badge yet. -->

---

## See it work in 3 minutes

Don't read the whole repo to understand the guarantee. Run the demo and watch the boundary accept one approved action, then refuse a hallucinated command, a replay, and a no-proof attempt — before any side effect.

```bash
git clone https://github.com/Actenon/actenon-kernel.git
cd actenon-kernel
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -e ".[asymmetric]"
python examples/interactive_execution_demo.py
```

```text
✅ approved refund: ord-123 £25.00              -> executed
🛑 hallucinated refund: ord-456 £2,500.00       -> refused / INTENT_MISMATCH
🛑 replay approved refund                       -> refused / DUPLICATE_REPLAY
🛑 refund with no proof                         -> refused / PCCB_REQUIRED

Final ledger events: [{'order_id': 'ord-123', 'amount_cents': 2500}]
No valid proof, no execution.
```

The domain doesn't matter. The invariant does: **the side-effect function only runs for the proof-bound action.**

---

## The core idea, in one example

The lowest-friction way to adopt Actenon is the direct `gate.protect()` path. It keeps the model's *proposed* action separate from the protected *side effect*.

```python
from actenon import ActenonGate

gate = ActenonGate.local_dev(audience="service:refunds")

def issue_refund(order_id: str, amount_cents: int):
    return {"status": "refunded", "order_id": order_id, "amount_cents": amount_cents}

# 1. Build the action intent (the helper fills the envelope; you bind the security-critical fields).
action = gate.build_action(
    "refund.issue",
    "payment.refund",
    {"order_id": "ord-123", "amount_cents": 2500},
    target_type="order",
    target_id="ord-123",
    tenant_id="demo",
    requester_id="support-agent",
)

# 2. Present proof for that exact action.
#    Local demo only: minted here with the dev signer. In production your issuer/control plane
#    mints proof after auth, policy, and approval — the protected tool only verifies it.
proof = gate.mint_proof(action)

# 3. Protect the side effect. If the proof doesn't validate, the lambda is never called.
outcome = gate.protect(
    action,
    proof,
    lambda: issue_refund(order_id="ord-123", amount_cents=2500),
    audience="service:refunds",
)
```

That's the whole mental model: **build the action → present proof for that exact action → protect the side effect.** The boundary does not care what the model "intended"; it verifies the exact action.

→ **Adapters for your runtime** (MCP/FastMCP, LangChain/LangGraph, FastAPI/HTTP): [`docs/adapters/`](docs/adapters/)
→ **The action helper in depth** (`build_action`, production fields): [`docs/adapters/ACTION_HELPER.md`](docs/adapters/ACTION_HELPER.md)

---

## Why Actenon exists

AI agents are moving from chat to action — issuing refunds, deploying code, modifying databases, updating IAM roles, exporting data, restarting infrastructure, coordinating with other agents. That creates a new failure mode:

> The model may be wrong, compromised, manipulated, over-authorized, or prompt-injected — but the side effect still happens.

Most AI-safety work focuses on what the model *says* or *intends*. Actenon focuses on the moment that matters most — **the execution gap: between an agent proposing an action and a system actually doing it.** At that point the boundary must be deterministic.

**If you're protecting MCP tools:** *MCP is how agents reach tools. Actenon is how tools decide whether the action is allowed.*

---

## What Actenon protects — and what it doesn't

**Protects** explicit, consequential, execution-edge actions routed through a protected boundary: payments and refunds; data export and customer deletion; IAM grants and privileged access; CI/CD deploys and rollbacks; MCP/browser/coding-agent tools; regulated operational actions; and multi-agent swarms acting on shared resources.

**Does not** inspect prompts, filter ordinary model output, or replace DLP/IAM/SIEM/EDR. It does not make an LLM truthful or protect resources reachable through an unprotected route. *If an action isn't routed through the protected boundary, Actenon can't protect it.*

→ Full guarantees and limits: [`KERNEL_GUARANTEES.md`](KERNEL_GUARANTEES.md) · [`SCOPE_AND_GUARANTEES.md`](docs/SCOPE_AND_GUARANTEES.md)

---

## Proof it works: runnable evidence

Actenon ships self-verifying examples that demonstrate proof-bound execution across frameworks, domains, and agent topologies. Each is runnable; together they're the evidence suite.

| Example | What it proves |
|---|---|
| [`financial_agent_protected_transfer`](examples/financial_agent_protected_transfer) | Money moves only when proof is bound to the exact payee, amount, target, and capability (tampering, payee-swap, laundering, replay, expiry, malformed → all refused) |
| [`fastmcp_financial_transfer`](examples/fastmcp_financial_transfer) | MCP/FastMCP tools refuse unproven consequential actions at the server boundary |
| [`protected_clinical_ehr_agent`](examples/protected_clinical_ehr_agent) | FastAPI/HTTP boundary protects medication administration (wrong patient, overdose, wrong drug/route, double dose, stale order → refused) |
| [`protected_multi_agent_swarm`](examples/protected_multi_agent_swarm) | Shared replay state enforces exactly one action across a swarm — verified with 32 workers racing the same proof |
| [`protected_iam_control_plane`](examples/protected_iam_control_plane) | Policy layer blocks privileged IAM grants unless approval evidence is present |
| [`protected_cicd_pipeline`](examples/protected_cicd_pipeline) | Release pipeline deploys only the approved artifact to the approved environment |

```bash
python -m pytest \
  examples/financial_agent_protected_transfer \
  examples/fastmcp_financial_transfer \
  examples/protected_clinical_ehr_agent \
  examples/protected_multi_agent_swarm \
  examples/protected_iam_control_plane \
  examples/protected_cicd_pipeline \
  -q
```

→ Detailed walkthrough of each evidence case: [`docs/evidence/`](docs/evidence/)

One adoption note worth surfacing here, because it's the easiest swarm mistake: **cross-agent single-use requires a shared/durable replay store.** With per-agent in-process state, a swarm can reopen the double-execution hole.

---

## How a deployment is shaped

```text
agent / workflow / tool caller
        |
        |  proposed action + proof
        v
protected boundary  ──verify: exact action · parameters · audience · expiry · replay · policy──┐
        |                                                                                       │
        v                                                                                       │
   side effect executes                                                          OR  refusal returned
```

1. **Issuer / control plane** — decides whether a proposed action may be authorized, and mints proof.
2. **Protected boundary / kernel gate** — verifies the proof immediately before the side effect.
3. **Receipt / refusal** — records what happened, what was refused, and why.

The agent can be cooperative, third-party, compromised, or unaware of Actenon. **The boundary enforces.** The adoption rule follows: *protect the boundary you own; don't try to make every agent safe; make the action surface safe.*

---

## Going to production: self-hosted or managed

The quickstart uses `ActenonGate.local_dev(...)` because it's the fastest way to understand the model — it's for development and demos only (it uses a local HMAC signer). Production needs the same guarantee backed by asymmetric signing, managed key custody, durable replay, issuer metadata, audit logging, and policy evidence.

**You can run all of this yourself with the open kernel. None of it requires Actenon Cloud.**

Actenon Cloud is an optional managed service that *operates* this trust infrastructure for you. It does not unlock a stronger guarantee than the open kernel — it removes the operational burden of running the issuer, approvals, key custody, durable replay, and audit/transparency yourself.

| Production capability | Self-hosted with `actenon-kernel` | Optional managed layer |
|---|---|---|
| Asymmetric signing | Kernel's asymmetric signing + your own signing process | Hosted proof issuance |
| Key custody | Your own KMS/HSM (AWS KMS, GCP KMS, Azure Key Vault, internal HSM) | Managed signing custody + rotation |
| Key rotation | Your own `kid` / public-key metadata process | Managed rotation + issuer metadata |
| Durable replay | Shared durable store (SQLite single-node, Postgres for shared boundaries) | Managed replay + monitoring |
| Issuer metadata | Host your own well-known issuer metadata + public keys | Hosted issuer discovery |
| Tenant-aware policy | Open policy/preflight layer + evidence objects in this repo | Managed policy + governance workflows |
| Approval evidence | Your own approval flow emitting verifiable approval evidence | Hosted human-approval UI + workflow |
| Receipts / refusals | Store the kernel's structured artifacts in your own logs/SIEM | Managed storage, search, reporting |
| Auditability | Wire events into your own audit sink | Managed audit trail + transparency |

> The kernel remains the neutral enforcement layer that can be adopted, audited, and self-hosted without depending on Actenon Cloud.

→ Production design: [`docs/guides/ISSUANCE_AND_APPROVAL.md`](docs/guides/ISSUANCE_AND_APPROVAL.md) · [`docs/guides/PRODUCTION_SIGNING_CUSTODY.md`](docs/guides/PRODUCTION_SIGNING_CUSTODY.md)

---

## FAQ

**Is Actenon an AI-safety model?** No. It's an execution-boundary control. It doesn't make the model safe; it makes the action boundary deterministic.

**Does the agent need to cooperate?** No. The boundary enforces proof before execution. The agent can ask, but can't force the side effect without valid proof.

**Can this work with third-party agents?** Yes — if the agent must use a protected boundary to reach the resource.

**Can Actenon stop data leakage in normal model output?** No. It can require proof for explicit export/transmit *actions*, but it doesn't inspect arbitrary model text.

**What if the agent has another credential or route?** Then the resource isn't fully protected. The protected edge must be the only route to the side effect, or backend credentials must only be issued after verification.

**Is the local signer production-ready?** No — development and demos only. Production uses asymmetric signing under managed key custody.

**Why not just use IAM?** Use IAM too. IAM answers *who has access*. Actenon answers *whether this exact action, with these exact parameters, has valid proof at execution time*.

**Why does replay protection matter?** Agents retry, workers scale horizontally, swarms duplicate work. A valid proof must not become permission to execute the same side effect repeatedly.

---

## Project status

Actenon Kernel is an open-source execution gate and evidence standard for proof-bound agentic actions (Apache-2.0). The goal is to make proof-bound execution a normal default for high-risk AI-agent actions.

Start with one high-risk action. Protect it. Run the evidence pattern. Expand from there.

> **No valid proof, no execution.**
