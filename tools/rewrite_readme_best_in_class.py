#!/usr/bin/env python3
"""
Rewrite the actenon-kernel README into a best-in-class adoption README.

What this does:
- Backs up the existing README.md.
- Reorders onboarding around the frictionless gate.protect() path.
- Demotes MCP/FastAPI/LangChain adapters into framework-specific sections.
- Adds the evidence gallery including clinical EHR, multi-agent swarm, IAM, and CI/CD.
- Adds honest scope, adoption paths, and production key custody guidance.
- Preserves a strong commercial/technical story without overclaiming.

Run from the repository root:
    python3 tools/rewrite_readme_best_in_class.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys


ROOT = Path.cwd()
README = ROOT / "README.md"
TOOLS = ROOT / "tools"


def exists(path: str) -> bool:
    return (ROOT / path).exists()


def link(path: str, label: str | None = None) -> str:
    return f"[{label or path}]({path})" if exists(path.split("#", 1)[0]) else f"`{path}`"


def evidence_row(path: str, name: str, proof_channel: str, what_it_proves: str) -> str:
    label = f"`{path}`" if not exists(path) else f"[`{path}`]({path})"
    return f"| {label} | {name} | {proof_channel} | {what_it_proves} |"


def test_command_for_existing_examples() -> str:
    candidates = [
        "examples/financial_agent_protected_transfer",
        "examples/fastmcp_financial_transfer",
        "examples/protected_langchain_finance_agent",
        "examples/protected_clinical_ehr_agent",
        "examples/protected_multi_agent_swarm",
        "examples/protected_iam_control_plane",
        "examples/protected_cicd_pipeline",
    ]
    found = [p for p in candidates if exists(p)]
    if not found:
        return "python3 -m pytest -q"
    return "python3 -m pytest \\\n  " + " \\\n  ".join(found) + " \\\n  -q"


def build_readme() -> str:
    docs = {
        "execution_gap": link("THE_EXECUTION_GAP.md"),
        "prod_signing": link("docs/guides/PRODUCTION_SIGNING_CUSTODY.md"),
        "issuance": link("docs/guides/ISSUANCE_AND_APPROVAL.md"),
        "kernel_guarantees": link("KERNEL_GUARANTEES.md"),
        "conformance": link("CONFORMANCE.md"),
        "threat_model": link("THREAT_MODEL.md"),
        "open_boundary": link("OPEN_SOURCE_BOUNDARY.md"),
    }

    example_table = "\n".join([
        evidence_row(
            "examples/financial_agent_protected_transfer",
            "Financial transfer / refund",
            "direct `gate.protect()`",
            "exact action binding, no-proof refusal, replay refusal",
        ),
        evidence_row(
            "examples/fastmcp_financial_transfer",
            "FastMCP financial transfer",
            "MCP request metadata",
            "MCP boundary enforcement without model-visible proof arguments",
        ),
        evidence_row(
            "examples/protected_langchain_finance_agent",
            "LangChain financial ops",
            "LangChain `RunnableConfig`",
            "proof stays out of the model-facing tool schema",
        ),
        evidence_row(
            "examples/protected_clinical_ehr_agent",
            "Clinical EHR medication administration",
            "`X-Actenon-Proof` HTTP header",
            "wrong patient, overdose, wrong drug/route, stale order, replay all refused before eMAR side effect",
        ),
        evidence_row(
            "examples/protected_multi_agent_swarm",
            "Multi-agent swarm",
            "per-agent gates sharing one replay store",
            "cross-agent replay and 32-worker concurrency race: exactly one side effect wins",
        ),
        evidence_row(
            "examples/protected_iam_control_plane",
            "IAM / identity control plane",
            "direct gate + access-governance policy pack",
            "privileged grants require approval evidence; escalation and tampering refused",
        ),
        evidence_row(
            "examples/protected_cicd_pipeline",
            "CI/CD release pipeline",
            "direct gate at release boundary",
            "only the approved reviewed/tested artifact deploys; environment jumps, vulnerable rollback, stale proof, replay refused",
        ),
    ])

    tests = test_command_for_existing_examples()

    return f"""# actenon-kernel

**The open proof gate for agentic execution.**

> **No valid proof, no execution.**

Actenon protects the place where AI agents become dangerous: the execution boundary.

Your model can reason. Your agent can ask. Your tools can propose. But the protected boundary — the API, MCP tool, service, database, release pipeline, payments rail, IAM control plane, EHR operation, or infrastructure endpoint — decides whether the action is allowed to happen.

Actenon refuses consequential actions unless the caller presents a cryptographic proof bound to the exact action being attempted. If the proof is missing, expired, replayed, scoped to another audience, or bound to different parameters, the side effect does not run.

That means the safety rule is outside the prompt, outside the agent's memory, and outside the model's cooperation.

> **The agent may ask. The protected boundary decides.**

---

## Why this exists

Agentic AI is moving from "answer a question" to "take an action":

- move money
- change IAM permissions
- deploy code
- restart infrastructure
- export customer data
- update production systems
- administer operational workflows
- call third-party tools through MCP
- coordinate multi-agent swarms

Prompt instructions are not an execution boundary. Guardrails that rely on the agent behaving, remembering, or interpreting policy correctly are not enough for high-impact side effects.

Actenon treats consequential actions like something that should be independently authorized, cryptographically bound, single-use, time-bounded, audience-scoped, and auditable.

Read the full problem statement in {docs["execution_gap"]}.

---

## The core idea in one sentence

A control plane issues a short-lived proof for a specific approved action, and the kernel verifies that proof at the execution edge before the side effect can run.

```text
human / policy / workflow approval
        │
        ▼
signed proof for exact action
        │
        ▼
agent attempts tool call
        │
        ▼
Actenon gate at protected boundary
        │
        ├── valid, exact, fresh, unused proof  → execute + receipt
        └── missing, stale, replayed, mutated  → refuse before side effect
```

---

## Start here: the 3-call adoption path

The easiest way to understand Actenon is not MCP, LangChain, or FastAPI. Those are framework adapters.

The core adoption path is:

1. Create a gate.
2. Mint or receive a proof for an approved action.
3. Protect the side effect with `gate.protect()`.

```python
from datetime import datetime, timedelta, timezone
from actenon import ActenonGate

now = datetime.now(timezone.utc)

gate = ActenonGate.local_dev(
    audience="service:support-refunds",
    clock=lambda: now,
)

approved_action = {{
    "contract": {{"name": "action_intent", "version": "v1"}},
    "intent_id": "intent_refund_order_123_2500",
    "issued_at": now.isoformat(),
    "expires_at": (now + timedelta(minutes=10)).isoformat(),
    "tenant": {{"tenant_id": "acme"}},
    "requester": {{"type": "user", "id": "support-manager-7"}},
    "action": {{
        "name": "refund.issue",
        "capability": "payment.refund",
        "parameters": {{"order_id": "order-123", "amount_cents": 2500}},
    }},
    "target": {{"resource_type": "order", "resource_id": "order-123"}},
}}

proof = gate.mint_proof(approved_action)

def issue_refund():
    # your real side effect goes here
    return {{"refunded": "order-123", "amount_cents": 2500}}

result = gate.protect(
    approved_action,
    proof,
    issue_refund,
    audience="service:support-refunds",
)

print(result)
```

If the action changes from `$25.00` to `$2,500.00`, the proof no longer matches. If the proof is reused, replay protection refuses it. If no proof is provided, the side effect never runs.

This is the "wrap the boundary" model.

---

## Quickstart

```bash
git clone https://github.com/Actenon/actenon-kernel.git
cd actenon-kernel

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[asymmetric]"

python examples/quickstart_min.py
```

Then run the evidence suite available in your checkout:

```bash
{tests}
```

---

## What Actenon guarantees

When the protected edge is the only path to the resource, Actenon can enforce:

- **No proof, no execution** — missing proof refuses before the side effect.
- **Exact action binding** — a proof for one action cannot authorize a mutated amount, target, route, role, commit, environment, or dataset.
- **Audience scoping** — a proof for one service boundary cannot be laundered into another boundary.
- **Time bounds** — expired approvals are refused.
- **Replay resistance** — the same proof cannot be used twice.
- **Receipts and refusals** — decisions are explicit artifacts rather than hidden prompt behavior.
- **Framework-agnostic enforcement** — the same kernel works across direct Python, MCP, LangChain, FastAPI/HTTP, IAM, CI/CD, clinical workflows, and multi-agent topologies.

Read more in {docs["kernel_guarantees"]} and {docs["conformance"]}.

---

## Evidence examples

The repo now includes runnable, self-verifying examples designed to answer the question a serious adopter asks:

> "Does this actually stop the wrong side effect before it happens?"

| Example | Domain | Proof travels in | What it demonstrates |
|---|---|---|---|
{example_table}

Each example is intentionally adversarial. The tests mutate amounts, targets, environments, users, routes, roles, commits, proofs, and replay timing. Exit code is `0` only if the expected side effects happen exactly once and every adversarial variant is refused.

---

## Evidence highlights

### Financial transfer / refund

A support or finance agent can only execute the exact approved movement of money. Prompt-injected amount changes, payee swaps, missing proofs, cross-tool misuse, and replayed refunds are refused before money moves.

### Clinical EHR medication administration

The FastAPI/HTTP example protects a medication-administration side effect. One authorized administration executes. Wrong patient, overdose, wrong drug, wrong route, stale order, missing proof, malformed proof, and double dose are refused before the eMAR side effect.

This is illustrative test evidence, not clinical certification.

### Multi-agent swarm

The swarm example is the proof that Actenon is not just a single-agent wrapper. Multiple independent workers act through separate gates while sharing one replay store.

The critical test: **32 workers race the same proof at once. Exactly one executes. Thirty-one are refused.**

That is the execution-boundary model applied to multi-agent systems.

### IAM / identity control plane

The IAM example exercises the policy layer. A low-risk sandbox grant executes. A privileged production admin grant without approval evidence is refused. The same privileged grant with approval evidence executes. Escalation, parameter tampering, missing proof, and replay are refused.

This shows Actenon is not only "proof matches action"; it can also require preflight evidence for high-risk classes of action.

### CI/CD release pipeline

The CI/CD example protects a release boundary. Only the approved reviewed/tested commit deploys to production. Unreviewed commits, staging-to-production environment jumps, rollback to a known-vulnerable commit, missing proof, stale approval, and double deploy are refused.

This is the pattern for release agents, DevOps agents, and autonomous deployment workflows.

---

## Which integration path should I use?

Use the simplest path that matches your boundary.

| Your boundary | Start with |
|---|---|
| Python service, worker, internal API, queue consumer | `ActenonGate.local_dev(...)` and `gate.protect(...)` |
| MCP server / FastMCP tool | MCP adapter after you have a running MCP server and proof metadata flow |
| LangChain tool | LangChain adapter with proof in `RunnableConfig`, not model-visible tool args |
| FastAPI / HTTP service | FastAPI adapter with proof in an HTTP header |
| Enterprise production | asymmetric verification, JWKS/KMS/HSM custody, durable replay store |

The most common first mistake is starting with the MCP adapter when you just want to understand the kernel.

Start with `gate.protect()`. Move to MCP, LangChain, or FastAPI once the boundary shape is clear.

---

## Production architecture

Local development examples use the local HMAC signer. That is for demos and tests only.

Production should use asymmetric signing and managed key custody:

- private signing keys in KMS/HSM or equivalent managed custody
- public verification keys distributed through JWKS or a trusted key registry
- short-lived proofs
- durable replay protection shared by every protected edge that can act on the same resource
- explicit audience scoping per service boundary
- approval and issuance workflows outside the model
- receipts/refusals exported to your audit and security systems

See {docs["prod_signing"]} and {docs["issuance"]}.

---

## What Actenon is not

Actenon is not a prompt filter, jailbreak detector, model monitor, or content moderation layer.

It does not make model output truthful. It does not inspect every token. It does not stop data disclosed inside ordinary model output unless that disclosure is modeled and routed as a protected action, such as `data.export` or `email.send`.

Actenon gates explicit execution-edge actions.

For threat boundaries, see {docs["threat_model"]}.

---

## Adoption model

Actenon is designed to be adopted like infrastructure:

- protect the consequential boundary once
- require proofs for high-impact action classes
- keep agents untrusted
- keep credentials behind the boundary
- verify at the edge before side effects
- record receipts and refusals

The strongest adoption pattern is:

```text
open kernel at the boundary
        +
paid/cloud control plane for issuance, approvals, key custody,
policy packs, dashboards, receipts, integrations, and enterprise audit
```

The open kernel should be easy to inspect, easy to run, and easy to adopt. The commercial value should live in managed issuance, governance, proof lifecycle, policy operations, audit evidence, and enterprise integrations.

---

## Developer experience priorities

This README intentionally leads with the direct `gate.protect()` path because that is the lowest-friction first adoption.

The next improvements that will make adoption even easier are:

1. **Construction-time validation** — fail clearly if an adapter is missing a verifier, malformed action builder, or required proof channel.
2. **Action builder helper** — reduce manual action-envelope boilerplate for common cases.
3. **Framework-specific copy/paste guides** — MCP, LangChain, and FastAPI should each show how proof gets into the runtime channel and how to test locally.

---

## Repository map

Common entry points:

- `examples/quickstart_min.py` — smallest direct-kernel example
- `examples/` — runnable evidence examples
- `actenon/` — kernel and adapters
- {docs["execution_gap"]} — problem statement
- {docs["kernel_guarantees"]} — what the kernel does and does not guarantee
- {docs["conformance"]} — conformance expectations
- {docs["prod_signing"]} — production key custody
- {docs["issuance"]} — issuance and approval flow
- {docs["open_boundary"]} — open-source boundary and commercial split

---

## The standard

Agentic systems should not be allowed to perform consequential actions merely because a model emitted a tool call.

The boundary should require proof.

**No valid proof, no execution.**
"""


def validate_links(markdown: str) -> list[str]:
    missing: list[str] = []
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", markdown):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path = target.split("#", 1)[0]
        if path and not (ROOT / path).exists():
            missing.append(target)
    return missing


def main() -> int:
    if not README.exists():
        print("ERROR: README.md not found. Run this from the actenon-kernel repository root.", file=sys.stderr)
        return 1

    backup = ROOT / f"README.backup.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.md"
    backup.write_text(README.read_text(encoding="utf-8"), encoding="utf-8")

    new_readme = build_readme()
    missing = validate_links(new_readme)
    if missing:
        print("ERROR: generated README contains missing links:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        print(f"Backup preserved at {backup}", file=sys.stderr)
        return 1

    README.write_text(new_readme, encoding="utf-8")
    print(f"Updated README.md")
    print(f"Backup written to {backup}")
    print()
    print("Next:")
    print("  git diff -- README.md")
    print("  python3 -m pytest -q")
    print('  git add README.md && git commit -m "Rewrite README for best-in-class adoption"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
