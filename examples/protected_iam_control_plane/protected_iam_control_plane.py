#!/usr/bin/env python3
"""
Actenon worked example & evidence: a protected IAM / identity control plane.

WHAT THIS DEMONSTRATES (and what it does not)
---------------------------------------------
A runnable, self-verifying demonstration of agent-driven IAM, where the canonical risk is PRIVILEGE
ESCALATION. An agent grants roles and modifies access; the gate is configured with the access-
governance POLICY pack, so this is the example that exercises Actenon's POLICY layer (privileged grants
require approval evidence), not just action-binding. It verifies: low-risk grants execute; a privileged
admin/production grant with NO approval is refused (PREFLIGHT_PRIVILEGED_ACCESS_APPROVAL_REQUIRED); the
SAME grant WITH documented approval executes in one pass; privilege escalation and parameter tampering
are refused (INTENT_MISMATCH); missing proof and replay are refused.

This is part of the evidence set alongside MCP, LangChain, FastAPI/clinical, and the multi-agent swarm.

This proves ENFORCEMENT CORRECTNESS on the local development signer. It is NOT a production deployment,
a third-party security audit, or evidence of production key custody. The local HMAC signer is
development-only; production uses asymmetric signing under managed custody (see
docs/guides/PRODUCTION_SIGNING_CUSTODY.md and docs/guides/ISSUANCE_AND_APPROVAL.md). Run it:

    pip install -e ".[asymmetric]"
    python examples/protected_iam_control_plane/protected_iam_control_plane.py

Exit code is 0 only if every expected outcome matches, so this doubles as a CI check.
"""

import sys
from datetime import datetime, timedelta, timezone

from actenon import ActenonGate
from actenon.preflight import build_access_governance_policy_pack

NOW = datetime.now(timezone.utc)

# The real side effect: the access-control system / directory.
DIRECTORY = {
    "grants": [],
    "principals": {
        "alice": "engineer",
        "bob": "analyst",
        "agent-svc": "automation",
    },
}

pack = build_access_governance_policy_pack()
gate = ActenonGate.local_dev(
    audience="service:iam-control-plane",
    clock=lambda: NOW,
    policy_pack=pack,
)

_PROOF_CACHE = {}


def grant_intent(principal, role, environment, iid, scope="single"):
    return {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": iid,
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "tenant": {"tenant_id": "corp-eng"},
        "requester": {"type": "agent", "id": "iam-agent"},
        "action": {
            "name": "iam.grant",
            "capability": "iam.permission.grant",
            "parameters": {
                "principal": principal,
                "role": role,
                "environment": environment,
                "scope": scope,
            },
        },
        "target": {
            "resource_type": "iam_principal",
            "resource_id": principal,
            "selectors": {"environment": environment},
        },
        "context": {"environment": environment},
    }


def do_grant(principal, role, environment, scope="single"):
    def _do():
        DIRECTORY["grants"].append(
            {
                "principal": principal,
                "role": role,
                "env": environment,
                "scope": scope,
            }
        )
        DIRECTORY["principals"][principal] = role
        return {"granted": role, "to": principal, "env": environment}

    return _do


def outcome_of(o):
    d = o if isinstance(o, dict) else o.to_dict()
    return d.get("outcome"), d.get("reason_code")


def main() -> int:
    print("=" * 74)
    print("Actenon developer evaluation — IAM / identity control plane (policy + binding)")
    print("=" * 74)
    print(f"\nInitial grants: {DIRECTORY['grants']}\n")

    results = []

    def run(label, fn, expect_outcome, expect_reason):
        try:
            outcome, reason = outcome_of(fn())
        except Exception as exc:
            outcome, reason = "raised", type(exc).__name__

        ok = (outcome == expect_outcome) and (
            expect_reason is None or reason == expect_reason
        )
        results.append(ok)

        tail = f" / {reason}" if reason else ""
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<54} -> {outcome}{tail}")

    print("IAM adversarial battery:\n")

    # 1) LOW-RISK grant: read_only in sandbox, valid proof — should execute.
    a1 = grant_intent("alice", "read_only", "sandbox", "intent_grant_alice_ro")
    run(
        "1 low-risk: alice read_only/sandbox (authorized)",
        lambda: gate.protect(
            a1,
            gate.mint_proof(a1),
            do_grant("alice", "read_only", "sandbox"),
            audience="service:iam-control-plane",
        ),
        "executed",
        None,
    )

    # 2) PRIVILEGED grant with NO approval evidence: admin in production -> policy must REFUSE.
    a2 = grant_intent("bob", "admin", "production", "intent_grant_bob_admin")
    run(
        "2 privileged: bob admin/production, NO approval",
        lambda: gate.protect(
            a2,
            gate.mint_proof(a2),
            do_grant("bob", "admin", "production"),
            audience="service:iam-control-plane",
        ),
        "refused",
        "PREFLIGHT_PRIVILEGED_ACCESS_APPROVAL_REQUIRED",
    )

    # 3) SAME privileged grant WITH documented approval evidence -> should execute.
    a3 = grant_intent("bob", "admin", "production", "intent_grant_bob_admin_approved")
    ev = {
        "approval_present": True,
        "approver_types": ["security_admin", "resource_owner"],
        "change_ticket": "CHG-4471",
    }
    p3 = gate.mint_proof(a3)
    _PROOF_CACHE["a3"] = a3
    _PROOF_CACHE["p3"] = p3
    run(
        "3 privileged: bob admin/production WITH approval",
        lambda: gate.protect(
            a3,
            p3,
            do_grant("bob", "admin", "production"),
            audience="service:iam-control-plane",
            evidence=ev,
        ),
        "executed",
        None,
    )

    # 4) PRIVILEGE ESCALATION via laundering: alice's read_only proof reused to grant admin.
    run(
        "4 escalation: alice-ro proof -> admin to attacker",
        lambda: gate.protect(
            grant_intent("attacker", "admin", "production", "intent_grant_attacker"),
            gate.mint_proof(a1),
            do_grant("attacker", "admin", "production"),
            audience="service:iam-control-plane",
            evidence=ev,
        ),
        "refused",
        "TARGET_MISMATCH",
    )

    # 5) PARAMETER TAMPERING: proof bound to read_only, body escalates same principal.
    a5 = grant_intent("alice", "read_only", "sandbox", "intent_grant_alice_ro_2")
    run(
        "5 tampering: read_only proof, escalate alice to admin",
        lambda: gate.protect(
            grant_intent("alice", "admin", "production", "intent_grant_alice_admin"),
            gate.mint_proof(a5),
            do_grant("alice", "admin", "production"),
            audience="service:iam-control-plane",
            evidence=ev,
        ),
        "refused",
        "TARGET_MISMATCH",
    )

    # 6) NO PROOF: agent tries to grant with nothing.
    run(
        "6 no proof: grant analyst to carol",
        lambda: gate.protect(
            grant_intent("carol", "analyst", "sandbox", "intent_grant_carol"),
            None,
            do_grant("carol", "analyst", "sandbox"),
            audience="service:iam-control-plane",
        ),
        "refused",
        "PCCB_REQUIRED",
    )

    # 7) REPLAY: re-fire exact approved admin grant proof from #3 — single-use must refuse.
    run(
        "7 replay: re-fire bob admin grant (#3, same proof)",
        lambda: gate.protect(
            _PROOF_CACHE["a3"],
            _PROOF_CACHE["p3"],
            do_grant("bob", "admin", "production"),
            audience="service:iam-control-plane",
            evidence=ev,
        ),
        "refused",
        "DUPLICATE_REPLAY",
    )

    print(f"\nFinal grants: {DIRECTORY['grants']}")
    invariants = {
        "only_two_grants": len(DIRECTORY["grants"]) == 2,
        "alice_ro_granted": {
            "principal": "alice",
            "role": "read_only",
            "env": "sandbox",
            "scope": "single",
        }
        in DIRECTORY["grants"],
        "bob_admin_granted_with_approval": {
            "principal": "bob",
            "role": "admin",
            "env": "production",
            "scope": "single",
        }
        in DIRECTORY["grants"],
        "no_attacker_grant": all(g["principal"] != "attacker" for g in DIRECTORY["grants"]),
        "alice_not_escalated": DIRECTORY["principals"]["alice"] == "read_only",
    }

    print("\nIAM-safety invariants:")
    for n, ok in invariants.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {n}")

    all_ok = all(results) and all(invariants.values())
    print("\n" + "=" * 74)
    print(
        f"RESULT: {'ALL CHECKS PASSED' if all_ok else 'CHECKS FAILED'}  "
        f"(battery={sum(results)}/{len(results)}, "
        f"invariants={sum(invariants.values())}/{len(invariants)})"
    )
    print("No valid proof, no execution.")
    print("=" * 74)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
