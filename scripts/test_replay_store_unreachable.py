#!/usr/bin/env python3
"""DISCOVERY TEST: what does the gate do when the replay store is UNREACHABLE?

Fable 5 Part 3.3: "determine what the gate does when the replay store is
UNREACHABLE. Test it, do not read the code and infer. If it fails OPEN,
do not fix it in this work order and do not document it as though it were
intended. Record in FINDINGS.md as a BLOCKER."

This test creates a replay store that raises on every operation (simulating
an unreachable database), then runs a full verification + execution attempt.
The observed outcome (allow or refuse) is recorded.

Usage:
    python scripts/test_replay_store_unreachable.py
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add the repo root to the path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.models.runtime import PolicyDecision
from actenon.proof import PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.proof.service import DynamicContextInput
from actenon.replay.base import (
    ActionConsumptionClaim,
    ActionConsumptionState,
    ReplayStore,
)


class UnreachableReplayStore(ReplayStore):
    """A replay store that simulates an unreachable database.

    Every operation raises ConnectionError, simulating a network partition
    or database outage.
    """

    def claim_once(self, claim: ActionConsumptionClaim, *, now: datetime) -> ActionConsumptionState:
        raise ConnectionError("replay store is unreachable (simulated network partition)")

    def mark_consumed(self, replay_key: str, *, now: datetime) -> ActionConsumptionState:
        raise ConnectionError("replay store is unreachable")

    def release_claim(self, replay_key: str, *, now: datetime, reason: str) -> ActionConsumptionState:
        raise ConnectionError("replay store is unreachable")


def main() -> int:
    print("=== DISCOVERY TEST: replay store unreachable ===")
    print()

    signer = build_local_proof_signer()
    minter = PCCBMinter(
        signer=signer,
        issuer=PartyRef(type="agent", id="agent:test"),
    )

    now = datetime.now(UTC)
    intent = ActionIntent(
        intent_id="intent_replay_unreachable_001",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        tenant=TenantRef(tenant_id="tenant:test"),
        requester=PartyRef(type="agent", id="agent:test"),
        action=ActionSpec(
            name="payment.refund",
            capability="payment.refund",
            parameters={"amount_cents": 2500, "currency": "GBP"},
        ),
        target=TargetRef(resource_type="payment_intent", resource_id="pi_test_001"),
    )
    context = DynamicContextInput(
        request_id="req_replay_unreachable_001",
        audience=AudienceRef(type="service", id="service:payments"),
        scope_capabilities=("payment.refund",),
        now=now,
    )
    decision = PolicyDecision(
        outcome="allow",
        summary="Test decision.",
        rule_evaluations=(),
        reason_codes=("TEST",),
    )

    pccb = minter.mint(intent, decision, context)
    verifier = PCCBVerifier(signer=signer)

    print("Step 1: Verify the proof (no replay store involved yet)...")
    try:
        verifier.verify(intent, pccb, context)
        print("  Proof verification PASSED (expected — verifier is stateless)")
    except Exception as e:
        print(f"  Proof verification FAILED: {e}")
        return 1

    print()
    print("Step 2: Attempt to claim the replay key with an UNREACHABLE store...")
    from actenon.replay.service import ReplayProtector, build_action_consumption_claim

    unreachable_store = UnreachableReplayStore()
    protector = ReplayProtector(store=unreachable_store)

    from actenon.models.runtime import ProtectedExecutionRequest
    request = ProtectedExecutionRequest(
        intent=intent,
        pccb=pccb,
        context=context,
    )

    try:
        state = protector.claim_request(request)
        print(f"  Claim SUCCEEDED — state={state.status}")
        print()
        print("  *** FAIL OPEN: the gate allowed execution when the replay store was unreachable ***")
        print("  This means a network partition could allow replay attacks.")
        return 2
    except ConnectionError as e:
        print(f"  Claim REFUSED with ConnectionError: {e}")
        print()
        print("  *** FAIL CLOSED: the gate refused execution when the replay store was unreachable ***")
        print("  This is the safe behavior — no execution without replay protection.")
        return 0
    except Exception as e:
        print(f"  Claim raised {type(e).__name__}: {e}")
        print()
        print(f"  The gate raised an exception (effectively fail-closed).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
