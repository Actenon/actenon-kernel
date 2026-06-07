#!/usr/bin/env python3
"""
Actenon worked example & evidence: a protected MULTI-AGENT SWARM on a shared resource boundary.

WHAT THIS DEMONSTRATES (and what it does not)
---------------------------------------------
A runnable, self-verifying demonstration for the architecture everyone is talking about: multi-agent
SWARMS. An orchestrator delegates to specialist sub-agents and a scaled-out worker pool; every agent
acts through its OWN gate, but all gates SHARE one replay store. The swarm-critical question this
answers: when N independent agents can all act, does the boundary still enforce EXACTLY ONE correct
action? It is attacked on the swarm-native failure modes a single-agent test cannot reach:
  - delegation amplification (a downstream worker inflates the delegated amount)
  - cross-agent proof laundering (one agent forwards another's proof to a different tool)
  - confused-deputy / audience confusion (agent A's authority used by agent B)
  - CROSS-AGENT REPLAY (a scaled-out 2nd worker replays the same proof) -- the killer
  - a rogue swarm member acting with no proof
  - REAL CONCURRENCY: 32 workers race the same proof at once; exactly one must win.

This is the fourth evidence example, alongside MCP (proof in metadata), LangChain (proof in
RunnableConfig) and FastAPI (proof in HTTP header). It shows the boundary holds not just across
frameworks but across a multi-agent TOPOLOGY with shared replay state.

KEY ADOPTION NOTE: cross-agent single-use requires the agents to SHARE the replay store. With per-agent
in-process stores, a swarm would re-open the double-execution hole. In production use a shared/durable
store (SQLite/Postgres) reachable by every protected edge (see the deployment docs).

This proves ENFORCEMENT CORRECTNESS on the local development signer. It is NOT a production deployment,
a third-party security audit, or evidence of production key custody. The local HMAC signer is
development-only; production uses asymmetric signing under managed custody (see
docs/guides/PRODUCTION_SIGNING_CUSTODY.md and docs/guides/ISSUANCE_AND_APPROVAL.md). Run it:

    pip install -e ".[asymmetric]"
    python examples/protected_multi_agent_swarm/protected_multi_agent_swarm.py

Exit code is 0 only if BOTH the battery and the concurrency race pass, so this doubles as a CI check.
"""
import sys

from datetime import datetime, timedelta, timezone
from actenon import ActenonGate
from actenon.replay import ReplayProtector, build_default_replay_store

NOW = datetime.now(timezone.utc)

# ONE shared resource boundary (the bank/ledger + data room). All agents act through gates that
# SHARE this replay store — the documented way to get cross-agent single-use.
LEDGER = {"balance_cents": 10_000_000, "events": []}
DATAROOM = {"exports": []}
SHARED_STORE = build_default_replay_store()

def agent_gate(audience):
    """Each sub-agent gets its OWN gate (own audience), but they SHARE the replay store."""
    return ActenonGate.local_dev(audience=audience, clock=lambda: NOW,
                                 replay_protector=ReplayProtector(SHARED_STORE))

# the boundary's protected operations, keyed by capability/audience
REFUND_AUD = "service:refund-boundary"
PAYOUT_AUD = "service:payout-boundary"
EXPORT_AUD = "service:export-boundary"

def refund_intent(order_id, amount_cents, iid):
    return _intent("payment.refund","payment.refund",{"order_id":order_id,"amount_cents":amount_cents},"order",order_id,iid)
def payout_intent(vendor, amount_cents, iid):
    return _intent("payment.release","payment.release",{"vendor":vendor,"amount_cents":amount_cents},"vendor",vendor,iid)
def export_intent(dataset, rows, iid):
    return _intent("data.export","data.export",{"dataset":dataset,"rows":rows},"dataset",dataset,iid)

def _intent(name, cap, params, ttype, tid, iid):
    return {"contract":{"name":"action_intent","version":"v1"},"intent_id":iid,
        "issued_at":NOW.isoformat(),"expires_at":(NOW+timedelta(minutes=10)).isoformat(),
        "tenant":{"tenant_id":"swarm-corp"},"requester":{"type":"agent","id":"orchestrator"},
        "action":{"name":name,"capability":cap,"parameters":dict(params)},
        "target":{"resource_type":ttype,"resource_id":tid}}

def do_refund(order_id, amount_cents):
    def _do(): LEDGER["balance_cents"]-=amount_cents; LEDGER["events"].append({"refund":order_id,"amount_cents":amount_cents}); return {"refunded":order_id}
    return _do
def do_payout(vendor, amount_cents):
    def _do(): LEDGER["balance_cents"]-=amount_cents; LEDGER["events"].append({"payout":vendor,"amount_cents":amount_cents}); return {"paid":vendor}
    return _do
def do_export(dataset, rows):
    def _do(): DATAROOM["exports"].append({"dataset":dataset,"rows":rows}); return {"exported":dataset}
    return _do

def run_battery() -> int:
    print("="*74); print("Actenon developer evaluation — MULTI-AGENT SWARM on a shared boundary"); print("="*74)
    print("\nTopology: orchestrator -> {refund-worker, payout-worker, export-worker, refund-worker-2 (scaled out)}")
    print("All sub-agents act through gates that SHARE one replay store.\n")

    # The four sub-agents in the swarm
    refund_worker  = agent_gate(REFUND_AUD)
    payout_worker  = agent_gate(PAYOUT_AUD)
    export_worker  = agent_gate(EXPORT_AUD)
    refund_worker2 = agent_gate(REFUND_AUD)   # a SECOND refund worker (horizontal scale-out / swarm)

    # The orchestrator obtains ONE proof for ONE approved delegated task: refund order #771, $80.00.
    approved = refund_intent("ord-771", 8000, "intent_refund_771_8000")
    PROOF = refund_worker.mint_proof(approved)
    print(f"Orchestrator authorized exactly ONE task: refund ord-771 $80.00")
    print(f"Initial: balance=${LEDGER['balance_cents']/100:,.2f}  events={LEDGER['events']}  exports={DATAROOM['exports']}\n")

    results=[]
    def run(label, fn, expect_outcome, expect_reason):
        try:
            out=fn()
            d = out if isinstance(out, dict) else (out.to_dict() if hasattr(out,"to_dict") else {"outcome":getattr(out,"outcome",None),"reason_code":getattr(out,"reason_code",None)})
            outcome,reason=d.get("outcome"),d.get("reason_code")
        except Exception as exc: outcome,reason="raised",type(exc).__name__
        ok=(outcome==expect_outcome) and (expect_reason is None or reason==expect_reason)
        results.append(ok)
        tail=f" / {reason}" if reason else ""
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<52} -> {outcome}{tail}")

    print("Swarm adversarial battery (one proof issued: refund ord-771 $80.00):\n")

    # 1) the legitimate delegated task: the refund worker executes it
    run("1 refund-worker: approved refund ord-771 $80 (delegated)",
        lambda: refund_worker.protect(approved, PROOF, do_refund("ord-771",8000), audience=REFUND_AUD),
        "executed", None)

    # 2) DELEGATION AMPLIFICATION: a poisoned worker inflates the delegated amount
    run("2 refund-worker: amplify to $80,000 (same proof)",
        lambda: refund_worker.protect(refund_intent("ord-771",8_000_000,"intent_refund_771_8000000"), PROOF, do_refund("ord-771",8_000_000), audience=REFUND_AUD),
        "refused", "INTENT_MISMATCH")

    # 3) CROSS-AGENT LAUNDERING: export worker forwards the refund proof to the export tool
    run("3 export-worker: refund proof -> data export (laundered)",
        lambda: export_worker.protect(export_intent("customers_pii",2_000_000,"intent_export_pii"), PROOF, do_export("customers_pii",2_000_000), audience=EXPORT_AUD),
        "refused", "AUDIENCE_MISMATCH")

    # 4) CONFUSED DEPUTY / AUDIENCE CONFUSION: payout worker reuses the refund proof for a payout
    run("4 payout-worker: refund proof -> vendor payout (confused deputy)",
        lambda: payout_worker.protect(payout_intent("vendor:x",8000,"intent_payout_x"), PROOF, do_payout("vendor:x",8000), audience=PAYOUT_AUD),
        "refused", "AUDIENCE_MISMATCH")

    # 5) CROSS-AGENT REPLAY (the killer): the SCALED-OUT 2nd refund worker replays the SAME proof
    run("5 refund-worker-2: replay the same proof (shared store)",
        lambda: refund_worker2.protect(approved, PROOF, do_refund("ord-771",8000), audience=REFUND_AUD),
        "refused", "DUPLICATE_REPLAY")

    # 6) SAME-AGENT REPLAY: the original worker tries again too
    run("6 refund-worker: replay the same proof again",
        lambda: refund_worker.protect(approved, PROOF, do_refund("ord-771",8000), audience=REFUND_AUD),
        "refused", "DUPLICATE_REPLAY")

    # 7) ROGUE SWARM MEMBER: an unauthorized agent with no proof tries to act
    run("7 rogue agent: refund with no proof",
        lambda: refund_worker.protect(refund_intent("ord-999",50000,"intent_refund_999"), None, do_refund("ord-999",50000), audience=REFUND_AUD),
        "refused", "PCCB_REQUIRED")

    print(f"\nFinal: balance=${LEDGER['balance_cents']/100:,.2f}  events={LEDGER['events']}  exports={DATAROOM['exports']}")
    invariants = {
        "exactly_one_event": len(LEDGER["events"])==1,
        "the_one_is_correct": LEDGER["events"]==[{"refund":"ord-771","amount_cents":8000}],
        "balance_moved_once": LEDGER["balance_cents"]==10_000_000-8000,
        "no_amplified_refund": all(e.get("amount_cents",0)<=8000 for e in LEDGER["events"]),
        "no_pii_exported": DATAROOM["exports"]==[],
        "no_rogue_payout": all("payout" not in e for e in LEDGER["events"]),
    }
    print("\nSwarm-safety invariants (the boundary enforced EXACTLY ONE correct action across N agents):")
    for n,ok in invariants.items(): print(f"  [{'PASS' if ok else 'FAIL'}] {n}")

    all_ok = all(results) and all(invariants.values())
    print("\n"+"="*74)
    print(f"RESULT: {'ALL CHECKS PASSED' if all_ok else 'CHECKS FAILED'}  "
          f"(battery={sum(results)}/{len(results)}, invariants={sum(invariants.values())}/{len(invariants)})")
    print("No valid proof, no execution."); print("="*74)
    return 0 if all_ok else 1




def run_concurrency() -> int:
    import threading
    from datetime import datetime, timedelta, timezone
    from actenon import ActenonGate
    from actenon.replay import ReplayProtector, build_default_replay_store
    
    NOW = datetime.now(timezone.utc)
    LEDGER = {"executions": []}
    LOCKLESS = threading.Lock()  # only to append test results safely; the gate is what must enforce single-use
    SHARED_STORE = build_default_replay_store()
    
    def worker_gate():
        return ActenonGate.local_dev(audience="service:swarm-pay", clock=lambda: NOW,
                                     replay_protector=ReplayProtector(SHARED_STORE))
    
    def intent():
        return {"contract":{"name":"action_intent","version":"v1"},"intent_id":"intent_race_001",
            "issued_at":NOW.isoformat(),"expires_at":(NOW+timedelta(minutes=10)).isoformat(),
            "tenant":{"tenant_id":"swarm"},"requester":{"type":"agent","id":"orch"},
            "action":{"name":"payment.release","capability":"payment.release","parameters":{"vendor":"v","amount_cents":5000}},
            "target":{"resource_type":"vendor","resource_id":"v"}}
    
    issuer = worker_gate()
    a = intent(); PROOF = issuer.mint_proof(a)
    
    N = 32
    outcomes = []
    barrier = threading.Barrier(N)
    def attempt(i):
        g = worker_gate()                       # each "worker" is its own gate, shared store
        def do(): 
            with LOCKLESS: LEDGER["executions"].append(i)
            return {"by":i}
        barrier.wait()                          # all threads fire at once
        out = g.protect(a, PROOF, do, audience="service:swarm-pay")
        d = out if isinstance(out, dict) else out.to_dict()
        with LOCKLESS: outcomes.append(d.get("outcome"))
    
    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(N)]
    for t in threads: t.start()
    for t in threads: t.join()
    
    executed = outcomes.count("executed")
    refused = outcomes.count("refused")
    print("="*74)
    print(f"SWARM CONCURRENCY: {N} workers raced the SAME proof against a shared replay store")
    print("="*74)
    print(f"  executed: {executed}   refused: {refused}   total: {len(outcomes)}")
    print(f"  actual side effects recorded: {len(LEDGER['executions'])}")
    ok = (executed == 1) and (len(LEDGER["executions"]) == 1) and (refused == N-1)
    print(f"\n  [{'PASS' if ok else 'FAIL'}] exactly one winner under concurrency "
          f"(executed==1, side_effects==1, refused=={N-1})")
    print("="*74)
    return 0 if ok else 1


if __name__ == "__main__":
    rc1 = run_battery()
    print()
    rc2 = run_concurrency()
    sys.exit(0 if (rc1 == 0 and rc2 == 0) else 1)
