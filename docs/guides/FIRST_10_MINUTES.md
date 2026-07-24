# First 10 Minutes

## Goal

Get to a complete local trust runtime, a memorable execution-gap simulation, and a real proof-required protected-endpoint run with no external accounts, no API keys, and artifacts you can inspect immediately.

If you want the problem statement before the walkthrough, read [../../THE_EXECUTION_GAP.md](../../THE_EXECUTION_GAP.md) first. This guide is the shortest way to watch the protected endpoint answer that problem locally.

## Why This Demo Exists

Most agent stacks decide upstream and trust downstream:

- auth says who called
- policy says allow or deny
- approval says proceed

But the execution edge can still receive the wrong action, the wrong target, or the same request twice.

This demo exists to make the missing boundary visible. The protected endpoint verifies proof before side effects, and you see both successful execution and blocked execution in one local run.

## Recommended Setup

```bash
make install
```

## Exact First Commands

```bash
actenon-kernel up
actenon-kernel doctor
actenon-kernel simulate --incident replit
```

Those commands do three important things immediately:

- start the complete local trust machine
- tell you whether it is healthy
- make the execution gap visible through a named incident simulation

The incident run writes a compact incident pack under `artifacts/local_runtime/simulations/replit/`.

## What Makes This Demo Good

It is not just a happy path and not just a verifier demo.

In the first few minutes you see:

- the local runtime come alive
- a deterministic execution-gap simulation
- a consequential endpoint protected at the execution edge
- canonical artifacts you can inspect directly

If you want the original seeded proof lab after that, run:

```bash
bash ./scripts/first_run.sh
```

That local proof lab still matters because in one run you see:

- refund allow and execution
- refund deny
- refund approval-required
- refund needs-evidence
- invoice payment allow and execution
- invoice payment duplicate protection
- invoice payment wrong-entity refusal
- invoice payment bank-mismatch refusal
- invoice payment approval-required
- invoice payment needs-evidence
- invoice payment batch-hash-mismatch refusal

That matters because a real execution-edge control is not just "it executed." It is also "it refused before side effects when the request no longer matched what was allowed."

## What You Should See In The Terminal

- `refund.allow: executed`
- `refund.deny: deny`
- `refund.approval_required: approval-required`
- `refund.needs_evidence: needs-evidence`
- `invoice_payment.allow: executed`
- `invoice_payment.duplicate_invoice_payment: deny`
- `invoice_payment.wrong_entity: deny`
- `invoice_payment.bank_mismatch: deny`
- `invoice_payment.approval_missing: approval-required`
- `invoice_payment.evidence_missing: needs-evidence`
- `invoice_payment.batch_hash_mismatch: deny`

## Open These First

- incident summary: `artifacts/local_runtime/simulations/replit/INCIDENT_SUMMARY.md`
- incident explanation artifacts: `artifacts/local_runtime/simulations/replit/`
- live runtime outcomes: `artifacts/local_runtime/artifacts/outcomes/`
- local proof lab summary if you ran it: `artifacts/local_proof/SUMMARY.txt`

## What To Do In Order

1. run `actenon-kernel up`, `actenon-kernel doctor`, and `actenon-kernel simulate --incident replit`
2. open `artifacts/local_runtime/simulations/replit/INCIDENT_SUMMARY.md`
3. open `artifacts/local_runtime/simulations/replit/intent_record.json` and compare it to the refusal or receipt artifacts beside it
4. start the protected refund endpoint from [../../examples/refund_guard_local/README.md](../../examples/refund_guard_local/README.md)
5. inspect the resulting local runtime Receipt or Refusal under `artifacts/local_runtime/artifacts/outcomes/`
6. run `actenon-kernel bundle export --runtime-dir artifacts/local_runtime` when you want to prove the runtime is portable
7. run `actenon-kernel bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon` when you want to inspect the exported artifact class seriously
7. move to [../../MCP_HERO_PATH.md](../../MCP_HERO_PATH.md) if you want the clearest agent-tool integration path
8. run `actenon-kernel conformance run` when you want the public compatibility check

If you want to explain the point of this demo to someone else in one sentence: it shows that upstream approval is not enough, and that the execution edge must verify the exact action before it acts.

The fastest unforgettable explanation of that point is still `actenon-kernel simulate --incident replit`, because it writes:

- the weak-control counterfactual
- the proof-bound protected outcome
- the remaining proof-only gap
- the bounded-intent explanation

## Then Explore These

- refund scenario artifacts: `artifacts/local_proof/scenarios/`
- refund endpoint state: `artifacts/local_proof/state/protected_endpoint_state.json`
- invoice payment artifacts: `artifacts/local_proof/invoice_payment/`
- invoice payment endpoint state: `artifacts/local_proof/invoice_payment/state/protected_endpoint_state.json`

If you want to turn that understanding into a real dangerous-endpoint integration next, do this immediately:

```bash
python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime
python3 -m examples.refund_guard_local.call_endpoint --issue-response /tmp/actenon-refund-issue.json
```

The second command assumes you already saved a local issuer response from `POST /v1/intents` to `/tmp/actenon-refund-issue.json`, exactly as shown in [../../examples/refund_guard_local/README.md](../../examples/refund_guard_local/README.md).

The full step-by-step path is in [../../examples/refund_guard_local/README.md](../../examples/refund_guard_local/README.md).

When you are done, export the runtime:

```bash
actenon-kernel bundle export --runtime-dir artifacts/local_runtime
```

Then verify the exported `.actenon` bundle:

```bash
actenon-kernel bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon
```

That bundle is portable execution evidence with internal tamper checks, not attestation-of-origin in active v1.

## Fastest Repeat Command

```bash
bash ./scripts/run_local_proof.sh
```

The script resets demo state by default so repeated runs stay deterministic.

## Next Best Step For Agent Tooling

If you want the clearest agent-stack adoption path after the local proof run, move next to the protected MCP tool example:

- [../../MCP_HERO_PATH.md](../../MCP_HERO_PATH.md)
- [../../examples/mcp_server_protected_tool/README.md](../../examples/mcp_server_protected_tool/README.md)

## First Conformance Run

```bash
actenon-kernel conformance run
```

## Full Repo Check

```bash
bash ./scripts/public_repo_verify.sh
```
