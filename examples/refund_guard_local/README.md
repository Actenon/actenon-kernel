# Local Protected Refund Endpoint

This is the dangerous-endpoint hero example in the kernel.

It shows a consequential refund path protected at the execution edge, entirely on local state, with no provider accounts, no API keys, and no hidden service dependency.

Why this example matters:

- refunds are easy to explain and hard to fake as a "safe demo"
- the side effect is real enough to feel operational: refundable balance changes and refund records are written
- the protected endpoint must verify the exact refund action before mutating state
- replay protection matters because a valid proof is still dangerous if the same request can execute twice

## What This Endpoint Protects

The local endpoint in [`protected_endpoint.py`](./protected_endpoint.py) simulates a refund resource with:

- payment fixture state
- remaining refundable balance
- refund execution records
- resource version increments

The protected endpoint updates that state only after verification succeeds.

## Fastest Path

This example supports two adoption paths on purpose:

1. edge-only local admission now
2. proof-carrying local issuer flow next

That keeps the kernel usable immediately even when your caller is just a third-party agent, tool runner, or framework workflow that does not know how to send Actenon proof yet.

Start the complete local trust runtime:

```bash
make install
actenon-kernel up
```

In a second terminal, start the tiny local protected refund endpoint:

```bash
python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime
```

### Path 1: Proof-Absent Local Admission

This is the shortest immediate adoption path for an existing agent or framework caller.

Send a plain local refund request to the protected endpoint:

```bash
curl -s http://127.0.0.1:9898/refunds/local-admission \
  -H 'Content-Type: application/json' \
  -d '{
    "payment_id": "payment_demo_001",
    "amount_minor": 1500,
    "currency": "USD",
    "requester_id": "framework_agent",
    "tenant_id": "tenant_demo",
    "risk_level": "normal"
  }'
```

What Actenon does at the edge in this mode:

- normalizes the raw request into a canonical local `Action Intent`
- evaluates local admission policy at the execution edge
- mints a local PCCB only if the decision is `allow`
- executes the protected refund only after the local proof path succeeds
- emits canonical Receipt and Refusal artifacts either way

This mode is intentionally explicit in the response as `proof-absent-local-admission`.

It is useful now, but it is not the same thing as portable cross-boundary proof from an upstream issuer.

Change `risk_level` to see the other local-admission outcomes:

- `blocked` -> `deny`
- `approval` -> `approval-required`
- `review` -> `needs-evidence`

### Path 2: Proof-Present Verification

This is the stronger local flow once you are ready to issue Actenon proof before calling the endpoint.

Issue an allowed refund locally and save the issuer response:

```bash
curl -s http://127.0.0.1:8787/v1/intents \
  -H 'Content-Type: application/json' \
  -d @- > /tmp/actenon-refund-issue.json <<'JSON'
{
  "action_intent": {
    "contract": {"name": "action_intent", "version": "v1"},
    "intent_id": "intent_local_runtime_allow",
    "issued_at": "2026-01-01T12:00:00Z",
    "expires_at": "2026-01-01T12:05:00Z",
    "tenant": {"tenant_id": "tenant_demo"},
    "requester": {"type": "service", "id": "demo_actor"},
    "action": {
      "name": "refund.create",
      "capability": "refund.execute",
      "parameters": {"amount_minor": 1500, "currency": "USD"},
      "constraints": {"exact_amount_minor": 1500, "exact_currency": "USD"},
      "scope": {"single_use": true, "target_resource_type": "payment"}
    },
    "target": {"resource_type": "payment", "resource_id": "payment_demo_001"}
  },
  "context": {
    "audience": "service:local-refund-endpoint",
    "now": "2026-01-01T12:00:00Z"
  }
}
JSON
```

What you get back from the issuer:

- `decision.outcome: "allow"`
- a minted `pccb`
- an `escrow_id`
- a canonical `receipt`
- request artifacts under `artifacts/local_runtime/artifacts/requests/`

Now call the protected endpoint with that issued proof:

```bash
python3 -m examples.refund_guard_local.call_endpoint \
  --issue-response /tmp/actenon-refund-issue.json
```

That call executes the refund exactly once and writes an execution Receipt.
The helper reuses the stored issuer request context from the runtime artifacts, so the shipped local proof timestamps stay valid for the endpoint call too.

If you run the same command again, the protected endpoint refuses the duplicate:

```bash
python3 -m examples.refund_guard_local.call_endpoint \
  --issue-response /tmp/actenon-refund-issue.json
```

That second call demonstrates something upstream approval alone cannot do for you: the same proof-bearing request is blocked at the execution edge instead of driving the side effect twice.

## Adoption Ladder

Use this sequence when you want the fastest serious rollout path:

1. edge-only admission: raw framework request enters the protected endpoint and Actenon normalizes and evaluates it locally
2. local issuing: call the local issuer first and let it mint PCCB plus escrow explicitly
3. proof-carrying flow: the caller now sends `Action Intent` and `PCCB` to the protected endpoint directly
4. cross-boundary trust later: move to well-known key discovery and verifier-only SDK paths when the proof must travel between systems

That ladder matters because it lets teams adopt the execution edge now instead of waiting for every upstream caller to speak Actenon on day one.

Inspect the resulting artifacts and protected state:

- `artifacts/local_runtime/artifacts/outcomes/receipts/`
- `artifacts/local_runtime/artifacts/protected_endpoints/refund_guard_local/state/protected_endpoint_state.json`
- `artifacts/local_runtime/artifacts/outcomes/refusals/`

If you want machine-readable endpoint output, add `--json` to `call_endpoint.py`.

## Why This Is Not Architecture Theater

The endpoint does not trust upstream allow state by itself.

It checks:

- exact refund amount binding
- exact currency binding
- exact payment target
- audience binding
- expiry
- replay and single-use behavior through the runtime path

If those checks do not hold, the endpoint does not mutate local state.

## See The Gap Immediately

Run the incident simulator:

```bash
actenon-kernel simulate --scenario all
```

Then open:

- `artifacts/local_runtime/simulations/audience-mismatch/INCIDENT_SUMMARY.md`
- `artifacts/local_runtime/simulations/replay-refused/INCIDENT_SUMMARY.md`

Those scenarios show the painful category gap directly:

- what would have happened without execution-edge verification
- what proof catches directly
- what still requires runtime enforcement, especially replay
- what the Action Intent plus Receipt or Refusal lets you prove afterward

## Files

- [`protected_endpoint.py`](./protected_endpoint.py)
- [`server.py`](./server.py)
- [`call_endpoint.py`](./call_endpoint.py)
- [`../../docs/guides/INTEGRATION_QUICKSTART.md`](../../docs/guides/INTEGRATION_QUICKSTART.md)
- [`../../spec/protected-endpoint/SPEC.md`](../../spec/protected-endpoint/SPEC.md)

## Boundary

This example is a local protected endpoint, not a hosted approval system, not a control plane, and not a provider integration.
