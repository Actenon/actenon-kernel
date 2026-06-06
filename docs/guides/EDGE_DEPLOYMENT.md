# Edge Deployment

## The Resource-Side Boundary

`ProtectedEdge` is the hardened resource-owner adapter. It accepts the agent's
raw requested action, constructs the `ActionIntent` from that request, verifies
that proof is bound to the exact intent, enforces the gate's replay policy,
brokers a credential, and invokes the backend only after verification.

```text
agent request + proof
        |
        v
ProtectedEdge -> exact request intent -> verify -> single-use -> broker
                                                        |
                                                        v
                                                resource side effect
```

The backend callback receives the verified `ActionIntent` and a
`BrokeredCredential`. It does not receive the PCCB. There is no public adapter
option that executes an action read from proof while ignoring the agent's
request.

## Exact Request Binding

The intent builder must place the complete raw request into
`ActionIntent.action.parameters`. `ProtectedEdge` compares their RFC 8785
canonical JSON forms and fails with `EdgeConfigurationError` if any requested
field is omitted, replaced, or added.

```python
from actenon.adapters.edge import ProtectedEdge

edge = ProtectedEdge(
    gate,
    intent_builder=build_intent_from_raw_request,
    backend=execute_with_brokered_credential,
)

intent = edge.intent_for(raw_request)
proof = issuer_gate.mint_proof(intent)  # local example; production issuance is separate
outcome = edge.execute(raw_request, proof)
```

No proof produces `NO_PROOF`. A proof for a different request produces
`INTENT_MISMATCH` or another exact-binding refusal before the backend runs.
Reusing a proof is refused by Actenon's default replay protection.

## Deployment Requirement: No Side Door

**The resource MUST be reachable only through the protected edge for the
claimed boundary to hold. The backend MUST accept only brokered credentials
issued after successful verification. Agents MUST NOT retain standing
credentials or an alternate route to the resource.**

The deployment pattern is:

```text
agent -> ProtectedEdge -> credential broker -> backend
agent -X-> backend
```

The broker should issue narrowly scoped, short-lived authority for the verified
action. The backend should reject a missing, expired, incorrectly scoped, or
non-brokered credential. Raw provider secrets remain inside the broker or
resource runtime and must not enter agent context, proof material, logs,
Receipts, or Refusals.

For multi-worker or multi-region edges, every executor that can reach the
resource must share a durable replay store. The default local replay store is
appropriate for one local process; configure SQLite or PostgreSQL according to
the deployment topology. The replay store is fail-closed by default and must
meet the durability, consistency, monitoring, and restore requirements in
[Replay Store Operations](REPLAY_STORE_OPERATIONS.md).

## False Assurance If Half-Deployed

Adding `ProtectedEdge` to one route while leaving a direct SDK, credential,
admin endpoint, queue consumer, or legacy integration available to the agent
does not protect that alternate path. Receipts and Refusals prove what happened
at the protected boundary; they cannot govern calls that bypass it.

Treat these as deployment blockers:

- standing production credentials in agent or tool runtimes
- direct backend networking from the agent path
- unprotected aliases for the same mutation
- broker grants reusable beyond the verified action
- independent edge workers with isolated replay state
- backend handlers that trust proof-derived parameters instead of the verified request intent

This is deliberately strict. A half-deployed edge can create false assurance
while the consequential authority remains reachable elsewhere.

## Templates And Limits

Local templates for database, payment HTTP API, cloud, IAM, storage, CI/CD,
communications, and physical/OT boundaries live in
`examples/edge_templates/`. They use synthetic callbacks and perform no live
provider actions.

The adapter proves proof-bound behavior for requests routed through it. It does
not prove complete route coverage, provider finality, production exposure,
exploitability, or prevention of every unsafe action. Review the wider
[Credential Broker Deployment](CREDENTIAL_BROKER_DEPLOYMENT.md) and
[Bypass Resistance](../architecture/BYPASS_RESISTANCE.md) guidance.
