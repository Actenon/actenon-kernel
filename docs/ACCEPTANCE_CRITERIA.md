# Protected Execution Kernel Acceptance Criteria

## Normative Gate

`scripts/verify.sh` is the single rebuild acceptance gate.

The kernel only counts as complete when the repository implementation satisfies every criterion below and the test evidence described in `docs/TEST_PLAN.md`.

## AC-001 Action Intent Admission

The system MUST accept a typed Action Intent for refund execution and reject malformed or incomplete intents before any policy evaluation or side effect occurs.

Minimum fields:

- `intent_id`
- `tenant_id`
- `actor`
- `action_type`
- `target_resource`
- `requested_capability`
- `parameters`
- `issued_at`
- `expires_at`

Completion evidence:

- schema validation exists
- invalid intents are refused with a refusal envelope
- no downstream proof or execution is attempted for rejected intents

## AC-002 Deterministic Policy Evaluation

The system MUST evaluate each Action Intent against all three policy sources:

- hard rules
- tenant rules
- dynamic context

Completion evidence:

- the evaluation result is deterministic for the same intent and same context snapshot
- the evaluation output records the allow or refuse decision
- the evaluation output records the exact rule hits and context inputs that led to the decision

## AC-003 PCCB Minting

The system MUST mint a PCCB only after a positive policy decision.

The PCCB MUST be bound to:

- the Action Intent identity or digest
- tenant identity
- actor identity
- requested capability
- target resource
- authorized parameters including amount and currency
- issuance time
- expiry time
- a replay-relevant nonce or unique token

Completion evidence:

- refused intents never receive a PCCB
- an allowed intent receives exactly one PCCB per approved execution attempt
- the PCCB is signed or otherwise cryptographically protected in local proof mode

## AC-004 PCCB Verification

The protected endpoint MUST verify the PCCB before attempting the action.

Completion evidence:

- tampered PCCBs are rejected
- expired PCCBs are rejected
- PCCBs with mismatched tenant, actor, capability, target, amount, or currency are rejected
- verification failure yields a refusal envelope and zero side effects

## AC-005 Capability Escrow

The system MUST issue a capability through Capability Escrow and require successful escrow validation before protected execution.

Completion evidence:

- escrow records capability state
- escrow records expiry
- escrow supports single-use consumption
- escrow can refuse revoked, expired, missing, or already-consumed capabilities

## AC-006 Replay Protection

The system MUST prevent replay of the same protected action.

Completion evidence:

- duplicate submission of the same intent or proof is detected
- a consumed capability cannot be reused
- a second execution attempt with the same proof material is refused
- replay refusal yields zero additional side effects

## AC-007 Protected Endpoint Verification

The refund endpoint MUST be protected by proof verification, escrow validation, and replay checks.

Completion evidence:

- direct calls without proof are refused
- direct calls with proof but without valid escrow are refused
- direct calls with valid proof and valid escrow execute exactly once

## AC-008 Refusal Envelopes

Every refusal path MUST emit a refusal envelope.

The refusal envelope MUST include:

- a refusal code
- a human-readable reason
- the related `intent_id` when present
- relevant rule references or verification failure category
- a timestamp

Completion evidence:

- refusal envelopes are machine-readable
- refusal envelopes do not leak secret material
- refusal envelopes are emitted for schema, policy, proof, escrow, replay, and execution guard failures

## AC-009 Receipts

Every successful protected action MUST emit a receipt.

The receipt MUST include:

- `receipt_id`
- `intent_id`
- tenant identity
- actor identity
- protected action type
- target resource
- executed parameters
- proof linkage
- execution timestamp
- resulting state or external reference

Completion evidence:

- each successful refund has exactly one receipt
- the receipt can be correlated back to the Action Intent and PCCB used
- receipts are durable enough for replay defense and audit

## AC-010 Local Proof Mode

The kernel MUST support local proof mode.

Completion evidence:

- proof minting and verification can run with local deterministic configuration
- the refund wedge can be demonstrated without external signing infrastructure
- local proof mode is clearly separated from future production signer implementations

## AC-011 Finance Wedge: Refund Execution

The first production-quality wedge MUST be refund execution.

The wedge scope is narrow by design:

- refund against a previously recorded payment only
- refund amount less than or equal to remaining refundable balance
- refund currency exactly matches the original payment currency
- no batch refunds
- no multi-leg settlement logic

Completion evidence:

- an allowed refund executes through the protected endpoint
- an over-limit refund is refused before execution
- duplicate refund attempts are blocked
- a successful refund emits a receipt
- a refused refund emits a refusal envelope

## AC-012 Observability And Auditability

The kernel MUST produce enough structured evidence to reconstruct what happened.

Completion evidence:

- logs include correlation identifiers such as `intent_id`, proof identifier, and receipt identifier when available
- policy decisions can be audited
- proof verification failures can be audited
- receipt and refusal records can be queried for test assertions

## AC-013 Test Harness And Acceptance Entry Point

The repository MUST expose a clear rebuild validation path.

Completion evidence:

- `docs/TEST_PLAN.md` defines unit, integration, and end-to-end evidence
- `scripts/verify.sh` remains the single rebuild acceptance entry point
- `scripts/judge.sh` provides a human-readable readiness summary

## Completion Summary

The kernel counts as complete only when all of the following are true:

1. every criterion from AC-001 through AC-013 is satisfied
2. refund execution works end to end through protected verification
3. no proof, no action is enforced on every consequential refund path
4. replay attempts are blocked
5. every success yields a receipt
6. every refusal yields a refusal envelope
