# Protected Execution Kernel Task Loop

## Purpose

This document defines the implementation loop for rebuilding the kernel from an empty repository to a passing protected refund execution system.

The loop is intentionally strict: no proof, no action, and no acceptance without `scripts/verify.sh`.

## Build Order

### Phase 1: Contracts First

Deliverables:

- schemas for Action Intent, PCCB, receipt, and refusal envelope
- internal models aligned with the schemas
- deterministic identifiers and timestamps strategy

Definition of done:

- schema fixtures exist
- invalid contract cases are rejected in tests

### Phase 2: Policy Engine

Deliverables:

- hard rules module
- tenant rules module
- dynamic context ingestion layer
- deterministic policy decision output

Definition of done:

- allow and refuse cases are reproducible
- decision output includes rule references and context evidence

### Phase 3: Proof Layer

Deliverables:

- PCCB minting
- PCCB verification
- local proof mode

Definition of done:

- proofs are bound to the approved action
- tampering and expiry are testable refusal paths

### Phase 4: Capability Escrow And Replay Defense

Deliverables:

- escrow record lifecycle
- single-use capability consumption
- replay ledger or equivalent replay detection

Definition of done:

- duplicate execution attempts are blocked
- escrow state is auditable

### Phase 5: Protected Endpoint

Deliverables:

- protected refund endpoint
- verifier integration
- protected refund adapter

Definition of done:

- endpoint refuses direct execution without valid proof
- endpoint executes exactly once when all checks pass

### Phase 6: Receipts And Refusals

Deliverables:

- refusal envelope generation
- receipt generation
- durable persistence for both outcome types

Definition of done:

- every path ends in either a refusal envelope or a receipt
- outcome records are queryable for assertions

### Phase 7: Test Harness And Examples

Deliverables:

- unit tests
- integration tests
- end-to-end tests
- local demo for refund execution

Definition of done:

- the repository can demonstrate the full protected refund flow locally
- `scripts/verify.sh` runs the authoritative checks

## Developer Loop

For every implementation task:

1. pick the next unmet acceptance criterion from `docs/ACCEPTANCE_CRITERIA.md`
2. write or update tests that prove the required behavior
3. implement the smallest slice that satisfies the behavior
4. run `scripts/verify.sh`
5. inspect refusal and receipt artifacts for correctness
6. only move on when the gate passes for the completed scope

## Failure Discipline

When a task fails:

1. preserve the refusal reason, logs, or failing assertion
2. determine whether the failure is contract, policy, proof, escrow, replay, or endpoint related
3. fix the narrowest broken boundary first
4. rerun `scripts/verify.sh`

## Completion Discipline

The kernel does not count as complete because the endpoint can issue a refund.

It only counts as complete when all of the following are true:

- the refund path is proof-required
- the refusal path is explicit and structured
- the success path is explicit and receipted
- replay is blocked
- acceptance criteria AC-001 through AC-013 are satisfied
- `scripts/verify.sh` passes
