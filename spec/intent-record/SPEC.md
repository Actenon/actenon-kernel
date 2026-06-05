# Intent Record Spec

## Status

`Intent Record` is a public additive kernel surface with draft artifact shape `intent_record v1alpha1`.

It is intentionally narrow in this pass:

- suitable for local issuer and simulator output
- suitable for educational and inspection use
- suitable as a future runtime-enforcement anchor
- not an active v1 proof-verification requirement

This spec does not change active `Action Intent`, `PCCB`, `Receipt`, `Refusal`, or protected-endpoint compatibility semantics.

## Purpose

An `Intent Record` captures bounded machine delegation as a first-class artifact.

It answers:

- what action was delegated
- for which execution edge
- with what explicit boundaries
- with what current decision state
- whether proof was issued yet
- which execution evidence exists so far

The kernel already had strong proof verification and execution evidence. `Intent Record` adds a computable delegation layer between authorization and proof.

## What It Is And Is Not

### Authorization

Authorization answers who may ask for an action or submit a request.

Authorization alone does not define the exact bounded machine action, the exact execution edge, or the exact abort conditions.

### Intent

`Intent Record` expresses bounded delegation:

- prohibited actions
- abort conditions
- blast-radius limits
- required approvals
- required evidence

It is the boundary statement for what the machine is supposed to be allowed to do and what must stop it.

### Proof

`PCCB` proves that a specific `Action Intent` was allowed for a specific execution edge and bounded scope.

Proof is what the protected endpoint verifies before side effects.

`Intent Record` is not a substitute for proof. It records the bounded delegation and proof state.

### Execution Evidence

`Receipt`, `Refusal`, receipt chains, and evidence queries answer what actually happened.

Execution evidence is downstream from intent and proof.

`Intent Record` is not an execution artifact. It is the bounded delegation artifact that helps explain why proof was or was not issued and what boundaries were in force.

## Contract Shape

`Intent Record` uses:

- `contract.name = "intent_record"`
- `contract.version = "v1alpha1"`

Current top-level fields:

- `intent_record_id`
- `created_at`
- `source`
- `intent_id`
- `tenant`
- `subject`
- `audience`
- `action`
- `target`
- `decision`
- `boundaries`
- `proof`
- `execution_evidence`

## Decision Section

`decision` captures the current bounded-delegation state:

- `outcome`
- `summary`
- `reason_codes`

Typical outcomes in current local kernel usage:

- `allow`
- `deny`
- `approval-required`
- `needs-evidence`

## Boundaries Section

`boundaries` defines the explicit delegation limits.

### `prohibited_actions`

Names actions or action families that are explicitly outside the delegation.

This field is descriptive in the current implementation unless a specific policy or endpoint already enforces it.

### `abort_conditions`

Names conditions that must stop proof issuance or execution.

Examples:

- `audience_mismatch`
- `batch_hash_mismatch`
- `duplicate_replay_detected`
- `merchant_mismatch`

This field is intended to be machine-readable and educational today, with broader generic enforcement deferred.

### `blast_radius_limits`

Defines concrete scope caps as named limit objects.

Each object contains:

- `name`
- `summary`
- optional `value`
- optional `unit`

Examples:

- max amount
- max targeted resources
- max invoices in a delegated batch
- max side effects

### `required_approvals`

Lists approvals that must exist before proof issuance or execution may proceed.

In current local kernel use, this is especially relevant for local issuer and simulator flows that stop at `approval-required`.

### `required_evidence`

Lists evidence types that must exist before proof issuance or execution may proceed.

In current local kernel use, this is especially relevant for `needs-evidence` and finance-style local issuer flows.

## Proof Section

`proof` records proof state without redefining `PCCB`.

Fields:

- `required_for_execution`
- `status`
- optional `pccb_id`

Current statuses:

- `issued`
- `not-issued`

Typical meanings:

- `issued`: a `PCCB` exists for this delegated intent
- `not-issued`: proof has not been minted because the flow stopped at denial, approval, or evidence requirements

## Execution Evidence Section

`execution_evidence` links the current bounded delegation to emitted artifacts without redefining `Receipt` or `Refusal`.

Fields:

- optional `receipt_id`
- optional `refusal_id`

This section is intentionally narrow. Rich evidence lookup stays in the Evidence API and receipt-chain surfaces.

## Current Kernel Usage

The current kernel uses `Intent Record` in these places:

- local issuer request artifacts
- incident simulator artifacts

This means the artifact is already useful for:

- educational simulation
- local runtime inspection
- future runtime enforcement planning
- explaining the difference between approval state, proof state, and execution evidence

## Current Non-Goals

This spec does not currently define:

- a new mandatory protected-endpoint input
- a new wire requirement for active v1 proof verification
- a hosted intent registry
- a multi-party coordination workflow
- generic enforcement of every listed boundary

## Example

- [`examples/invoice-payment-approval.json`](examples/invoice-payment-approval.json)
