# Execution Semantics

## Purpose

This document defines the category-grade execution state model, idempotency semantics, and retry semantics for the open kernel.

It exists so third-party implementers can target a stable behavioral contract without having to reverse-engineer semantics from the local proof demos.

## State Model

The canonical execution state vocabulary is:

- `received`
- `policy_allowed`
- `proof_minted`
- `escrow_issued`
- `execution_attempted`
- `provider_pending`
- `confirmed`
- `refused`
- `failed`
- `ambiguous`
- `replay_refused`
- `expired`
- `revoked`

The reference model and transition helpers live at:

- `actenon/models/execution.py`

## State Meanings

| State | Meaning |
| --- | --- |
| `received` | A consequential request has entered the protected execution path. |
| `policy_allowed` | Policy evaluation has produced an allow decision for the request. |
| `proof_minted` | A PCCB has been minted for the allowed request. |
| `escrow_issued` | Execution-side single-use state has been issued for the proof-bound capability. |
| `execution_attempted` | The protected handler has been entered after proof, replay, and escrow checks. |
| `provider_pending` | A downstream provider or external system has accepted the action, but final confirmation is still pending. |
| `confirmed` | The protected action is confirmed within the integration boundary. |
| `refused` | The action was intentionally blocked before a side effect crossed the ambiguity boundary. |
| `failed` | The execution path reached a deterministic failure result without needing to treat the outcome as ambiguous. |
| `ambiguous` | The execution path crossed the ambiguity boundary and final side-effect status is not yet known. |
| `replay_refused` | A duplicate execution attempt was refused by replay protection. |
| `expired` | Proof or execution-side authority expired before safe execution could continue. |
| `revoked` | Execution-side authority was explicitly revoked before safe execution could continue. |

## Transition Invariants

The canonical path starts at `received`.

Representative valid paths:

- `received -> policy_allowed -> proof_minted -> escrow_issued -> execution_attempted -> confirmed`
- `received -> refused`
- `received -> policy_allowed -> proof_minted -> escrow_issued -> replay_refused`
- `received -> policy_allowed -> proof_minted -> escrow_issued -> execution_attempted -> provider_pending -> confirmed`
- `received -> policy_allowed -> proof_minted -> escrow_issued -> execution_attempted -> ambiguous -> confirmed`

Representative invalid paths:

- `received -> proof_minted`
- `confirmed -> provider_pending`
- `replay_refused -> execution_attempted`
- `expired -> confirmed`

Terminal states are:

- `confirmed`
- `refused`
- `failed`
- `replay_refused`
- `expired`
- `revoked`

## Idempotency Semantics

The open kernel distinguishes transport idempotency from execution idempotency.

### Action Intent Idempotency

- `ActionIntent.idempotency_key` is a caller retry aid.
- It helps a caller express that multiple submissions represent the same intended request.
- It is not proof, not authorization, and not a substitute for replay protection.

### Execution Idempotency

- Execution idempotency is enforced at the protected execution edge.
- The replay key is derived from proof-bound execution material such as `pccb_id`, `nonce`, `action_hash`, audience, capability, and target.
- A second attempt with the same proof-bound execution identity MUST be refused while the replay claim is active or consumed.

## Retry Semantics

### Safe Retries

Retries are generally safe when:

- the request has not crossed the ambiguity boundary
- the replay claim was released
- the caller corrects a refusal cause and obtains fresh authorization or proof when required

Examples:

- retry after schema correction with a new valid Action Intent
- retry after policy-evidence collection when the system issues a fresh allow path
- retry after a pre-execution proof or escrow failure that released the replay claim

### Unsafe Retries

Retries are unsafe when:

- the request has already been confirmed
- the replay state is consumed
- the execution path crossed the ambiguity boundary and outcome remains unknown

In those cases, an operator or higher-level system should reconcile or investigate before authorizing another attempt.

## Relation To Receipts And Refusals

- receipts record portable outcomes such as `allow`, `executed`, and `refused`
- refusals record structured reasons why the system would not proceed
- the execution state model is a behavioral contract for conformance and reasoning, not a claim that every state is serialized as a first-class top-level field in every artifact

## Related Specs

- [../../spec/protected-endpoint/SPEC.md](../../spec/protected-endpoint/SPEC.md)
- [../../spec/replay/SPEC.md](../../spec/replay/SPEC.md)
- [../../spec/action-intent/SPEC.md](../../spec/action-intent/SPEC.md)
- [../../spec/receipt/SPEC.md](../../spec/receipt/SPEC.md)
- [../../spec/refusal/SPEC.md](../../spec/refusal/SPEC.md)
