# Operation Identity, Idempotency and Reconciliation Design

> **Phase 4A design note.** Defines the operation model, idempotency
> semantics, and reconciliation abstraction for the Actenon kernel.
> This is a design document — no production code changes are made in
> Phase 4A beyond the regression tests and design scaffolding.
>
> **Central invariant preserved:** No valid proof, no execution.

## Architectural Distinction

Three distinct concerns are currently conflated in the kernel:

| Concern | Current mechanism | What it controls |
|---|---|---|
| **Replay protection** | `ReplayStore.claim_once()` / `mark_consumed()` / `release_claim()` | Authority reuse — prevents the same PCCB from authorising execution twice |
| **Idempotency** | None | Duplicate business execution — prevents the same business operation from executing twice even with different PCCBs |
| **Reconciliation** | None | Ambiguous provider outcomes — resolves whether a handler that threw after the provider accepted the call actually executed or not |

Currently, replay protection is the only mechanism, and it conflates all three:
a replayed proof is rejected as "already used" without distinguishing "same
operation, same action" (idempotent replay — should return prior result) from
"same proof, different operation" (which shouldn't happen in normal operation).

## Operation Identity

### Proposed identifier: `operation_id`

The `operation_id` is an immutable identifier bound to the exact action.
It is:

- **caller-supplied** (the agent or issuer provides it at mint time);
- **bound to the action_hash** (included in the PCCB's signed payload so it cannot be substituted);
- **stored in the receipt** (so prior results can be looked up by operation_id);
- **stored in the replay state** (so the replay store can detect same-operation + same-action vs same-operation + different-action).

The identifier is placed in `ActionIntent.metadata["operation_id"]` (additive
— no schema change to the v1 Action Intent contract required, since
`metadata` is already an open dict). The PCCB builder includes it in the
action hash input, so it is cryptographically bound.

If the caller does not supply an `operation_id`, the kernel derives one
from the `replay_key` (the existing hash of PCCB+intent+nonce+action_hash).
This preserves backward compatibility — existing callers that don't supply
an operation_id get the same replay semantics as today.

## State Model

### Operation States

The kernel already has `ActionConsumptionStatus` (`claimed`, `consumed`,
`released`, `expired`). The operation model extends this with business
execution states:

| State | Meaning | Terminal? | Corresponds to ActionConsumptionStatus |
|---|---|---|---|
| `CLAIMED` | Operation claimed; execution in progress | No | `claimed` |
| `EXECUTED` | Handler completed; provider confirmed success | Yes | `consumed` |
| `NOT_EXECUTED` | Handler did not run; proof/escrow/policy refused | Yes | `released` |
| `REFUSED` | Policy or proof verification denied execution | Yes | `released` |
| `OUTCOME_UNKNOWN` | Handler threw; provider outcome ambiguous | Yes | `consumed` (fail-closed) |
| `RECONCILED_EXECUTED` | Reconciler confirmed provider executed | Yes | `consumed` |
| `RECONCILED_NOT_EXECUTED` | Reconciler confirmed provider did not execute | Yes | `consumed` (but refundable) |

States `EXECUTED`, `NOT_EXECUTED`, `REFUSED`, `OUTCOME_UNKNOWN`,
`RECONCILED_EXECUTED`, `RECONCILED_NOT_EXECUTED` are all terminal.
`CLAIMED` is the only non-terminal state.

### Transitions

```
                    ┌─────────────┐
                    │   CLAIMED   │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
     ┌──────────┐   ┌──────────┐   ┌────────────────┐
     │ EXECUTED  │   │ REFUSED  │   │ OUTCOME_UNKNOWN │
     └──────────┘   └──────────┘   └───────┬────────┘
                                            │
                                    ┌───────┴───────┐
                                    │               │
                                    ▼               ▼
                          ┌─────────────────┐ ┌──────────────────────┐
                          │RECONCILED_EXECUTED│ │RECONCILED_NOT_EXECUTED│
                          └─────────────────┘ └──────────────────────┘
```

`NOT_EXECUTED` is entered when the handler is never called (proof/escrow/policy
failure before handler invocation). `REFUSED` is entered when the policy
decision is DENY.

Only `OUTCOME_UNKNOWN` can transition to a reconciled state. All other
terminal states are immutable.

## Idempotency Semantics

### First request (normal path)

1. Validate proof (signature + semantic checks)
2. Atomically claim the operation (`operation_id` + `action_hash`)
3. Execute the handler at most once
4. Pass `operation_id` to providers that support idempotency (via
   `BrokeredCredential.metadata` or handler kwargs)
5. Store the terminal result (receipt + operation state)
6. Consume the proof (mark replay as `consumed`)

### Same operation_id + same action_hash (idempotent replay)

1. Validate proof
2. Look up `operation_id` in the operation store
3. If found with matching `action_hash`:
   - Return the prior recorded result/receipt
   - Expose `IDEMPOTENT_REPLAY` as the outcome
   - Do NOT execute the handler again
   - Do NOT consume a new proof (the prior proof was already consumed)
4. The returned receipt is the ORIGINAL receipt, not a new one

### Same operation_id + different action_hash (idempotency conflict)

1. Validate proof
2. Look up `operation_id` in the operation store
3. If found with DIFFERENT `action_hash`:
   - Return `IDEMPOTENCY_CONFLICT`
   - Do NOT execute the handler
   - Do NOT consume the proof (the caller can retry with the correct operation_id)

## Ambiguous Provider Outcome

When the handler throws an exception AFTER the provider may have accepted
the call (e.g., network timeout after the payment was submitted):

1. Consume the authority (mark replay as `consumed` — fail-closed)
2. Mark the operation `OUTCOME_UNKNOWN`
3. Persist a durable ambiguous-outcome record:
   - `operation_id`
   - `pccb_id`
   - `action_hash`
   - `handler_exception` (redacted)
   - `occurred_at`
4. Do NOT retry automatically
5. Do NOT reissue authority
6. Require manual reconciliation

## Reconciliation Abstraction

### Interface

```python
class OperationReconciler(Protocol):
    def reconcile(
        self,
        operation_id: str,
        *,
        resolved_outcome: Literal["executed", "not_executed"],
        provider_evidence: dict[str, Any],
        reconciler: PartyRef,
    ) -> Receipt:
        ...
```

### Semantics

- **Provider-neutral**: the reconciler doesn't call the provider; it
  receives provider evidence from the operator who has already queried
  the provider.
- **Query by operation_id**: the reconciler looks up the operation
  record and verifies it is in `OUTCOME_UNKNOWN` state.
- **Resolve to `RECONCILED_EXECUTED` or `RECONCILED_NOT_EXECUTED`**:
  the reconciler transitions the operation to a reconciled state.
- **Attach provider evidence**: the evidence is stored in the
  reconciliation receipt's `details` field.
- **Emit a reconciliation receipt**: a new Receipt with
  `outcome="reconciled"` and `phase="reconciliation"`.
- **Preserve the original action hash**: the reconciliation receipt
  carries the same `action_hash` as the original operation.
- **Preserve the original authority reference**: the reconciliation
  receipt carries the same `pccb_id` and `escrow_id`.
- **Prevent alteration of the originally requested action**: the
  reconciler cannot change the `action_hash`, `target`, or any other
  bound parameter.
- **Require an authorised reconciler**: the `reconciler` PartyRef must
  be authorised by the deployment's policy to perform reconciliation.

## Storage Transaction Boundaries

### Current

The `SqliteReplayStore` wraps `claim_once` / `mark_consumed` /
`release_claim` in `BEGIN IMMEDIATE` transactions. This is correct for
replay protection but does not cover the full operation lifecycle.

### Proposed

The operation store needs a single transaction that covers:
1. Claim (INSERT or fail if operation_id already exists)
2. Store result (UPDATE with terminal state + receipt_id)
3. Store ambiguous-outcome record (INSERT into a separate table)

The transaction boundary is:
```
BEGIN IMMEDIATE
  INSERT INTO operations (operation_id, action_hash, pccb_id, status, ...)
  ON CONFLICT(operation_id) DO NOTHING
  if inserted:
    -- first request, proceed with execution
  else:
    -- duplicate: check if action_hash matches
    SELECT action_hash, status, receipt_id FROM operations WHERE operation_id = ?
    if action_hash matches and status is terminal:
      return prior result (IDEMPOTENT_REPLAY)
    elif action_hash differs:
      return IDEMPOTENCY_CONFLICT
    elif status is CLAIMED:
      return IN_PROGRESS (another request is executing)
COMMIT
```

## Proof-Consumption Order

The current order is correct and preserved:

1. **Verify proof** (signature + semantic checks)
2. **Claim replay** (atomic `claim_once` on the replay store)
3. **Consume escrow** (if configured)
4. **Acquire credential** (broker)
5. **Mark replay consumed** (before handler runs — fail-closed)
6. **Execute handler**
7. **Release credential** (after handler returns or throws)
8. **Write receipt** (terminal result)

The operation_id claim happens BETWEEN step 1 and step 2, so that:
- An idempotent replay is detected before consuming the replay slot
- An idempotency conflict is detected before consuming the replay slot
- The proof is NOT consumed for idempotent replays or conflicts

## Crash Points

| Crash point | Current behaviour | Proposed behaviour |
|---|---|---|
| After claim, before mark_consumed | Replay claim is released (correct) | Same — operation stays CLAIMED, must be manually resolved |
| After mark_consumed, before handler | Replay is consumed (fail-closed); no receipt emitted | Same — operation is OUTCOME_UNKNOWN, requires reconciliation |
| During handler (handler throws) | Replay is consumed; EXECUTION_FAILED refusal emitted | Operation is OUTCOME_UNKNOWN; ambiguous-outcome record persisted |
| After handler, before receipt write | Replay is consumed; no receipt (data loss) | Operation is EXECUTED but receipt may be missing; receipt store should be transactional with operation state |
| After receipt write | Normal | Normal |

## Provider-Idempotency Propagation

The `operation_id` is passed to the handler via the `BrokeredHandler`
callback's second argument (`BrokeredCredential`). The handler can read
it from `credential.metadata["operation_id"]` and pass it to the provider
as the provider's idempotency key (e.g., Stripe's `Idempotency-Key`
header, AWS's `ClientRequestToken`).

This is a convention, not a requirement — providers that don't support
idempotency keys simply ignore it. The kernel's own idempotency is
enforced by the operation store, not by the provider.

## Backend-Specific Transaction Requirements

| Backend | Requirement |
|---|---|
| SQLite (current default) | `BEGIN IMMEDIATE` + `PRAGMA busy_timeout` for atomic claim. The operation table is a new table in the same SQLite database. |
| PostgreSQL (cloud) | `SELECT ... FOR UPDATE` or `INSERT ... ON CONFLICT DO NOTHING` for atomic claim. The operation table is a new table in the cloud database, with RLS policies matching the existing tenant-scoped tables. |
| InMemory (tests) | Dictionary with a threading.Lock for atomic claim. |

## Compatibility Impact

- **No public schema changes** to PCCB v1 or Receipt v1.
- `operation_id` is stored in `ActionIntent.metadata` (already an open dict).
- The operation store is a new internal table — no existing table is modified.
- Existing callers that don't supply `operation_id` get the same replay
  semantics as today (derived from the replay_key).
- The `ActionConsumptionStatus` enum is extended, not replaced.
- New failure codes: `IDEMPOTENT_REPLAY`, `IDEMPOTENCY_CONFLICT`,
  `OUTCOME_UNKNOWN` are additive to the existing taxonomy.
- The `FailureCode` taxonomy maps them:
  - `IDEMPOTENT_REPLAY` → `DUPLICATE_REPLAY` (same semantics: not a new execution)
  - `IDEMPOTENCY_CONFLICT` → `ACTION_MISMATCH` (same semantics: the action doesn't match)
  - `OUTCOME_UNKNOWN` → `ENGINE_ERROR` (requires manual intervention)
