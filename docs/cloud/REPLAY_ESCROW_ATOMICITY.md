# Cloud Replay, Escrow, and Receipt Atomicity

Status: Cloud/control-plane atomicity doctrine and local SQLite test evidence.
This document does not claim production Postgres, KMS/HSM, or external-provider
finality validation.

## Core Rule

Single-use proof is only real if the control plane and protected execution path
use storage that lets exactly one worker claim or consume the same authority.
Static proof verification is not enough; replay, issuance, escrow, and receipt
state must be durable and idempotent at the database boundary.

## Stores Identified

| Surface | Current store/model | Atomicity boundary |
|---|---|---|
| Kernel replay store | `SqliteReplayStore`, `PostgresReplayStore` | Atomic replay-key claim with primary-key uniqueness and transactions. |
| Kernel escrow store | `SqliteCapabilityEscrow`, `InMemoryCapabilityEscrow` | SQLite uses `BEGIN IMMEDIATE` and state-guarded updates; in-memory uses an in-process lock only. |
| Cloud proof issuance records | `issued_proofs` | Active proof issuance has a partial uniqueness guard over tenant, Action Intent, proof kind, audience, scope hash, and action digest for `requested`/`issued` proofs. Concurrent contenders replay the one issued proof. |
| Cloud escrow records | `escrow_records` | One escrow hold per issued proof plus state-guarded `held -> released` and `released -> consumed` transitions. |
| Cloud receipt records | `receipt_records` | Tenant plus kernel receipt digest uniqueness makes repeated receipt ingestion idempotent. |
| Cloud audit/transition records | `escrow_transition_records`, `signing_operation_records`, `audit_events` | Written only after the corresponding state claim succeeds. |

## Required Runtime Order

For protected execution, the intended order remains:

1. verify proof and action binding
2. evaluate policy or verify policy-bound proof state
3. claim replay state where configured
4. consume escrow/capability state where configured
5. broker credentials
6. execute handler or target adapter
7. emit Receipt/Refusal and audit records

Proof verification failure and policy refusal must not consume escrow. Broker or
handler failure after escrow consumption is the safe ambiguity boundary: the
single-use state remains consumed and operators reconcile from the Refusal,
Receipt, audit trace, and provider-side idempotency/finality signals.

## Cloud Atomicity Behavior

Cloud proof issuance is idempotent for active proofs. If multiple workers ask
for the same tenant/action/audience/scope/digest at the same time, one request
creates and signs the proof; the other requests return the same issued proof as
idempotent replays.

Cloud escrow release and consume use database state claims:

- release claims only rows still in `held`
- consume claims only rows still in `released` with the matching capability
  token digest
- losing contenders roll back before writing transition records
- a consumed escrow cannot be consumed again in a new session

Receipt ingestion already uses tenant plus digest uniqueness. Repeated
submission of the same kernel receipt returns the existing receipt record.

## Test Evidence

Kernel focused coverage:

- `tests/unit/test_replay_store.py`
- `tests/unit/test_sqlite_escrow.py`
- `tests/unit/test_protected_executor.py`

Cloud focused coverage:

- `Actenon Cloud Control Layer/tests/integration/test_replay_escrow_atomicity.py`
- `Actenon Cloud Control Layer/tests/integration/test_escrow.py`
- `Actenon Cloud Control Layer/tests/integration/test_issuance.py`
- `Actenon Cloud Control Layer/tests/integration/test_receipts.py`

The Cloud atomicity tests prove:

- N concurrent proof issuance attempts produce one issued proof record
- N concurrent escrow consume attempts produce exactly one consumed transition
- consumed escrow state survives a new database session
- existing escrow and issuance flows still pass

## Production Guidance

The local SQLite evidence is appropriate for local, test, demo, and single-node
pilot harnesses. A production deployment must use storage shared by every worker
that can execute the same protected route.

Required production properties:

- atomic insert or state-guarded update for replay/escrow claims
- durable consumed/replayed state across process restart
- database constraints that enforce idempotency under concurrent workers
- provider idempotency keys where a downstream provider supports them
- audit records written only after the corresponding state claim succeeds
- fail-closed behavior when replay, escrow, or receipt state cannot be read or
  written

`InMemoryCapabilityEscrow` is dev/test/demo only. It is process-local,
non-durable, and not a production or multi-worker escrow backend.

The Cloud SQLite test harness does not prove production PostgreSQL transaction
isolation or RLS behavior. Those must be validated against the production
database configuration before production claims.

## Related Documents

- [`docs/architecture/REPLAY_ESCROW_CONCURRENCY.md`](../architecture/REPLAY_ESCROW_CONCURRENCY.md)
- [`docs/cloud/FULL_LIFECYCLE_TEST.md`](FULL_LIFECYCLE_TEST.md)
- [`docs/cloud/TENANT_ISOLATION_MODEL.md`](TENANT_ISOLATION_MODEL.md)
- [`THREAT_MODEL.md`](../../THREAT_MODEL.md)
