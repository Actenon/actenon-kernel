# Replay and Escrow Concurrency

Status: kernel deployment guidance and test contract.

## Core Rule

Single-use execution is only real when replay and escrow state are claimed or
consumed atomically by storage shared by every worker that can execute the same
protected route.

Proof verification alone validates an artifact. It does not make that artifact
single-use. Protected execution needs a replay claim and, where configured, a
capability escrow consume before credentials are brokered or side effects run.

## Required Ordering

For routes that use replay and escrow, the protected endpoint order is:

1. verify the Action Intent and PCCB
2. apply policy or Preflight-bound policy result
3. claim replay state
4. consume escrow/capability state
5. acquire brokered credentials
6. execute the handler
7. mark replay consumed
8. emit Receipt or Refusal

If proof verification fails, escrow is not consumed. If policy fails, escrow is
not consumed. If escrow fails after a replay claim, the replay claim is released
because no consequential authority was brokered.

If the credential broker or handler fails after escrow consumption, the replay
and escrow state remain consumed. That is the safe ambiguity boundary: the same
proof must not be retried as though no authority may have been used. Operators
should reconcile from the emitted Refusal/Receipt and deployment logs.

## Store Guidance

| Store | Concurrency posture | Production guidance |
|---|---|---|
| `SqliteReplayStore` | Uses SQLite transactions, `BEGIN IMMEDIATE`, and `replay_key` primary-key uniqueness. Concurrent local claims against the same database file allow exactly one winner. | Suitable for local, demo, and single-node deployments. Do not treat a node-local SQLite file as shared state for multi-node protected endpoints. |
| `SqliteCapabilityEscrow` | Uses SQLite transactions and state-guarded updates. Concurrent local consumes against the same database file allow exactly one winner. | Suitable for local, demo, and single-node deployments. Multi-node deployments need a shared transactional escrow backend. |
| `InMemoryCapabilityEscrow` | Uses an in-process lock, so concurrent threads in one process allow exactly one winner. State is not durable and is not shared across processes. | Dev/test/demo only. Not a production or multi-worker escrow backend. |
| `PostgresReplayStore` | Uses a transactional DB-API store and `replay_key` primary-key uniqueness. | Recommended OSS replay backend for multi-instance deployments. |

The kernel currently ships a production-oriented PostgreSQL replay store. It
does not ship a PostgreSQL escrow backend in this pass. Production deployments
that require multi-worker escrow must provide a `CapabilityEscrow`
implementation backed by a shared transactional store with an atomic
`issued -> consumed` transition.

## Atomicity Requirements For Custom Stores

Replay stores must:

- claim by atomic insert or equivalent uniqueness constraint
- reject active duplicates with a replay refusal
- persist consumed state across process restart
- avoid check-then-set logic without a transaction or lock

Escrow stores must:

- consume by atomic state transition, such as `UPDATE ... WHERE state='issued'`
- reject consumed, revoked, expired, mismatched proof, and mismatched capability
- persist consumed state across process restart where durability is claimed
- avoid check-then-set logic without a transaction or lock

## Test Contract

The kernel security tests cover:

- concurrent replay claims with exactly one winner
- concurrent SQLite escrow consumes with exactly one winner
- concurrent in-memory escrow consumes with exactly one in-process winner
- expired escrow refusal
- revoked escrow refusal
- consumed escrow and replay state surviving SQLite reopen
- proof and policy failure not consuming escrow
- broker failure after escrow consumption producing a safe refused outcome

These tests prove the local store contract. They do not prove a custom
production store is safe unless that store is tested against the same atomicity
requirements.

