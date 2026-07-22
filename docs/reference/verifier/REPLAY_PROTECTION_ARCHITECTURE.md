# Replay Protection Architecture

## Purpose

Replay protection is a kernel-owned execution safeguard.

It is not optional host-app glue. The protected execution layer ships with replay claim and consumption behavior as a first-class packaged capability.

## Design Goal

Prevent the same proof-bound action from being executed more than once, even when:

- clients retry requests
- middleware is invoked concurrently
- protected handlers are called from multiple worker processes
- execution attempts race across the same durable backend

## Core Model

Replay protection operates on an action consumption record.

The record binds:

- replay key
- intent identifier
- PCCB identifier
- nonce
- action hash
- audience
- capability
- tenant
- subject
- expiry

## State Model

The replay store tracks these states:

- `claimed`: execution has claimed the replay key and duplicate claims must fail
- `consumed`: execution completed or reached an ambiguity boundary where duplicate retries are unsafe
- `released`: the claim was abandoned before side effects and may be reclaimed
- `expired`: a stale unconsumed claim aged out and may be reclaimed

## Request Flow

1. The protected endpoint verifies proof integrity and binding.
2. Replay protection derives a replay key from PCCB identity, nonce, audience, capability, target, and action hash.
3. The replay store attempts an atomic `claim_once`.
4. If the claim already exists in an active state, the kernel returns a structured replay refusal.
5. If escrow or another pre-execution guard fails after the replay claim, the claim is released.
6. If execution succeeds, the claim is marked `consumed`.
7. If execution fails after entering the handler, the claim is also marked `consumed` to avoid ambiguous duplicate side effects.

## Why Replay Is Separate From Escrow

Escrow and replay solve different problems:

- escrow binds a capability to a single-use approval path
- replay protects the execution edge itself from repeated proof-bound delivery

The kernel now ships both. Replay is not delegated to the host app.

## Default Backend

Default backend: SQLite durable store at:

- environment override: `ACTENON_REPLAY_DB`
- fallback path: `.actenon/replay.sqlite3`

This backend is suitable for local, development, demo, and single-node use through SQLite transaction semantics.

## Production-Credible Abstraction

The production-oriented abstraction is `DbApiReplayStore`, with `PostgresReplayStore` as the concrete PostgreSQL implementation for production OSS multi-instance deployments.

It defines the required atomic operations for a transactional relational backend:

- `claim_once`
- `mark_consumed`
- `release_claim`
- `inspect`
- `purge_expired`

Production deployments can implement the same interface against a stronger relational backend while preserving kernel behavior.

For the shipped production-grade OSS path, prefer PostgreSQL:

- it centralizes replay state across workers and nodes
- it preserves atomic duplicate-claim refusal with transactions and a `replay_key` primary key
- it avoids treating a node-local SQLite file as shared production state

SQLite remains the right default for local proof mode and single-node demos.
For replay and escrow concurrency guidance, including in-memory escrow
limitations and broker-failure ambiguity semantics, see
[`docs/architecture/REPLAY_ESCROW_CONCURRENCY.md`](../../architecture/REPLAY_ESCROW_CONCURRENCY.md).

## Failure Semantics

- duplicate claim: `DUPLICATE_REPLAY`
- invalid state transition: `REPLAY_STATE_INVALID`
- missing claim on release: `REPLAY_CLAIM_MISSING`

All replay failures surface as structured `replay` refusal envelopes.
