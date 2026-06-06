# Replay Store Operations

## Security Property

Replay protection makes a proof single-use only across execution edges that
share the same durable replay store and replay-key namespace.

`ProtectedExecutor` fails closed by default. If the replay store cannot
atomically claim or consume a proof, the executor emits a Refusal with
`REPLAY_STORE_UNAVAILABLE` and does not call the side-effect handler.

The protected ordering is:

1. verify the exact Action Intent and PCCB
2. evaluate policy
3. atomically claim the replay key
4. consume escrow, when configured
5. acquire the brokered credential
6. durably mark the replay key consumed
7. call the side-effect handler
8. emit the Receipt or Refusal

Recording consumption before step 7 intentionally burns the proof at the
execution ambiguity boundary. A handler failure must not make the same proof
safe to retry.

## Deployment Requirements

Every process, container, region, or protected edge that can perform the same
consequential action must use a replay store with:

- atomic conditional insert or equivalent uniqueness enforcement
- durable committed writes before the side effect runs
- consistency strong enough that all writers observe the same replay-key state
- stable storage across process and node replacement
- authenticated transport and least-privilege database credentials
- backups, restore controls, and monitoring that preserve or detect monotonic state

Use `SqliteReplayStore` for local or single-node deployments where all
executors use the same database file. SQLite uses `BEGIN IMMEDIATE`, a primary
key on `replay_key`, WAL, and `synchronous=FULL`.

Use `PostgresReplayStore` for multi-process, multi-container, or multi-node
deployments. All protected edges must connect to the same authoritative
database. The adapter uses a transaction plus
`INSERT ... ON CONFLICT (replay_key) DO NOTHING`, so concurrent claims have one
winner.

Asynchronous replicas are not safe write authorities for replay claims. Route
claims and consumes to the authoritative writer. Configure database durability
and synchronous replication to match the consequence class.

## Failure Behavior

Default behavior is:

```python
ProtectedExecutor(
    proof_verifier=verifier,
    credential_broker=broker,
    replay_protector=replay_protector,
    replay_store_failure="fail_closed",
)
```

An unavailable store refuses before the side effect. Monitor at least:

- `REPLAY_STORE_UNAVAILABLE`
- `REPLAY_STORE_ROLLBACK_DETECTED`
- `DUPLICATE_REPLAY`
- database connection and transaction failures
- replication lag and failover events
- backup restore and point-in-time recovery operations

The unsafe operational escape hatch is explicit:

```python
ProtectedExecutor(
    proof_verifier=verifier,
    credential_broker=broker,
    replay_protector=replay_protector,
    replay_store_failure="fail_open",
)
```

Construction logs:

```text
Actenon: replay store failures configured FAIL-OPEN — an action may execute when single-use cannot be enforced. This is unsafe for consequential actions.
```

Fail-open applies only to replay-store operational failures. A known duplicate,
invalid replay transition, or detected rollback remains a refusal. Do not use
fail-open for consequential production actions.

## Rollback And Replay-Window Detection

The relational stores maintain a mutation counter in
`replay_store_metadata`. A live store instance remembers the highest counter it
has observed and refuses with `REPLAY_STORE_ROLLBACK_DETECTED` if the database
regresses behind it.

This is a detection aid, not an external trust anchor. It cannot detect a
database rollback that occurs before a fresh process has observed the newer
counter, or a restore that also resets every external observation. Production
operators should additionally:

- export the mutation counter or transaction position to tamper-resistant monitoring
- alert on counter regression, database promotion, restore, and timeline changes
- restrict restore privileges separately from application write privileges
- retain append-only audit evidence outside the replay database
- test failover and restore procedures with concurrent duplicate submissions
- prevent old snapshots from becoming writable without an explicit security review

After a restore or uncertain partition, keep protected execution unavailable
until operators establish that the replay state is at least as recent as the
last accepted side effect.

## Cross-Edge Semantics

Cross-edge single-use holds when all of these are true:

- every route to the side effect passes through a protected executor
- every executor derives the same replay key for the same proof-bound action
- every executor uses the same consistent durable store
- the store commits claim and consume transitions atomically
- the backend accepts only credentials brokered after verification

An isolated local database per edge does not provide cross-edge single-use.
Neither does a shared store reached through stale replicas or a bypass route
with standing credentials.

This guidance defines proof-bound execution behavior at the protected boundary.
It does not claim downstream provider finality or eliminate failures outside
that boundary.
