# Replay Store Reference

## Public Package Surface

The replay package lives under `actenon/replay`.

Key types:

- `ReplayStore`: replay store interface
- `ActionConsumptionClaim`: claim input model
- `ActionConsumptionState`: durable action-consumption state model
- `DbApiReplayStore`: production-oriented transactional abstraction
- `SqliteReplayStore`: durable local/dev backend
- `PostgresReplayStore`: PostgreSQL backend for multi-instance deployments
- `ReplayProtector`: middleware-facing replay helper

## ReplayStore Operations

### `claim_once(claim, now)`

Attempts to atomically claim a replay key.

Behavior:

- first claim succeeds and returns state `claimed`
- active duplicate claim raises replay refusal
- expired or released claims may be reclaimed

### `mark_consumed(replay_key, now)`

Marks a claimed action as consumed.

Behavior:

- transitions `claimed -> consumed`
- rejects invalid transitions

### `release_claim(replay_key, now, reason)`

Releases a claim when a pre-execution guard fails and no consequential side effect occurred.

Behavior:

- transitions `claimed -> released`
- consumed records are left unchanged

### `inspect(replay_key, now=None)`

Reads the current state for a replay key.

Behavior:

- returns `None` when no record exists
- may surface stale claims as `expired`

### `purge_expired(now)`

Marks stale unconsumed claims as expired.

Behavior:

- updates `claimed -> expired` for claims past expiry
- returns the number of affected records

## Default Backend

`ProtectedExecutor` constructs a `ReplayProtector` with the default replay store when the caller does not inject one. Replay/single-use protection is therefore default-on for this protected execution path.

Default store:

- `SqliteReplayStore`
- location from `ACTENON_REPLAY_DB` when set
- otherwise `.actenon/replay.sqlite3`

The explicit `replay_protection="disabled"` mode restores execution without a replay store and logs an unsafe-configuration warning. Supplying both an explicit `replay_protector` and `replay_protection="disabled"` is rejected.

Replay-store operational failures are fail-closed by default. The executor
emits `REPLAY_STORE_UNAVAILABLE` and does not call the side-effect handler when
a claim or consume cannot be committed. The explicit
`replay_store_failure="fail_open"` mode logs an unsafe-configuration warning.
Known duplicates, invalid transitions, and detected rollback remain refusals.

SQLite is intentionally the local and single-node default. It is appropriate
for demos, tests, local proof runs, and a single process or single-node
deployment where every worker that can execute the route uses the same local
SQLite file. It is not a multi-node shared-state story.

## PostgreSQL Backend

Use `PostgresReplayStore` for production OSS deployments that run more than one worker, process, container, or node against the same protected endpoint identity.

Install an optional PostgreSQL DB-API driver:

```bash
pip install "actenon-kernel[postgres]"
```

Then inject the store explicitly:

```python
from actenon.replay import PostgresReplayStore, ReplayProtector

replay_store = PostgresReplayStore(dsn="postgresql://actenon:secret@db.example/actenon")
replay_protector = ReplayProtector(replay_store)
```

You may also pass a DB-API compatible `connection_factory` if the host application owns connection pooling.

The PostgreSQL adapter uses the same `action_consumption` table shape as the
DB-API replay model and relies on PostgreSQL transactions, a conditional
`INSERT ... ON CONFLICT DO NOTHING`, and the `replay_key` primary key for
atomic duplicate-claim refusal across instances.

SQLite and PostgreSQL stores also maintain a monotonic mutation counter in
`replay_store_metadata`. A live store instance refuses a counter regression
with `REPLAY_STORE_ROLLBACK_DETECTED`. See
[Replay Store Operations](../../guides/REPLAY_STORE_OPERATIONS.md) for the
detector's limits and the external monitoring required around backup restores
and failover.

## Recommended Host Usage

Hosts should not disable replay protection.

Recommended patterns:

- accept the default SQLite backend in local/dev
- use `PostgresReplayStore` for production multi-instance OSS deployments
- keep replay and escrow enabled together

## Testing Surface

The test suite covers:

- first claim and consume success
- duplicate replay refusal
- expiry and reclaim behavior
- concurrent claim races against the durable backend
- consumed replay state surviving SQLite reopen
- PostgreSQL adapter schema initialization and claim/refusal/expiry behavior through the DB-API abstraction

Capability escrow has the same single-use requirement. The shipped SQLite
escrow store uses transactions and state-guarded updates for local/single-node
atomic consume. The in-memory escrow uses an in-process lock and is dev/test
only because it is neither durable nor shared across worker processes.
