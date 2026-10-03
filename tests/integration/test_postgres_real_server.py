"""PostgresReplayStore against a real PostgreSQL server.

Runs only when ACTENON_TEST_POSTGRES_DSN is set (CI job `postgres-replay`
provides a PostgreSQL 16 service; there the skip gate allows no skip). Each
gate below has its own store instance and connection, standing in for a
separate worker process.
"""

from __future__ import annotations

import os
import threading
import uuid

import pytest

from actenon.gate import ActenonGate
from actenon.replay import PostgresReplayStore, ReplayProtector
from tests.security.test_production_environment_paths import _Ed25519Signer

DSN = os.environ.get("ACTENON_TEST_POSTGRES_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="ACTENON_TEST_POSTGRES_DSN not set (runs in the postgres-replay CI job)")


def _gate(trust, dsn=DSN, **kwargs) -> ActenonGate:
    return ActenonGate(verifier=trust, audience="service:payments", issuer="service:issuer",
                       capabilities=("payment.refund",),
                       replay_protector=ReplayProtector(PostgresReplayStore(dsn)), **kwargs)


def test_one_execution_across_independent_store_connections(monkeypatch):
    monkeypatch.setenv("ACTENON_ENV", "production")
    signer = _Ed25519Signer()
    issuer = _gate(signer, signer=signer)
    action = issuer.build_action("refund", "payment.refund", {"amount_minor": 100},
                                 target_type="charge", target_id=f"ch_{uuid.uuid4().hex}")
    proof = issuer.mint_proof(action)
    workers = [_gate(signer) for _ in range(4)]
    executed: list[int] = []
    lock = threading.Lock()

    def present(gate):
        def effect():
            with lock:
                executed.append(1)
        gate.protect(action, proof, effect)

    threads = [threading.Thread(target=present, args=(gate,)) for gate in workers for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert executed == [1]
    assert _gate(signer).protect(action, proof, lambda: executed.append(2)).reason_code == "DUPLICATE_REPLAY"
    assert executed == [1]


def test_unreachable_server_never_executes(monkeypatch):
    monkeypatch.setenv("ACTENON_ENV", "production")
    signer = _Ed25519Signer()
    issuer = _gate(signer, signer=signer)
    action = issuer.build_action("refund", "payment.refund", {"amount_minor": 100},
                                 target_type="charge", target_id=f"ch_{uuid.uuid4().hex}")
    proof = issuer.mint_proof(action)
    executed: list[int] = []
    try:
        gate = _gate(signer, dsn="postgresql://postgres@/actenon?host=/nonexistent&port=1")
    except Exception:
        return  # refused at construction: fails closed
    out = gate.protect(action, proof, lambda: executed.append(1))
    assert not out.ok and executed == []


def _construct_store(dsn: str, schema: str, barrier, results) -> None:
    barrier.wait()
    try:
        PostgresReplayStore(dsn, connect_kwargs={"options": f"-c search_path={schema}"})
        results.put("ok")
    except Exception as exc:  # reported, then asserted on by the parent
        results.put(f"{type(exc).__name__}: {str(exc).splitlines()[0]}")


def test_concurrent_cold_start_creates_the_schema_once():
    """Workers starting together against an empty database must all start.

    CREATE TABLE IF NOT EXISTS is not concurrency-safe in PostgreSQL: before the
    advisory lock, 139 of 160 such constructors failed with UniqueViolation on
    pg_type (north-star evidence), i.e. a cold-started fleet lost workers.
    """
    import multiprocessing

    import psycopg

    ctx = multiprocessing.get_context("spawn")
    for _ in range(3):
        schema = f"cold_start_{uuid.uuid4().hex[:12]}"
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(f"CREATE SCHEMA {schema}")
        try:
            barrier, results = ctx.Barrier(8), ctx.Queue()
            workers = [ctx.Process(target=_construct_store, args=(DSN, schema, barrier, results)) for _ in range(8)]
            for w in workers:
                w.start()
            for w in workers:
                w.join(60)
            outcomes = [results.get(timeout=5) for _ in workers]
            assert outcomes == ["ok"] * 8, outcomes
        finally:
            with psycopg.connect(DSN, autocommit=True) as conn:
                conn.execute(f"DROP SCHEMA {schema} CASCADE")
