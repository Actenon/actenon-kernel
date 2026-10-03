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
