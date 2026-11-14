"""Every store operation must close the connection it opened.

Leaving ``with connection`` only ends the transaction for sqlite3: the connection
and its file descriptors stayed open until the cyclic garbage collector ran. A
long-lived process making one claim per request climbed to its descriptor limit
and then failed every request.
"""

from __future__ import annotations

import gc
import os
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.core import EscrowValidationError, ReplayValidationError
from actenon.escrow import SqliteCapabilityEscrow
from actenon.replay import ActionConsumptionClaim, SqliteReplayStore


def build_claim(replay_key: str, *, expires_at: datetime | None = None) -> ActionConsumptionClaim:
    return ActionConsumptionClaim(
        replay_key=replay_key,
        intent_id="intent_001",
        pccb_id="pccb_001",
        nonce="nonce_0011223344556677",
        action_hash="a" * 64,
        audience="service:protected-endpoint",
        capability="refund.execute",
        tenant_id="tenant_alpha",
        subject_id="actor_123",
        expires_at=expires_at or (datetime.now(timezone.utc) + timedelta(minutes=5)),
        metadata={"request_id": "req_001"},
    )


def is_closed(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


class _RecordingReplayStore(SqliteReplayStore):
    """Keeps every connection alive, so garbage collection cannot hide one left open."""

    def _create_connection(self) -> sqlite3.Connection:
        connection = super()._create_connection()
        self.__dict__.setdefault("opened", []).append(connection)
        return connection


class _RecordingEscrow(SqliteCapabilityEscrow):
    def _connect(self) -> sqlite3.Connection:
        connection = super()._connect()
        self.__dict__.setdefault("opened", []).append(connection)
        return connection


class StoreConnectionLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def assert_all_closed(self, opened: list[sqlite3.Connection]) -> None:
        self.assertTrue(opened)
        still_open = [index for index, connection in enumerate(opened) if not is_closed(connection)]
        for connection in opened:
            connection.close()
        self.assertEqual([], still_open, f"{len(still_open)} of {len(opened)} connections left open")

    def test_replay_store_closes_the_connection_of_every_operation(self) -> None:
        store = _RecordingReplayStore(self.root / "replay.sqlite3")
        now = datetime.now(timezone.utc)

        store.claim_once(build_claim("rpk_consumed"), now=now)
        store.mark_consumed("rpk_consumed", now=now)
        store.claim_once(build_claim("rpk_released"), now=now)
        store.release_claim("rpk_released", now=now, reason="execution_failed")
        store.claim_once(build_claim("rpk_expiring", expires_at=now + timedelta(seconds=1)), now=now)
        store.purge_expired(now=now + timedelta(seconds=2))
        self.assertIsNone(store.inspect("rpk_missing", now=now))

        self.assert_all_closed(store.opened)

    def test_replay_store_closes_connections_when_an_operation_is_refused(self) -> None:
        store = _RecordingReplayStore(self.root / "replay.sqlite3")
        now = datetime.now(timezone.utc)
        store.claim_once(build_claim("rpk_once"), now=now)

        with self.assertRaises(ReplayValidationError):
            store.claim_once(build_claim("rpk_once"), now=now)
        with self.assertRaises(ReplayValidationError):
            store.mark_consumed("rpk_missing", now=now)
        with self.assertRaises(ReplayValidationError):
            store.release_claim("rpk_missing", now=now, reason="execution_failed")

        self.assert_all_closed(store.opened)

    def test_escrow_closes_the_connection_of_every_operation(self) -> None:
        escrow = _RecordingEscrow(self.root / "escrow.sqlite3")
        now = datetime.now(timezone.utc)
        for escrow_id in ("esc_consumed", "esc_revoked"):
            escrow.issue(
                escrow_id=escrow_id,
                pccb_id="pccb_001",
                capability="refund.execute",
                expires_at=now + timedelta(minutes=5),
            )

        escrow.consume(escrow_id="esc_consumed", pccb_id="pccb_001", capability="refund.execute", now=now)
        escrow.revoke("esc_revoked", reason="operator_revoked")
        self.assertIsNone(escrow.inspect("esc_missing"))
        with self.assertRaises(EscrowValidationError):
            escrow.consume(escrow_id="esc_consumed", pccb_id="pccb_001", capability="refund.execute", now=now)
        with self.assertRaises(EscrowValidationError):
            escrow.consume(escrow_id="esc_missing", pccb_id="pccb_001", capability="refund.execute", now=now)

        self.assert_all_closed(escrow.opened)

    def test_keep_open_holds_one_connection_until_the_store_is_closed(self) -> None:
        store = _RecordingReplayStore(self.root / "replay.sqlite3", keep_open=True)
        now = datetime.now(timezone.utc)
        store.claim_once(build_claim("rpk_held"), now=now)
        store.mark_consumed("rpk_held", now=now)

        self.assertEqual(1, sum(not is_closed(connection) for connection in store.opened))
        # The held connection is what stops each operation's close from deleting the WAL.
        self.assertTrue(Path(str(store.database_path) + "-wal").exists())

        store.close()
        store.close()
        store.claim_once(build_claim("rpk_after_close"), now=now)
        self.assert_all_closed(store.opened)

    @unittest.skipUnless(os.path.isdir("/dev/fd"), "needs /dev/fd to count open descriptors")
    def test_descriptor_count_stays_flat_without_the_garbage_collector(self) -> None:
        for keep_open in (False, True):
            with self.subTest(keep_open=keep_open):
                self.assert_descriptors_stay_flat(keep_open)

    def assert_descriptors_stay_flat(self, keep_open: bool) -> None:
        store = SqliteReplayStore(self.root / f"replay-{keep_open}.sqlite3", keep_open=keep_open)
        self.addCleanup(store.close)
        escrow = SqliteCapabilityEscrow(self.root / f"escrow-{keep_open}.sqlite3")
        now = datetime.now(timezone.utc)

        def one_round(index: int) -> None:
            store.claim_once(build_claim(f"rpk_{index}"), now=now)
            store.mark_consumed(f"rpk_{index}", now=now)
            escrow.issue(
                escrow_id=f"esc_{index}",
                pccb_id="pccb_001",
                capability="refund.execute",
                expires_at=now + timedelta(minutes=5),
            )
            escrow.consume(escrow_id=f"esc_{index}", pccb_id="pccb_001", capability="refund.execute", now=now)

        one_round(0)
        gc.collect()
        gc.disable()
        try:
            before = len(os.listdir("/dev/fd"))
            for index in range(1, 51):
                one_round(index)
            after = len(os.listdir("/dev/fd"))
        finally:
            gc.enable()

        self.assertLessEqual(after - before, 2, f"descriptors grew from {before} to {after} over 50 rounds")


if __name__ == "__main__":
    unittest.main()
