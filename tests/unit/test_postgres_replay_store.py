from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from actenon.core import ReplayValidationError
from actenon.replay import ActionConsumptionClaim, PostgresReplayStore


def build_claim(*, replay_key: str = "rpk_pg_test", expires_at=None) -> ActionConsumptionClaim:
    now = datetime.now(timezone.utc)
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
        expires_at=expires_at or (now + timedelta(minutes=5)),
        metadata={"request_id": "req_001"},
    )


class _PercentStyleCursor:
    def __init__(self, cursor: sqlite3.Cursor, sql_log: list[str]) -> None:
        self._cursor = cursor
        self._sql_log = sql_log

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> "_PercentStyleCursor":
        self._sql_log.append(sql)
        self._cursor.execute(sql.replace("%s", "?"), parameters)
        return self

    def fetchone(self):
        return self._cursor.fetchone()


class _PercentStyleSqliteConnection:
    def __init__(self, database_path: Path, sql_log: list[str]) -> None:
        self._connection = sqlite3.connect(str(database_path))
        self._connection.row_factory = sqlite3.Row
        self._sql_log = sql_log
        self.autocommit = False

    def __enter__(self) -> "_PercentStyleSqliteConnection":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._connection.close()

    def cursor(self) -> _PercentStyleCursor:
        return _PercentStyleCursor(self._connection.cursor(), self._sql_log)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()


class PostgresReplayStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "postgres-replay-test.sqlite3"
        self.sql_log: list[str] = []
        self.store = PostgresReplayStore(connection_factory=self._connection_factory)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _connection_factory(self) -> _PercentStyleSqliteConnection:
        return _PercentStyleSqliteConnection(self.database_path, self.sql_log)

    def test_schema_initialization_creates_action_consumption_table(self) -> None:
        with sqlite3.connect(str(self.database_path)) as connection:
            table_count = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'action_consumption'"
            ).fetchone()[0]

        self.assertEqual(1, table_count)

    def test_requires_dsn_or_connection_factory(self) -> None:
        with self.assertRaises(ValueError):
            PostgresReplayStore()

    def test_claim_success_and_consume(self) -> None:
        now = datetime.now(timezone.utc)
        claim = build_claim()

        claimed = self.store.claim_once(claim, now=now)
        consumed = self.store.mark_consumed(claim.replay_key, now=now + timedelta(seconds=1))

        self.assertEqual("claimed", claimed.status)
        self.assertEqual("consumed", consumed.status)
        self.assertIsNotNone(consumed.consumed_at)

    def test_duplicate_replay_refusal(self) -> None:
        now = datetime.now(timezone.utc)
        claim = build_claim()

        self.store.claim_once(claim, now=now)

        with self.assertRaises(ReplayValidationError) as context:
            self.store.claim_once(claim, now=now)

        self.assertEqual("DUPLICATE_REPLAY", context.exception.refusal_code)
        self.assertEqual("claimed", context.exception.details["existing_status"])

    def test_expiry_allows_reclaim_of_stale_unconsumed_claim(self) -> None:
        now = datetime.now(timezone.utc)
        claim = build_claim(replay_key="rpk_pg_expiring", expires_at=now + timedelta(seconds=1))
        renewed_claim = build_claim(replay_key="rpk_pg_expiring", expires_at=now + timedelta(minutes=5))

        self.store.claim_once(claim, now=now)
        purged = self.store.purge_expired(now=now + timedelta(seconds=2))
        reclaimed = self.store.claim_once(renewed_claim, now=now + timedelta(seconds=2))

        self.assertEqual(1, purged)
        self.assertEqual("claimed", reclaimed.status)

    def test_adapter_uses_postgresql_parameter_style_for_claims(self) -> None:
        self.store.claim_once(build_claim(replay_key="rpk_pg_parameter_style"), now=datetime.now(timezone.utc))

        self.assertTrue(any("%s" in sql for sql in self.sql_log))

    def test_integrity_error_detection_handles_driver_subclasses(self) -> None:
        class DriverIntegrityError(Exception):
            pass

        class UniqueViolation(DriverIntegrityError):
            pass

        self.assertTrue(self.store._is_integrity_error(UniqueViolation()))


if __name__ == "__main__":
    unittest.main()
