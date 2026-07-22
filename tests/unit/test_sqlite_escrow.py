from __future__ import annotations

import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.escrow import (
    SqliteCapabilityEscrow,
    build_default_capability_escrow,
    build_sqlite_capability_escrow,
    default_escrow_db_path,
)


class SqliteCapabilityEscrowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "escrow.sqlite3"
        self.escrow = SqliteCapabilityEscrow(self.database_path)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_default_escrow_db_path_uses_base_dir(self) -> None:
        base_dir = Path(self.tempdir.name) / "runtime-state"
        self.assertEqual(base_dir / "escrow.sqlite3", default_escrow_db_path(base_dir))

    def test_build_default_capability_escrow_creates_sqlite_store(self) -> None:
        base_dir = Path(self.tempdir.name) / "default-store"
        escrow = build_default_capability_escrow(base_dir)
        self.assertIsInstance(escrow, SqliteCapabilityEscrow)
        assert isinstance(escrow, SqliteCapabilityEscrow)
        self.assertEqual(base_dir / "escrow.sqlite3", escrow.database_path)
        self.assertTrue(escrow.database_path.exists())

    def test_build_sqlite_capability_escrow_accepts_explicit_database_path(self) -> None:
        database_path = Path(self.tempdir.name) / "explicit" / "capability.sqlite3"
        escrow = build_sqlite_capability_escrow(database_path)
        self.assertEqual(database_path, escrow.database_path)
        self.assertTrue(database_path.exists())

    def test_issue_creates_record(self) -> None:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        record = self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=expires_at,
            metadata={"intent_id": "intent_001"},
        )

        self.assertEqual("esc_001", record.escrow_id)
        self.assertEqual("issued", record.state)
        self.assertEqual("intent_001", record.metadata["intent_id"])

    def test_inspect_returns_record_after_issue(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
            metadata={"intent_id": "intent_001"},
        )

        record = self.escrow.inspect("esc_001")

        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("esc_001", record.escrow_id)
        self.assertEqual("pccb_001", record.pccb_id)
        self.assertEqual("refund.execute", record.capability)
        self.assertEqual("intent_001", record.metadata["intent_id"])

    def test_duplicate_issue_fails(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )

        with self.assertRaises(Exception) as context:
            self.escrow.issue(
                escrow_id="esc_001",
                pccb_id="pccb_002",
                capability="invoice_payment.execute",
                expires_at=now + timedelta(minutes=5),
            )

        self.assertEqual("ESCROW_ALREADY_EXISTS", context.exception.refusal_code)

    def test_consume_succeeds_once(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )

        consumed = self.escrow.consume(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            now=now,
        )

        self.assertEqual("consumed", consumed.state)
        self.assertEqual(now.replace(microsecond=0), consumed.consumed_at.replace(microsecond=0))

    def test_second_consume_fails(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )
        self.escrow.consume(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            now=now,
        )

        with self.assertRaises(Exception) as context:
            self.escrow.consume(
                escrow_id="esc_001",
                pccb_id="pccb_001",
                capability="refund.execute",
                now=now,
            )

        self.assertEqual("ESCROW_ALREADY_CONSUMED", context.exception.refusal_code)

    def test_concurrent_consumes_allow_one_winner(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_race",
            pccb_id="pccb_race",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )
        barrier = threading.Barrier(8)
        results: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            escrow = SqliteCapabilityEscrow(self.database_path)
            try:
                barrier.wait(timeout=5)
                escrow.consume(
                    escrow_id="esc_race",
                    pccb_id="pccb_race",
                    capability="refund.execute",
                    now=now,
                )
                outcome = "consumed"
            except Exception as exc:
                outcome = getattr(exc, "refusal_code", exc.__class__.__name__)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(8, len(results))
        self.assertEqual(1, results.count("consumed"))
        self.assertEqual(7, results.count("ESCROW_ALREADY_CONSUMED"))
        record = self.escrow.inspect("esc_race")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("consumed", record.state)

    def test_consume_rejects_pccb_mismatch(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )

        with self.assertRaises(Exception) as context:
            self.escrow.consume(
                escrow_id="esc_001",
                pccb_id="pccb_wrong",
                capability="refund.execute",
                now=now,
            )

        self.assertEqual("ESCROW_PCCB_MISMATCH", context.exception.refusal_code)
        record = self.escrow.inspect("esc_001")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("issued", record.state)

    def test_consume_rejects_capability_mismatch(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )

        with self.assertRaises(Exception) as context:
            self.escrow.consume(
                escrow_id="esc_001",
                pccb_id="pccb_001",
                capability="invoice_payment.execute",
                now=now,
            )

        self.assertEqual("ESCROW_CAPABILITY_MISMATCH", context.exception.refusal_code)
        record = self.escrow.inspect("esc_001")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("issued", record.state)

    def test_revoke_marks_record_and_blocks_consume(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )

        revoked = self.escrow.revoke("esc_001", reason="manual shutdown")

        self.assertEqual("revoked", revoked.state)
        self.assertEqual("manual shutdown", revoked.metadata["revocation_reason"])

        with self.assertRaises(Exception) as context:
            self.escrow.consume(
                escrow_id="esc_001",
                pccb_id="pccb_001",
                capability="refund.execute",
                now=now,
            )

        self.assertEqual("ESCROW_REVOKED", context.exception.refusal_code)

    def test_expired_record_transitions_to_expired_on_consume(self) -> None:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=1)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=expires_at,
        )

        with self.assertRaises(Exception) as context:
            self.escrow.consume(
                escrow_id="esc_001",
                pccb_id="pccb_001",
                capability="refund.execute",
                now=expires_at + timedelta(seconds=1),
            )

        self.assertEqual("ESCROW_EXPIRED", context.exception.refusal_code)
        record = self.escrow.inspect("esc_001")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("expired", record.state)

    def test_record_persists_across_reinstantiation(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
            metadata={"intent_id": "intent_001"},
        )

        reloaded = SqliteCapabilityEscrow(self.database_path)
        record = reloaded.inspect("esc_001")

        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("pccb_001", record.pccb_id)
        self.assertEqual("intent_001", record.metadata["intent_id"])

    def test_consumed_record_persists_across_reinstantiation(self) -> None:
        now = datetime.now(timezone.utc)
        self.escrow.issue(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            expires_at=now + timedelta(minutes=5),
        )
        self.escrow.consume(
            escrow_id="esc_001",
            pccb_id="pccb_001",
            capability="refund.execute",
            now=now,
        )

        reloaded = SqliteCapabilityEscrow(self.database_path)

        with self.assertRaises(Exception) as context:
            reloaded.consume(
                escrow_id="esc_001",
                pccb_id="pccb_001",
                capability="refund.execute",
                now=now,
            )

        self.assertEqual("ESCROW_ALREADY_CONSUMED", context.exception.refusal_code)


if __name__ == "__main__":
    unittest.main()
