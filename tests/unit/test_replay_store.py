from __future__ import annotations

import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.core import ReplayValidationError
from actenon.replay import ActionConsumptionClaim, SqliteReplayStore


def build_claim(*, replay_key: str = "rpk_test", expires_at=None) -> ActionConsumptionClaim:
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


class SqliteReplayStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "replay.sqlite3"
        self.store = SqliteReplayStore(self.database_path)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_first_consumption_succeeds(self) -> None:
        now = datetime.now(timezone.utc)
        claim = build_claim()

        claimed = self.store.claim_once(claim, now=now)
        consumed = self.store.mark_consumed(claim.replay_key, now=now)

        self.assertEqual("claimed", claimed.status)
        self.assertEqual("consumed", consumed.status)
        self.assertIsNotNone(consumed.consumed_at)

    def test_duplicate_replay_fails(self) -> None:
        now = datetime.now(timezone.utc)
        claim = build_claim()

        self.store.claim_once(claim, now=now)

        with self.assertRaises(ReplayValidationError) as context:
            self.store.claim_once(claim, now=now)

        self.assertEqual("DUPLICATE_REPLAY", context.exception.refusal_code)

    def test_expiry_allows_reclaim_of_stale_unconsumed_claim(self) -> None:
        now = datetime.now(timezone.utc)
        expired_at = now + timedelta(seconds=1)
        claim = build_claim(replay_key="rpk_expiring", expires_at=expired_at)
        renewed_claim = build_claim(replay_key="rpk_expiring", expires_at=now + timedelta(minutes=5))

        self.store.claim_once(claim, now=now)
        purged = self.store.purge_expired(now=now + timedelta(seconds=2))
        reclaimed = self.store.claim_once(renewed_claim, now=now + timedelta(seconds=2))

        self.assertEqual(1, purged)
        self.assertEqual("claimed", reclaimed.status)

    def test_concurrent_claims_allow_one_winner(self) -> None:
        claim = build_claim(replay_key="rpk_race")
        now = datetime.now(timezone.utc)
        barrier = threading.Barrier(8)
        results: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            store = SqliteReplayStore(self.database_path)
            try:
                barrier.wait(timeout=5)
                store.claim_once(claim, now=now)
                outcome = "claimed"
            except ReplayValidationError:
                outcome = "duplicate"
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(8, len(results))
        self.assertEqual(1, results.count("claimed"))
        self.assertEqual(7, results.count("duplicate"))


if __name__ == "__main__":
    unittest.main()
