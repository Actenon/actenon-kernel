"""Adversarial tests for the stateful execution edge (ProtectedExecutor).

These cover what the stateless verifier cannot: idempotent retries, the
single-use race across threads and processes, replay-store outages, and
credential brokering order.
"""

from __future__ import annotations

import multiprocessing
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from actenon.credentials import BrokeredCredential
from actenon.execution.protected_executor import ProtectedExecutor
from actenon.idempotency import IdempotencyStore
from actenon.models.runtime import ProtectedExecutionRequest
from actenon.proof import PCCBVerifier, VerifierDisclosureMode
from actenon.receipts import InMemoryOutcomeWriter
from actenon.replay import ReplayProtector, SqliteReplayStore
from tests.security.helpers import (
    build_security_context,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)


class _RecordingBroker:
    def __init__(self) -> None:
        self.acquired: list[str] = []
        self.released: list[dict] = []

    def acquire(self, intent, pccb, context):
        self.acquired.append(pccb.pccb_id)
        return BrokeredCredential(
            credential_id=f"cred_{pccb.pccb_id}",
            issued_at=context.now,
            expires_at=context.now + timedelta(minutes=5),
            scope=(intent.action.capability,),
        )

    def release(self, credential, result):
        self.released.append(dict(result))


def _executor(replay_db: Path, *, broker=None, idempotency_store=None, mode=VerifierDisclosureMode.TRUSTED_DETAILED):
    writer = InMemoryOutcomeWriter()
    executor = ProtectedExecutor(
        proof_verifier=PCCBVerifier(security_signer(), disclosure_mode=mode),
        credential_broker=broker or _RecordingBroker(),
        replay_protector=ReplayProtector(SqliteReplayStore(replay_db)),
        outcome_writer=writer,
        idempotency_store=idempotency_store,
    )
    return executor, writer


def _op_intent(operation_id: str, **kwargs):
    return replace(build_security_intent(**kwargs), metadata={"operation_id": operation_id})


class IdempotencyRequiresVerifiedProofTests(unittest.TestCase):
    """An idempotent retry must still present a proof that verifies.

    Before the fix the idempotency lookup ran before proof verification, so
    anyone who knew an operation_id and its (public) action_hash could get
    the prior handler result and a fresh "executed" receipt with a forged
    proof.
    """

    def _prime(self, tempdir: str):
        store = IdempotencyStore()
        executor, writer = _executor(Path(tempdir) / "replay.sqlite3", idempotency_store=store)
        intent = _op_intent("op_secret_001")
        context = build_security_context()
        pccb = mint_security_pccb(intent=intent, context=context)
        first = executor.execute(
            ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context),
            lambda request, credential: {"transfer_id": "tr_confidential_123"},
        )
        self.assertIsNone(first.refusal)
        return executor, writer, intent, context, pccb

    def test_forged_signature_does_not_return_prior_result(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            executor, writer, intent, context, pccb = self._prime(tempdir)
            forged = replace(pccb, pccb_id="pccb_forged", signature=replace(pccb.signature, value="A" * 43))
            calls = []
            result = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=forged, context=context),
                lambda request, credential: calls.append(1) or {},
            )
            self.assertIsNotNone(result.refusal)
            self.assertEqual("PROOF_INVALID", result.refusal.reason_code)
            self.assertIsNone(result.payload)
            self.assertEqual([], calls)
            self.assertNotIn("pccb_forged", [r.correlation.pccb_id for r in writer.receipts if r.outcome == "executed"])

    def test_forged_proof_cannot_probe_idempotency_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            executor, _writer, intent, context, pccb = self._prime(tempdir)
            forged = replace(
                pccb,
                action_hash=replace(pccb.action_hash, value="f" * 64),
                signature=replace(pccb.signature, value="A" * 43),
            )
            result = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=forged, context=context),
                lambda request, credential: {},
            )
            self.assertEqual("PROOF_INVALID", result.refusal.reason_code)
            self.assertNotIn("expected_action_hash", result.refusal.details)

    def test_expired_proof_does_not_return_prior_result(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            executor, _writer, intent, context, pccb = self._prime(tempdir)
            late = replace(context, now=pccb.expires_at + timedelta(minutes=1))
            result = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=pccb, context=late),
                lambda request, credential: {},
            )
            self.assertEqual("PROOF_EXPIRED", result.refusal.reason_code)
            self.assertIsNone(result.payload)

    def test_wrong_audience_does_not_return_prior_result(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            executor, _writer, intent, context, pccb = self._prime(tempdir)
            elsewhere = build_security_context(audience_id="some-other-endpoint")
            result = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=pccb, context=elsewhere),
                lambda request, credential: {},
            )
            self.assertEqual("AUDIENCE_MISMATCH", result.refusal.reason_code)
            self.assertIsNone(result.payload)

    def test_replaying_the_same_proof_is_duplicate_replay_not_an_executed_receipt(self) -> None:
        # E2E B6: an idempotency key is not permission to reuse a proof.
        with tempfile.TemporaryDirectory() as tempdir:
            executor, writer, intent, context, pccb = self._prime(tempdir)
            executed_before = sum(1 for r in writer.receipts if r.outcome == "executed")
            calls = []
            result = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context),
                lambda request, credential: calls.append(1) or {},
            )
            self.assertEqual("DUPLICATE_REPLAY", result.refusal.reason_code)
            self.assertIsNone(result.payload)
            self.assertEqual([], calls)
            self.assertEqual(executed_before, sum(1 for r in writer.receipts if r.outcome == "executed"))

    def test_new_proof_for_the_same_operation_returns_prior_result_without_re_executing(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            executor, _writer, intent, context, _pccb = self._prime(tempdir)
            fresh = mint_security_pccb(intent=intent, context=context, pccb_id="pccb_retry_002", nonce="nonce-retry-002")
            calls = []
            result = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=fresh, context=context),
                lambda request, credential: calls.append(1) or {},
            )
            self.assertIsNone(result.refusal)
            self.assertEqual({"transfer_id": "tr_confidential_123"}, result.payload)
            self.assertEqual([], calls)
            # ...and that new proof is now spent too.
            again = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=fresh, context=context),
                lambda request, credential: calls.append(1) or {},
            )
            self.assertEqual("DUPLICATE_REPLAY", again.refusal.reason_code)


def _race_worker(replay_db: str, counter_path: str, barrier, results) -> None:
    executor, _ = _executor(Path(replay_db))
    intent = build_security_intent()
    context = build_security_context()
    pccb = mint_security_pccb(intent=intent, context=context)

    def handler(request, credential):
        with open(counter_path, "a", encoding="utf-8") as handle:
            handle.write("x")
        return {"ok": True}

    barrier.wait()
    result = executor.execute(ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context), handler)
    results.put(None if result.refusal is None else result.refusal.reason_code)


class SingleUseRaceTests(unittest.TestCase):
    def test_32_threads_presenting_one_proof_execute_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            executor, _ = _executor(Path(tempdir) / "replay.sqlite3")
            intent = build_security_intent()
            context = build_security_context()
            pccb = mint_security_pccb(intent=intent, context=context)
            side_effects = []
            lock = threading.Lock()
            barrier = threading.Barrier(32)
            codes: list[str | None] = []

            def handler(request, credential):
                with lock:
                    side_effects.append(1)
                return {"ok": True}

            def worker() -> None:
                barrier.wait()
                result = executor.execute(ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context), handler)
                with lock:
                    codes.append(None if result.refusal is None else result.refusal.reason_code)

            threads = [threading.Thread(target=worker) for _ in range(32)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(1, len(side_effects))
            self.assertEqual(1, codes.count(None))
            self.assertEqual(31, codes.count("DUPLICATE_REPLAY"))

    def test_separate_processes_sharing_a_store_execute_exactly_once(self) -> None:
        ctx = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as tempdir:
            replay_db = str(Path(tempdir) / "replay.sqlite3")
            counter = Path(tempdir) / "side_effects.txt"
            counter.write_text("", encoding="utf-8")
            SqliteReplayStore(Path(replay_db))  # create the schema once up front
            barrier = ctx.Barrier(4)
            results = ctx.Queue()
            processes = [
                ctx.Process(target=_race_worker, args=(replay_db, str(counter), barrier, results)) for _ in range(4)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=120)
                self.assertEqual(0, process.exitcode)
            codes = [results.get(timeout=5) for _ in processes]
            self.assertEqual(1, len(counter.read_text(encoding="utf-8")))
            self.assertEqual(1, codes.count(None))
            self.assertEqual(3, codes.count("DUPLICATE_REPLAY"))


class _BrokenReplayStore:
    def __init__(self, *, fail_on: str) -> None:
        self.fail_on = fail_on
        self.inner_claimed = False

    def claim_once(self, claim, *, now):
        if self.fail_on == "claim":
            raise ConnectionError("replay store unreachable")
        self.inner_claimed = True
        return SimpleNamespace(replay_key=claim.replay_key, status="claimed")

    def mark_consumed(self, replay_key, *, now):
        raise ConnectionError("replay store unreachable")

    def release_claim(self, replay_key, *, now, reason):
        raise ConnectionError("replay store unreachable")


class ReplayStoreOutageTests(unittest.TestCase):
    def _run(self, store) -> tuple[object, _RecordingBroker, list]:
        broker = _RecordingBroker()
        executor = ProtectedExecutor(
            proof_verifier=PCCBVerifier(security_signer()),
            credential_broker=broker,
            replay_protector=ReplayProtector(store),
        )
        calls: list[int] = []
        intent = build_security_intent()
        context = build_security_context()
        pccb = mint_security_pccb(intent=intent, context=context)
        result = executor.execute(
            ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context),
            lambda request, credential: calls.append(1) or {},
        )
        return result, broker, calls

    def test_claim_outage_fails_closed_before_credentials(self) -> None:
        result, broker, calls = self._run(_BrokenReplayStore(fail_on="claim"))
        self.assertEqual("REPLAY_STORE_UNAVAILABLE", result.refusal.reason_code)
        self.assertEqual([], calls)
        self.assertEqual([], broker.acquired)

    def test_consume_outage_fails_closed_and_releases_credential(self) -> None:
        result, broker, calls = self._run(_BrokenReplayStore(fail_on="consume"))
        self.assertEqual("REPLAY_STORE_UNAVAILABLE", result.refusal.reason_code)
        self.assertEqual([], calls)
        self.assertEqual(1, len(broker.released))
        self.assertEqual("refused", broker.released[0]["outcome"])


class CredentialBrokerOrderingTests(unittest.TestCase):
    def test_no_credential_is_acquired_for_a_refused_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            broker = _RecordingBroker()
            executor, _ = _executor(Path(tempdir) / "replay.sqlite3", broker=broker)
            intent = build_security_intent()
            context = build_security_context()
            pccb = mint_security_pccb(intent=intent, context=context)
            widened = build_security_intent(amount_minor=999_999)
            result = executor.execute(
                ProtectedExecutionRequest(intent=widened, pccb=pccb, context=context),
                lambda request, credential: {},
            )
            self.assertIsNotNone(result.refusal)
            self.assertEqual([], broker.acquired)

    def test_handler_receives_only_the_brokered_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            broker = _RecordingBroker()
            executor, _ = _executor(Path(tempdir) / "replay.sqlite3", broker=broker)
            intent = build_security_intent()
            context = build_security_context()
            pccb = mint_security_pccb(intent=intent, context=context)
            seen = []
            result = executor.execute(
                ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context),
                lambda request, credential: seen.append(credential.credential_id) or {},
            )
            self.assertIsNone(result.refusal)
            self.assertEqual([f"cred_{pccb.pccb_id}"], seen)
            self.assertFalse(result.receipt.details["credential_broker"]["credential_material_exposed"])


if __name__ == "__main__":
    unittest.main()
