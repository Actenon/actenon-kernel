from __future__ import annotations

import threading
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.core import EscrowValidationError, ProofVerificationError, ReplayValidationError
from actenon.escrow import InMemoryCapabilityEscrow, SqliteCapabilityEscrow
from actenon.models import ProtectedExecutionRequest, TargetRef
from actenon.proof import PCCBVerifier
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.replay.service import build_action_consumption_claim

from .helpers import NOW, build_security_context, build_security_intent, mint_security_pccb, security_signer


def _verify_refuses(testcase: unittest.TestCase, *, intent=None, pccb=None, context=None, refusal_code: str) -> None:
    verifier = PCCBVerifier(security_signer())
    with testcase.assertRaises(ProofVerificationError) as captured:
        verifier.verify(
            intent or build_security_intent(),
            pccb or mint_security_pccb(),
            context or build_security_context(),
        )
    testcase.assertEqual(refusal_code, captured.exception.refusal_code)


class BindingModelAttackTests(unittest.TestCase):
    def test_changed_amount_action_parameter_is_rejected(self) -> None:
        _verify_refuses(self, intent=build_security_intent(amount_minor=2000), pccb=mint_security_pccb(), refusal_code="ACTION_MISMATCH")

    def test_changed_tenant_is_rejected(self) -> None:
        _verify_refuses(self, intent=build_security_intent(tenant_id="tenant_other"), pccb=mint_security_pccb(), refusal_code="TENANT_MISMATCH")

    def test_changed_requester_is_rejected(self) -> None:
        _verify_refuses(self, intent=build_security_intent(requester_id="agent_other"), pccb=mint_security_pccb(), refusal_code="SUBJECT_MISMATCH")

    def test_changed_target_is_rejected(self) -> None:
        intent = build_security_intent()
        attacked_intent = replace(intent, target=TargetRef(resource_type="payment", resource_id="payment_other"))

        _verify_refuses(self, intent=attacked_intent, pccb=mint_security_pccb(intent=intent), refusal_code="TARGET_MISMATCH")

    def test_changed_audience_is_rejected(self) -> None:
        _verify_refuses(
            self,
            pccb=mint_security_pccb(),
            context=build_security_context(audience_id="other-endpoint"),
            refusal_code="AUDIENCE_MISMATCH",
        )

    def test_changed_capability_and_wrong_scope_are_rejected(self) -> None:
        _verify_refuses(
            self,
            intent=build_security_intent(capability="payment.refund"),
            pccb=mint_security_pccb(capabilities=("payment.release",)),
            refusal_code="SCOPE_CAPABILITY_MISMATCH",
        )

    def test_changed_intent_issue_or_expiry_times_are_rejected_by_action_hash(self) -> None:
        original = build_security_intent()
        pccb = mint_security_pccb(intent=original)
        changed_issued_at = replace(original, issued_at=original.issued_at - timedelta(minutes=1))
        changed_expires_at = replace(original, expires_at=original.expires_at + timedelta(minutes=1))

        _verify_refuses(self, intent=changed_issued_at, pccb=pccb, refusal_code="ACTION_HASH_MISMATCH")
        _verify_refuses(self, intent=changed_expires_at, pccb=pccb, refusal_code="ACTION_HASH_MISMATCH")

    def test_unsigned_pccb_validity_mutation_is_rejected(self) -> None:
        pccb = mint_security_pccb()
        attacked = replace(pccb, expires_at=pccb.expires_at + timedelta(minutes=10))

        _verify_refuses(self, pccb=attacked, refusal_code="SIGNATURE_INVALID")

    def test_expired_proof_is_rejected(self) -> None:
        context = build_security_context(now=NOW + timedelta(minutes=6))

        _verify_refuses(self, pccb=mint_security_pccb(), context=context, refusal_code="PROOF_EXPIRED")

    def test_not_before_in_future_is_rejected_before_signature_evaluation(self) -> None:
        pccb = mint_security_pccb()
        attacked = replace(pccb, not_before=NOW + timedelta(minutes=1))

        _verify_refuses(self, pccb=attacked, refusal_code="PROOF_NOT_YET_VALID")


class ReplayAndEscrowAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.intent = build_security_intent()
        self.context = build_security_context()
        self.pccb = mint_security_pccb(intent=self.intent, context=self.context)
        self.request = ProtectedExecutionRequest(intent=self.intent, pccb=self.pccb, context=self.context)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_proof_replay_is_rejected(self) -> None:
        replay = ReplayProtector(SqliteReplayStore(self.root / "replay.sqlite3"))
        first = replay.claim_request(self.request)

        with self.assertRaises(ReplayValidationError) as captured:
            replay.claim_request(self.request)

        self.assertEqual("claimed", first.status)
        self.assertEqual("DUPLICATE_REPLAY", captured.exception.refusal_code)

    def test_escrow_mismatch_and_second_consume_are_rejected(self) -> None:
        escrow = SqliteCapabilityEscrow(self.root / "escrow.sqlite3")
        escrow.issue(
            escrow_id="esc_security_001",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            expires_at=self.pccb.expires_at,
        )

        with self.assertRaises(EscrowValidationError) as wrong_pccb:
            escrow.consume(
                escrow_id="esc_security_001",
                pccb_id="pccb_other",
                capability=self.intent.action.capability,
                now=self.context.now,
            )
        first = escrow.consume(
            escrow_id="esc_security_001",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            now=self.context.now,
        )
        with self.assertRaises(EscrowValidationError) as second_consume:
            escrow.consume(
                escrow_id="esc_security_001",
                pccb_id=self.pccb.pccb_id,
                capability=self.intent.action.capability,
                now=self.context.now,
            )

        self.assertEqual("ESCROW_PCCB_MISMATCH", wrong_pccb.exception.refusal_code)
        self.assertEqual("consumed", first.state)
        self.assertEqual("ESCROW_ALREADY_CONSUMED", second_consume.exception.refusal_code)

    def test_revoked_and_expired_escrow_cannot_be_consumed(self) -> None:
        escrow = SqliteCapabilityEscrow(self.root / "escrow.sqlite3")
        escrow.issue(
            escrow_id="esc_revoked",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            expires_at=self.pccb.expires_at,
        )
        escrow.revoke("esc_revoked", reason="adversarial test")
        escrow.issue(
            escrow_id="esc_expired",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            expires_at=self.context.now - timedelta(seconds=1),
        )

        with self.assertRaises(EscrowValidationError) as revoked:
            escrow.consume(
                escrow_id="esc_revoked",
                pccb_id=self.pccb.pccb_id,
                capability=self.intent.action.capability,
                now=self.context.now,
            )
        with self.assertRaises(EscrowValidationError) as expired:
            escrow.consume(
                escrow_id="esc_expired",
                pccb_id=self.pccb.pccb_id,
                capability=self.intent.action.capability,
                now=self.context.now,
            )

        self.assertEqual("ESCROW_REVOKED", revoked.exception.refusal_code)
        self.assertEqual("ESCROW_EXPIRED", expired.exception.refusal_code)

    def test_simultaneous_escrow_consumes_allow_only_one_winner(self) -> None:
        database_path = self.root / "escrow-race.sqlite3"
        escrow = SqliteCapabilityEscrow(database_path)
        escrow.issue(
            escrow_id="esc_race",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            expires_at=self.pccb.expires_at,
        )
        barrier = threading.Barrier(8)
        results: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            store = SqliteCapabilityEscrow(database_path)
            try:
                barrier.wait(timeout=5)
                store.consume(
                    escrow_id="esc_race",
                    pccb_id=self.pccb.pccb_id,
                    capability=self.intent.action.capability,
                    now=self.context.now,
                )
                outcome = "consumed"
            except EscrowValidationError as exc:
                outcome = exc.refusal_code
            except Exception as exc:  # pragma: no cover - concurrency diagnostic guard
                outcome = type(exc).__name__
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(8, len(results))
        self.assertEqual(1, results.count("consumed"))
        self.assertEqual(7, results.count("ESCROW_ALREADY_CONSUMED"))

    def test_simultaneous_in_memory_escrow_consumes_allow_only_one_winner_in_process(self) -> None:
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_memory_race",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            expires_at=self.pccb.expires_at,
        )
        barrier = threading.Barrier(8)
        results: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                escrow.consume(
                    escrow_id="esc_memory_race",
                    pccb_id=self.pccb.pccb_id,
                    capability=self.intent.action.capability,
                    now=self.context.now,
                )
                outcome = "consumed"
            except EscrowValidationError as exc:
                outcome = exc.refusal_code
            except Exception as exc:  # pragma: no cover - concurrency diagnostic guard
                outcome = type(exc).__name__
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(8, len(results))
        self.assertEqual(1, results.count("consumed"))
        self.assertEqual(7, results.count("ESCROW_ALREADY_CONSUMED"))

    def test_simultaneous_replay_claims_allow_only_one_winner(self) -> None:
        database_path = self.root / "replay-race.sqlite3"
        claim = build_action_consumption_claim(self.intent, self.pccb, self.context)
        SqliteReplayStore(database_path)
        barrier = threading.Barrier(8)
        results: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            store = SqliteReplayStore(database_path)
            try:
                barrier.wait(timeout=5)
                store.claim_once(claim, now=self.context.now)
                outcome = "claimed"
            except ReplayValidationError as exc:
                outcome = exc.refusal_code
            except Exception as exc:  # pragma: no cover - concurrency diagnostic guard
                outcome = type(exc).__name__
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(8, len(results))
        self.assertEqual(1, results.count("claimed"))
        self.assertEqual(7, results.count("DUPLICATE_REPLAY"))

    def test_replay_and_escrow_state_persist_across_restart(self) -> None:
        replay_path = self.root / "replay.sqlite3"
        escrow_path = self.root / "escrow.sqlite3"
        replay = ReplayProtector(SqliteReplayStore(replay_path))
        replay_state = replay.claim_request(self.request)
        replay.mark_consumed(replay_state.replay_key, now=self.context.now)
        escrow = SqliteCapabilityEscrow(escrow_path)
        escrow.issue(
            escrow_id="esc_persist",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            expires_at=self.pccb.expires_at,
        )

        consumed = escrow.consume(
            escrow_id="esc_persist",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            now=self.context.now,
        )
        reloaded_replay = SqliteReplayStore(replay_path)
        reloaded_escrow = SqliteCapabilityEscrow(escrow_path)

        self.assertEqual("consumed", consumed.state)
        self.assertEqual("consumed", reloaded_replay.inspect(replay_state.replay_key, now=self.context.now).status)
        self.assertEqual("consumed", reloaded_escrow.inspect("esc_persist").state)

        with self.assertRaises(EscrowValidationError) as second_consume:
            reloaded_escrow.consume(
                escrow_id="esc_persist",
                pccb_id=self.pccb.pccb_id,
                capability=self.intent.action.capability,
                now=self.context.now,
            )
        with self.assertRaises(ReplayValidationError) as duplicate_replay:
            ReplayProtector(reloaded_replay).claim_request(self.request)

        self.assertEqual("ESCROW_ALREADY_CONSUMED", second_consume.exception.refusal_code)
        self.assertEqual("DUPLICATE_REPLAY", duplicate_replay.exception.refusal_code)


if __name__ == "__main__":
    unittest.main()
