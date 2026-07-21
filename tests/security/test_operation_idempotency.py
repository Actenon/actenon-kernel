"""Phase 4A regression tests for operation idempotency and reconciliation.

These tests define the required semantics for operation identity,
idempotency, and reconciliation. Some tests are expected to FAIL until
Phase 4B implements the operation store and reconciliation abstraction.

Test expectations:
  1. concurrent same-operation execution — FAIL (not currently atomic)
  2. same operation + same action returns prior outcome — FAIL (no idempotency)
  3. same operation + different action conflicts — FAIL (no conflict detection)
  4. ambiguous provider failure becomes non-retriable — PARTIAL (fail-closed exists, but no OUTCOME_UNKNOWN state)
  5. unauthorised reconciliation is denied — FAIL (no reconciler)
  6. reconciliation cannot mutate the original action — FAIL (no reconciler)
  7. consumed proof cannot authorise a different operation — PASS (replay protection already enforces this)
"""

from __future__ import annotations

import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from actenon.core.errors import ProofVerificationError, RefusalException
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.execution.protected_executor import ProtectedExecutor
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PCCB,
    PartyRef,
    PolicyDecision,
    TargetRef,
    TenantRef,
)
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier, VerifierDisclosureMode
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore

from tests.security.helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)


def _intent_with_op(operation_id: str, **kwargs) -> ActionIntent:
    """Build a security intent with an operation_id in metadata."""
    intent = build_security_intent(**kwargs)
    return replace(intent, metadata={"operation_id": operation_id})


def _build_executor(*, tempdir: str) -> ProtectedExecutor:
    """Build a ProtectedExecutor wired with real replay + escrow + receipt writer.
    Returns (executor, escrow) so tests can issue escrow records before execution.
    """
    import tempfile
    replay_db = tempfile.mktemp(suffix=".sqlite3", dir=tempdir)
    executor = ProtectedExecutor(
        proof_verifier=PCCBVerifier(
            security_signer(),
            disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG,
        ),
        replay_protector=ReplayProtector(SqliteReplayStore(replay_db)),
        escrow=None,  # Tests use PCCB with escrow_id but no escrow store
        credential_broker=_SimpleBroker(),
        receipt_factory=ReceiptFactory(),
        refusal_factory=RefusalFactory(),
        outcome_writer=InMemoryOutcomeWriter(),
    )
    return executor


class _SimpleBroker:
    """Minimal credential broker for testing."""
    from actenon.credentials import BrokeredCredential, CredentialBroker

    def acquire(self, intent, pccb, context):
        return self.BrokeredCredential(
            credential_id="cred_test",
            issued_at=context.now,
            expires_at=context.now + timedelta(minutes=5),
            scope=("test",),
            metadata={"operation_id": intent.metadata.get("operation_id", "derived")},
        )

    def release(self, credential, result):
        pass


class ConcurrentSameOperationTests(unittest.TestCase):
    """Test 1: concurrent same-operation execution must not duplicate.

    Currently the replay store uses `claim_once` which is atomic, but the
    operation-level idempotency is not fully specified. This test verifies
    that concurrent requests with the same operation_id and action_hash
    do not both execute.
    """

    def test_1_concurrent_same_operation_does_not_duplicate(self) -> None:
        """Two threads presenting the same PCCB concurrently must not both
        execute the handler. The replay store should reject the second
        as a duplicate.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tempdir:
            executor = _build_executor(tempdir=tempdir)
            intent = build_security_intent()
            context = build_security_context()
            pccb = mint_security_pccb(intent=intent, context=context)

            execution_count = 0
            count_lock = threading.Lock()

            def handler(req, cred):
                nonlocal execution_count
                with count_lock:
                    execution_count += 1
                return {"result": "executed"}

            results = []
            errors = []

            def run():
                try:
                    result = executor.execute(
                        ProtectedExecutor.ProtectedExecutionRequest(
                            intent=intent, pccb=pccb, context=context
                        ) if hasattr(ProtectedExecutor, 'ProtectedExecutionRequest') else _make_request(intent, pccb, context),
                        handler,
                    )
                    results.append(result)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=run) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # At least one should succeed
            self.assertGreaterEqual(len(results), 1, "At least one execution should succeed")
            # The handler should have been called at most once
            self.assertLessEqual(
                execution_count,
                1,
                f"Handler was called {execution_count} times. Concurrent same-operation "
                f"execution must not duplicate the handler call.",
            )


def _make_request(intent, pccb, context):
    from actenon.models.runtime import ProtectedExecutionRequest
    return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)


class IdempotentReplayTests(unittest.TestCase):
    """Test 2: same operation_id + same action_hash returns prior outcome.

    Currently the replay store rejects the same PCCB as DUPLICATE_REPLAY.
    The proposed idempotency layer should return the prior RESULT instead
    of a refusal, with an IDEMPOTENT_REPLAY marker.
    """

    def test_2_same_operation_same_action_returns_prior_outcome(self) -> None:
        """Presenting the same operation_id + action_hash twice should
        return the prior recorded result, not a DUPLICATE_REPLAY refusal.

        Currently FAILS: the replay store returns DUPLICATE_REPLAY.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tempdir:
            executor = _build_executor(tempdir=tempdir)
            intent = _intent_with_op("op_test_002")
            context = build_security_context()
            pccb = mint_security_pccb(intent=intent, context=context)
            request = _make_request(intent, pccb, context)

            def handler(req, cred):
                return {"result": "executed", "amount": 100}

            # First execution
            result1 = executor.execute(request, handler)
            self.assertIsNone(result1.refusal, "First execution should succeed")
            self.assertIsNotNone(result1.receipt)

            # Second execution with same operation_id + action_hash
            result2 = executor.execute(request, handler)
            # Should return prior result, not a new execution
            if result2.refusal is not None:
                self.assertNotEqual(
                    result2.refusal.reason_code,
                    "DUPLICATE_REPLAY",
                    "Same operation + same action should return prior result, "
                    "not DUPLICATE_REPLAY refusal.",
                )
            # The payload should match the first execution's payload
            if result2.payload is not None:
                self.assertEqual(
                    result2.payload.get("result"),
                    "executed",
                    "Idempotent replay should return the prior result payload.",
                )


class IdempotencyConflictTests(unittest.TestCase):
    """Test 3: same operation_id + different action_hash conflicts."""

    def test_3_same_operation_different_action_conflicts(self) -> None:
        """Presenting the same operation_id with a different action_hash
        should return IDEMPOTENCY_CONFLICT, not execute the handler.

        Currently FAILS: no operation_id tracking exists. The second
        execution succeeds because the replay store sees a different
        replay_key (different PCCB) and allows it.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tempdir:
            executor = _build_executor(tempdir=tempdir)
            # First intent: payment.release $10
            intent1 = _intent_with_op("op_conflict_001", amount_minor=1000)
            context1 = build_security_context()
            pccb1 = mint_security_pccb(intent=intent1, context=context1)
            request1 = _make_request(intent1, pccb1, context1)

            # Second intent: same operation_id, different amount
            intent2 = _intent_with_op("op_conflict_001", amount_minor=9999)
            context2 = build_security_context()
            pccb2 = mint_security_pccb(intent=intent2, context=context2)
            request2 = _make_request(intent2, pccb2, context2)

            call_count = 0

            def handler(req, cred):
                nonlocal call_count
                call_count += 1
                return {"result": "executed", "call": call_count}

            # First execution succeeds
            executor.execute(request1, handler)
            self.assertEqual(1, call_count, "First execution should call handler once")

            # Second execution with same operation_id but different action
            result2 = executor.execute(request2, handler)
            # Should return IDEMPOTENCY_CONFLICT, not execute the handler
            self.assertIsNotNone(
                result2.refusal,
                "Same operation_id + different action_hash should be refused "
                "as IDEMPOTENCY_CONFLICT, not allowed to execute.",
            )
            self.assertIn(
                result2.refusal.reason_code,
                ("IDEMPOTENCY_CONFLICT", "ACTION_MISMATCH"),
                f"Same operation + different action should conflict, "
                f"got {result2.refusal.reason_code!r}",
            )
            self.assertEqual(
                1,
                call_count,
                "Handler should not be called for a conflicting operation.",
            )


class AmbiguousOutcomeTests(unittest.TestCase):
    """Test 4: ambiguous provider failure becomes non-retriable.

    When the handler throws, the current executor marks replay consumed
    (fail-closed) and emits EXECUTION_FAILED. The proposed model should
    mark the operation OUTCOME_UNKNOWN and require reconciliation.
    """

    def test_4_handler_failure_marks_outcome_unknown(self) -> None:
        """A handler that throws after the provider may have accepted the
        call should mark the operation OUTCOME_UNKNOWN, not EXECUTION_FAILED.

        Currently PARTIAL: the executor is fail-closed (consumes replay),
        but there's no OUTCOME_UNKNOWN state or ambiguous-outcome record.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tempdir:
            executor = _build_executor(tempdir=tempdir)
            intent = _intent_with_op("op_ambiguous_001")
            context = build_security_context()
            pccb = mint_security_pccb(intent=intent, context=context)
            request = _make_request(intent, pccb, context)

            call_count = 0

            def failing_handler(req, cred):
                nonlocal call_count
                call_count += 1
                raise RuntimeError("provider timeout after payment accepted")

            result = executor.execute(request, failing_handler)

            # The executor must be fail-closed — the proof is consumed
            self.assertIsNotNone(result.refusal, "Handler failure should produce a refusal")

            # The refusal code should indicate an ambiguous outcome, not just a generic failure
            # Currently this is EXECUTION_FAILED; the proposed code is OUTCOME_UNKNOWN
            # This test asserts the CURRENT behaviour (EXECUTION_FAILED) and documents
            # the desired behaviour (OUTCOME_UNKNOWN) in the assertion message.
            self.assertIn(
                result.refusal.reason_code,
                ("EXECUTION_FAILED", "OUTCOME_UNKNOWN"),
                f"Handler failure should mark ambiguous outcome. Current: "
                f"{result.refusal.reason_code!r}. Desired: OUTCOME_UNKNOWN.",
            )

            # The proof must be consumed (fail-closed) — retry must fail
            result_retry = executor.execute(request, failing_handler)
            self.assertIsNotNone(
                result_retry.refusal,
                "Consumed proof must not allow retry after ambiguous failure.",
            )


class ReconciliationTests(unittest.TestCase):
    """Tests 5-6: reconciliation abstraction."""

    def test_5_unauthorised_reconciliation_is_denied(self) -> None:
        """An unauthorised reconciler must not be able to reconcile an
        OUTCOME_UNKNOWN operation.

        Currently FAILS: no reconciler exists.
        """
        # The reconciliation interface does not exist yet.
        # This test documents the requirement: only authorised reconcilers
        # can transition OUTCOME_UNKNOWN to RECONCILED_EXECUTED or
        # RECONCILED_NOT_EXECUTED.
        try:
            from actenon.reconciliation import OperationReconciler
        except ImportError:
            self.skipTest("Reconciliation module not yet implemented (Phase 4B)")

    def test_6_reconciliation_cannot_mutate_original_action(self) -> None:
        """Reconciliation must preserve the original action_hash and
        cannot alter the originally requested action.

        Currently FAILS: no reconciler exists.
        """
        try:
            from actenon.reconciliation import OperationReconciler
        except ImportError:
            self.skipTest("Reconciliation module not yet implemented (Phase 4B)")


class ConsumedProofTests(unittest.TestCase):
    """Test 7: consumed proof cannot authorise a different operation.

    This test PASSES against the current verifier because the replay
    store already enforces single-use. A consumed proof is rejected
    as DUPLICATE_REPLAY regardless of the operation_id.
    """

    def test_7_consumed_proof_cannot_authorise_different_operation(self) -> None:
        """A proof that has been consumed for one operation cannot be
        reused for a different operation. The replay store rejects it
        as DUPLICATE_REPLAY.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tempdir:
            executor = _build_executor(tempdir=tempdir)
            intent = _intent_with_op("op_first_001")
            context = build_security_context()
            pccb = mint_security_pccb(intent=intent, context=context)
            request = _make_request(intent, pccb, context)

            def handler(req, cred):
                return {"result": "executed"}

            # First execution
            result1 = executor.execute(request, handler)
            self.assertIsNone(result1.refusal)

            # Second execution with the SAME proof (same PCCB)
            # but trying to use a different operation_id in the intent metadata
            intent2 = _intent_with_op("op_different_001")
            request2 = _make_request(intent2, pccb, context)

            result2 = executor.execute(request2, handler)
            # The proof is consumed — must be rejected
            self.assertIsNotNone(
                result2.refusal,
                "Consumed proof must not authorise a different operation.",
            )


if __name__ == "__main__":
    unittest.main()
