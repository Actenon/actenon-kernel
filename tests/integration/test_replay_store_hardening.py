from __future__ import annotations

import logging
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.execution import ProtectedExecutor
from actenon.execution.protected_executor import REPLAY_STORE_FAIL_OPEN_WARNING
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PartyRef,
    PolicyDecision,
    ProtectedExecutionRequest,
    TargetRef,
    TenantRef,
)
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier, VerifierDisclosureMode
from actenon.replay import ReplayProtector, SqliteReplayStore


class _UnavailableReplayProtector:
    def claim_request(self, request: ProtectedExecutionRequest):
        raise OSError("synthetic replay store outage")

    def mark_consumed(self, replay_key: str, *, now: datetime):
        raise OSError("synthetic replay store outage")

    def release_claim(self, replay_key: str, *, now: datetime, reason: str):
        raise OSError("synthetic replay store outage")


class _ConsumeUnavailableReplayProtector(_UnavailableReplayProtector):
    def claim_request(self, request: ProtectedExecutionRequest):
        return SimpleNamespace(replay_key="rpk_synthetic_consume_outage")


class ReplayStoreHardeningIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.signer = HmacSha256Signer(
            secret=b"replay-store-hardening-test",
            key_id="replay-store-hardening-key",
        )
        self.request = self._build_request()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _build_request(self) -> ProtectedExecutionRequest:
        intent = ActionIntent(
            intent_id="intent_replay_store_hardening_001",
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=10),
            tenant=TenantRef(tenant_id="tenant_replay_test"),
            requester=PartyRef(type="agent", id="refund-agent"),
            action=ActionSpec(
                name="payment.refund",
                capability="payment.refund",
                parameters={"charge_id": "ch_synthetic_001", "amount": 2500},
            ),
            target=TargetRef(resource_type="charge", resource_id="ch_synthetic_001"),
            justification="Synthetic local replay-store regression.",
        )
        context = DynamicContextInput(
            request_id="req_replay_store_hardening_001",
            audience=AudienceRef(type="service", id="refund-protected-endpoint"),
            scope_capabilities=("payment.refund",),
            now=self.now,
            parameter_constraints=dict(intent.action.parameters),
        )
        decision = PolicyDecision(
            outcome="allow",
            summary="Synthetic local action is allowed.",
            rule_evaluations=(),
            reason_codes=("SYNTHETIC_LOCAL_ALLOW",),
        )
        pccb = PCCBMinter(
            signer=self.signer,
            issuer=PartyRef(type="service", id="replay-store-hardening-issuer"),
            pccb_id_factory=lambda: "pccb_replay_store_hardening_001",
            nonce_factory=lambda: "nonce-replay-store-hardening-001",
        ).mint(intent, decision, context)
        return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

    def _executor(self, replay_protector, **kwargs) -> ProtectedExecutor:
        return ProtectedExecutor(
            proof_verifier=PCCBVerifier(self.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
            credential_broker=InMemoryCredentialBroker(),
            replay_protector=replay_protector,
            **kwargs,
        )

    @staticmethod
    def _handler(side_effects: list[str], lock: threading.Lock | None = None):
        def execute(
            request: ProtectedExecutionRequest,
            _credential: BrokeredCredential,
        ) -> dict[str, str]:
            if lock is None:
                side_effects.append(request.intent.intent_id)
            else:
                with lock:
                    side_effects.append(request.intent.intent_id)
            return {"external_reference": f"synthetic:{request.intent.intent_id}"}

        return execute

    def test_parallel_durable_submissions_execute_exactly_once(self) -> None:
        database_path = self.root / "parallel-replay.sqlite3"
        executor_count = 12
        executors = [
            self._executor(ReplayProtector(SqliteReplayStore(database_path)))
            for _ in range(executor_count)
        ]
        barrier = threading.Barrier(executor_count)
        side_effects: list[str] = []
        outcomes = []
        result_lock = threading.Lock()

        def worker(executor: ProtectedExecutor) -> None:
            barrier.wait(timeout=10)
            result = executor.execute(
                self.request,
                self._handler(side_effects, result_lock),
            )
            with result_lock:
                outcomes.append(result)

        threads = [threading.Thread(target=worker, args=(executor,)) for executor in executors]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        executed = [result for result in outcomes if result.refusal is None]
        refused = [result for result in outcomes if result.refusal is not None]
        self.assertEqual(executor_count, len(outcomes))
        self.assertEqual(1, len(executed))
        self.assertEqual(executor_count - 1, len(refused))
        self.assertTrue(
            all(
                result.refusal is not None
                and result.refusal.reason_code == "DUPLICATE_REPLAY"
                for result in refused
            )
        )
        self.assertEqual(["intent_replay_store_hardening_001"], side_effects)

    def test_store_unavailable_refuses_before_side_effect_by_default(self) -> None:
        side_effects: list[str] = []
        result = self._executor(_UnavailableReplayProtector()).execute(
            self.request,
            self._handler(side_effects),
        )

        self.assertIsNotNone(result.refusal)
        assert result.refusal is not None
        self.assertEqual("REPLAY_STORE_UNAVAILABLE", result.refusal.reason_code)
        self.assertEqual([], side_effects)

    def test_consume_outage_refuses_before_side_effect(self) -> None:
        side_effects: list[str] = []
        result = self._executor(_ConsumeUnavailableReplayProtector()).execute(
            self.request,
            self._handler(side_effects),
        )

        self.assertIsNotNone(result.refusal)
        assert result.refusal is not None
        self.assertEqual("REPLAY_STORE_UNAVAILABLE", result.refusal.reason_code)
        self.assertEqual([], side_effects)

    def test_explicit_fail_open_executes_and_warns_once(self) -> None:
        side_effects: list[str] = []

        with self.assertLogs(level=logging.WARNING) as captured:
            executor = self._executor(
                _UnavailableReplayProtector(),
                replay_store_failure="fail_open",
            )

        result = executor.execute(self.request, self._handler(side_effects))

        self.assertEqual(1, len(captured.records))
        self.assertEqual(REPLAY_STORE_FAIL_OPEN_WARNING, captured.records[0].getMessage())
        self.assertIsNone(result.refusal)
        self.assertEqual(["intent_replay_store_hardening_001"], side_effects)


if __name__ == "__main__":
    unittest.main()
