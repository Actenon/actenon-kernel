from __future__ import annotations

import logging
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.execution import ProtectedExecutor
from actenon.execution.protected_executor import REPLAY_PROTECTION_DISABLED_WARNING
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
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier
from actenon.replay import ReplayProtector, SqliteReplayStore


class SecureDefaultReplayIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.signer = HmacSha256Signer(secret=b"secure-default-replay-test", key_id="secure-default-replay-key")
        self.request = self._build_request()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _build_request(self) -> ProtectedExecutionRequest:
        intent = ActionIntent(
            intent_id="intent_secure_default_replay_001",
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=10),
            tenant=TenantRef(tenant_id="tenant_healthcare"),
            requester=PartyRef(type="agent", id="medication-agent"),
            action=ActionSpec(
                name="medication.administer",
                capability="medication.administer",
                parameters={"patient_id": "patient-synthetic-001", "dose_mg": 5},
            ),
            target=TargetRef(resource_type="patient", resource_id="patient-synthetic-001"),
            justification="Synthetic local replay-protection regression.",
        )
        context = DynamicContextInput(
            request_id="req_secure_default_replay_001",
            audience=AudienceRef(type="service", id="medication-protected-endpoint"),
            scope_capabilities=("medication.administer",),
            now=self.now,
            parameter_constraints=dict(intent.action.parameters),
        )
        decision = PolicyDecision(
            outcome="allow",
            summary="Synthetic local action is allowed for the replay regression.",
            rule_evaluations=(),
            reason_codes=("SYNTHETIC_LOCAL_ALLOW",),
        )
        pccb = PCCBMinter(
            signer=self.signer,
            issuer=PartyRef(type="service", id="secure-default-replay-test-issuer"),
            pccb_id_factory=lambda: "pccb_secure_default_replay_001",
            nonce_factory=lambda: "nonce-secure-default-replay-001",
        ).mint(intent, decision, context)
        return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

    @staticmethod
    def _handler(side_effects: list[str]):
        def execute(
            request: ProtectedExecutionRequest,
            _credential: BrokeredCredential,
        ) -> dict[str, str]:
            side_effects.append(request.intent.intent_id)
            return {"external_reference": f"synthetic:{request.intent.intent_id}"}

        return execute

    def _broker(self) -> InMemoryCredentialBroker:
        sequence = {"value": 0}

        def next_id() -> str:
            sequence["value"] += 1
            return f"cred_secure_default_{sequence['value']:02d}"

        return InMemoryCredentialBroker(credential_id_factory=next_id)

    def test_default_executor_refuses_second_execution_without_side_effect(self) -> None:
        replay_db = self.root / "default-replay.sqlite3"
        side_effects: list[str] = []

        with patch.dict(os.environ, {"ACTENON_REPLAY_DB": str(replay_db)}, clear=False):
            executor = ProtectedExecutor(
                proof_verifier=PCCBVerifier(self.signer),
                credential_broker=self._broker(),
            )

        first = executor.execute(self.request, self._handler(side_effects))
        second = executor.execute(self.request, self._handler(side_effects))

        self.assertIsNone(first.refusal)
        self.assertIsNotNone(first.receipt)
        self.assertIsNotNone(second.refusal)
        self.assertIsNotNone(second.receipt)
        assert second.refusal is not None
        self.assertEqual("DUPLICATE_REPLAY", second.refusal.refusal_code)
        self.assertIsNone(second.payload)
        self.assertEqual(["intent_secure_default_replay_001"], side_effects)

    def test_explicit_disabled_mode_restores_repeat_execution_and_warns_once(self) -> None:
        side_effects: list[str] = []

        with self.assertLogs(level=logging.WARNING) as captured:
            executor = ProtectedExecutor(
                proof_verifier=PCCBVerifier(self.signer),
                credential_broker=self._broker(),
                replay_protection="disabled",
            )

        first = executor.execute(self.request, self._handler(side_effects))
        second = executor.execute(self.request, self._handler(side_effects))

        self.assertEqual(1, len(captured.records))
        self.assertEqual(REPLAY_PROTECTION_DISABLED_WARNING, captured.records[0].getMessage())
        self.assertIsNone(first.refusal)
        self.assertIsNone(second.refusal)
        self.assertEqual(
            ["intent_secure_default_replay_001", "intent_secure_default_replay_001"],
            side_effects,
        )

    def test_explicit_replay_protector_cannot_be_combined_with_disabled_mode(self) -> None:
        replay = ReplayProtector(SqliteReplayStore(self.root / "conflict.sqlite3"))

        with self.assertRaisesRegex(
            ValueError,
            "replay_protector cannot be supplied when replay_protection is 'disabled'",
        ):
            ProtectedExecutor(
                proof_verifier=PCCBVerifier(self.signer),
                credential_broker=self._broker(),
                replay_protector=replay,
                replay_protection="disabled",
            )

    def test_two_executors_sharing_durable_store_reject_second_edge(self) -> None:
        shared_path = self.root / "shared-replay.sqlite3"
        first_executor = ProtectedExecutor(
            proof_verifier=PCCBVerifier(self.signer),
            credential_broker=self._broker(),
            replay_protector=ReplayProtector(SqliteReplayStore(shared_path)),
        )
        second_executor = ProtectedExecutor(
            proof_verifier=PCCBVerifier(self.signer),
            credential_broker=self._broker(),
            replay_protector=ReplayProtector(SqliteReplayStore(shared_path)),
        )
        side_effects: list[str] = []

        first = first_executor.execute(self.request, self._handler(side_effects))
        second = second_executor.execute(self.request, self._handler(side_effects))

        self.assertIsNone(first.refusal)
        self.assertIsNotNone(second.refusal)
        assert second.refusal is not None
        self.assertEqual("DUPLICATE_REPLAY", second.refusal.refusal_code)
        self.assertEqual(["intent_secure_default_replay_001"], side_effects)


if __name__ == "__main__":
    unittest.main()
