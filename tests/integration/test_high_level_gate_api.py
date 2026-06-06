from __future__ import annotations

import os
import unittest
import warnings
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import actenon
from actenon import ActenonGate
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.receipts import InMemoryOutcomeWriter


class HighLevelGateAPIIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.intent = ActionIntent(
            intent_id="intent_gate_api_001",
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=5),
            tenant=TenantRef(tenant_id="tenant_gate_api"),
            requester=PartyRef(type="agent", id="gate-api-agent"),
            action=ActionSpec(
                name="database.delete_table",
                capability="database.delete",
                parameters={"table": "synthetic_customers"},
            ),
            target=TargetRef(
                resource_type="database_table",
                resource_id="synthetic_customers",
            ),
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _gate(self, *, writer: InMemoryOutcomeWriter | None = None) -> ActenonGate:
        replay_db = self.root / "gate-replay.sqlite3"
        with (
            patch.dict(os.environ, {"ACTENON_REPLAY_DB": str(replay_db)}, clear=False),
            warnings.catch_warnings(),
        ):
            warnings.simplefilter("ignore", RuntimeWarning)
            return ActenonGate.local_dev(
                audience="service:database-protected-endpoint",
                clock=lambda: self.now,
                outcome_writer=writer,
            )

    def test_top_level_package_exports_gate(self) -> None:
        self.assertIs(ActenonGate, actenon.ActenonGate)
        self.assertIn("ActenonGate", actenon.__all__)

    def test_valid_executes_mismatch_refuses_and_replay_refuses(self) -> None:
        writer = InMemoryOutcomeWriter()
        gate = self._gate(writer=writer)
        proof = gate.mint_proof(self.intent)
        side_effects: list[str] = []

        valid = gate.protect(
            self.intent,
            proof,
            lambda: side_effects.append("executed"),
        )
        mismatch = gate.protect(
            replace(self.intent, intent_id="intent_gate_api_other"),
            proof,
            lambda: side_effects.append("mismatch"),
        )
        replay = gate.protect(
            self.intent,
            proof,
            lambda: side_effects.append("replay"),
        )

        self.assertTrue(valid.ok)
        self.assertEqual("executed", valid.outcome)
        self.assertEqual("INTENT_MISMATCH", mismatch.reason_code)
        self.assertEqual("DUPLICATE_REPLAY", replay.reason_code)
        self.assertEqual(["executed"], side_effects)
        self.assertEqual(3, len(writer.receipts))
        self.assertEqual(2, len(writer.refusals))
        self.assertEqual("INTENT_MISMATCH", mismatch.to_dict()["reason_code"])

    def test_missing_proof_refuses_and_emits_both_artifacts(self) -> None:
        writer = InMemoryOutcomeWriter()
        gate = self._gate(writer=writer)

        outcome = gate.protect(self.intent, None, lambda: self.fail("side effect ran"))

        self.assertFalse(outcome.ok)
        self.assertEqual("PCCB_REQUIRED", outcome.reason_code)
        self.assertEqual(1, len(writer.receipts))
        self.assertEqual(1, len(writer.refusals))

    def test_protect_action_decorator_returns_gate_outcome(self) -> None:
        gate = self._gate()
        proof = gate.mint_proof(self.intent)
        side_effects: list[str] = []

        @gate.protect_action(self.intent, proof)
        def delete_table() -> dict[str, str]:
            side_effects.append("executed")
            return {"status": "deleted"}

        outcome = delete_table()

        self.assertTrue(outcome.ok)
        self.assertEqual({"status": "deleted"}, outcome.payload)
        self.assertEqual(["executed"], side_effects)


if __name__ == "__main__":
    unittest.main()
