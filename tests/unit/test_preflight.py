from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.preflight import PreflightDecision, PreflightEngine


class PreflightTests(unittest.TestCase):
    def _intent(
        self,
        *,
        capability: str,
        environment: str,
        parameters: dict[str, object] | None = None,
    ) -> ActionIntent:
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        resource_type = "database" if capability.startswith("database") else "resource"
        return ActionIntent(
            intent_id=f"intent_{capability.replace('.', '_')}_{environment}",
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
            tenant=TenantRef(tenant_id="tenant_alpha"),
            requester=PartyRef(type="agent", id="agent_planner"),
            action=ActionSpec(
                name=capability,
                capability=capability,
                parameters={"environment": environment, **dict(parameters or {})},
            ),
            target=TargetRef(resource_type=resource_type, resource_id=f"{environment}-target", selectors={"environment": environment}),
        )

    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_production_database_delete_requires_approval_when_evidence_is_complete(self) -> None:
        decision = PreflightEngine().check(
            self._intent(capability="database.delete", environment="production"),
            evidence_context={"change_ticket": "CHG-001", "backup_verified": True},
        )

        self.assertEqual("approval_required", decision.outcome)
        self.assertEqual("PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED", decision.reason_code)
        self.assertEqual(("infrastructure_owner", "security_admin"), decision.required_approvals)

    def test_missing_backup_is_reported_with_higher_severity_approval(self) -> None:
        decision = PreflightEngine().check(
            self._intent(capability="volume.delete", environment="production"),
            evidence_context={"change_ticket": "CHG-001"},
        )

        self.assertEqual("approval_required", decision.outcome)
        self.assertEqual(
            "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
            decision.reason_code,
        )
        self.assertEqual(("backup_verified",), decision.required_evidence)
        self.assertIn(
            "PREFLIGHT_BACKUP_EVIDENCE_REQUIRED",
            {requirement.reason_code for requirement in decision.unmet_requirements},
        )

    def test_sandbox_action_can_allow(self) -> None:
        decision = PreflightEngine().check(self._intent(capability="infrastructure.delete", environment="sandbox"))

        self.assertEqual("allow", decision.outcome)
        self.assertEqual("PREFLIGHT_SANDBOX_LOW_RISK_ALLOWED", decision.reason_code)
        self.assertEqual("low", decision.risk_level)

    def test_broad_data_export_requires_approval(self) -> None:
        decision = PreflightEngine().check(
            self._intent(
                capability="data.export",
                environment="production",
                parameters={"row_count": 25_000, "destination": "s3://external-vendor/export"},
            ),
            evidence_context={"change_ticket": "CHG-002"},
        )

        self.assertEqual("approval_required", decision.outcome)
        self.assertEqual("PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED", decision.reason_code)
        self.assertEqual(("data_owner", "privacy_reviewer"), decision.required_approvals)

    def test_preflight_decision_json_round_trips_stably(self) -> None:
        decision = PreflightEngine().check(self._intent(capability="infrastructure.delete", environment="sandbox"))
        payload = decision.to_dict()
        serialized = json.dumps(payload, sort_keys=True)

        self.assertEqual(payload, PreflightDecision.from_dict(json.loads(serialized)).to_dict())
        self.assertEqual(decision.decision_id, PreflightEngine().check(self._intent(capability="infrastructure.delete", environment="sandbox")).decision_id)

    def test_preflight_check_cli_outputs_json(self) -> None:
        with TemporaryDirectory() as tempdir:
            intent_path = Path(tempdir) / "intent.json"
            intent_path.write_text(
                json.dumps(self._intent(capability="database.delete", environment="production").to_dict()),
                encoding="utf-8",
            )

            code, stdout, stderr = self._run_cli(
                [
                    "preflight",
                    "check",
                    "--intent",
                    str(intent_path),
                    "--evidence-json",
                    '{"change_ticket":"CHG-001","backup_verified":true}',
                    "--json",
                ]
            )

        self.assertEqual(0, code, stderr)
        payload = json.loads(stdout)
        self.assertEqual("preflight_decision", payload["contract"]["name"])
        self.assertEqual("approval_required", payload["outcome"])
        self.assertEqual("PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED", payload["reason_code"])

    def test_preflight_explain_cli_accepts_saved_decision(self) -> None:
        with TemporaryDirectory() as tempdir:
            decision_path = Path(tempdir) / "decision.json"
            decision = PreflightEngine().check(self._intent(capability="infrastructure.delete", environment="sandbox"))
            decision_path.write_text(json.dumps(decision.to_dict()), encoding="utf-8")

            code, stdout, stderr = self._run_cli(["preflight", "explain", "--decision", str(decision_path)])

        self.assertEqual(0, code, stderr)
        self.assertIn("Actenon Preflight decision.", stdout)
        self.assertIn("PREFLIGHT_SANDBOX_LOW_RISK_ALLOWED", stdout)

    def test_preflight_simulate_cli_outputs_infra_delete(self) -> None:
        code, stdout, stderr = self._run_cli(["preflight", "simulate", "--wedge", "infra_delete", "--json"])

        self.assertEqual(0, code, stderr)
        payload = json.loads(stdout)
        self.assertEqual("approval_required", payload["outcome"])
        self.assertEqual("PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED", payload["reason_code"])


if __name__ == "__main__":
    unittest.main()
