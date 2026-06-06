from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main
from examples.mcp_server_protected_tool.proof_gate import (
    build_demo_tool_call,
    invoke_protected_tool,
    supported_tool_names,
)


class MCPHeroPathIntegrationTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_supported_consequential_tools_execute_after_proof_gate(self) -> None:
        with TemporaryDirectory() as tempdir:
            example_root = Path(tempdir)
            for tool_name in supported_tool_names():
                with self.subTest(tool_name=tool_name):
                    call = build_demo_tool_call(tool_name, scenario="allow")
                    outcome = invoke_protected_tool(
                        tool_name,
                        intent_payload=call.intent.to_dict(),
                        pccb_payload=call.pccb.to_dict(),
                        preflight_evidence=call.preflight_evidence,
                        request_id=f"test_{tool_name.replace('.', '_')}_allow",
                        example_root=example_root,
                    )
                    payload = outcome.to_dict()

                    self.assertTrue(payload["ok"])
                    self.assertEqual("allow", payload["preflight"]["outcome"])
                    self.assertEqual("executed", payload["receipt"]["outcome"])
                    self.assertEqual("receipt", payload["var"]["artifact_kind"])
                    self.assertEqual(payload["receipt"]["receipt_id"], payload["var"]["artifact_id"])
                    self.assertFalse(payload["receipt"]["details"]["credential_broker"]["credential_material_exposed"])
                    self.assertNotIn("raw_secret", json.dumps(payload))

    def test_preflight_refusal_blocks_before_brokered_execution(self) -> None:
        with TemporaryDirectory() as tempdir:
            example_root = Path(tempdir)
            call = build_demo_tool_call("database.migrate", scenario="refuse")

            outcome = invoke_protected_tool(
                "database.migrate",
                intent_payload=call.intent.to_dict(),
                pccb_payload=call.pccb.to_dict(),
                preflight_evidence=call.preflight_evidence,
                request_id="test_database_migrate_refuse",
                example_root=example_root,
            )
            payload = outcome.to_dict()

            self.assertFalse(payload["ok"])
            self.assertEqual("approval_required", payload["preflight"]["outcome"])
            self.assertEqual(
                "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
                payload["refusal"]["reason_code"],
            )
            self.assertEqual(
                {
                    "PREFLIGHT_CHANGE_TICKET_REQUIRED",
                    "PREFLIGHT_BACKUP_EVIDENCE_REQUIRED",
                    "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
                },
                {
                    requirement["reason_code"]
                    for requirement in payload["preflight"]["unmet_requirements"]
                },
            )
            self.assertEqual("refused", payload["receipt"]["outcome"])
            self.assertEqual("receipt", payload["var"]["artifact_kind"])
            self.assertEqual(payload["receipt"]["receipt_id"], payload["var"]["artifact_id"])
            self.assertNotIn("brokered_credential", payload["receipt"].get("details", {}))

    def test_missing_proof_emits_refusal_and_refused_receipt(self) -> None:
        with TemporaryDirectory() as tempdir:
            example_root = Path(tempdir)
            call = build_demo_tool_call("payment.release", scenario="allow")

            outcome = invoke_protected_tool(
                "payment.release",
                intent_payload=call.intent.to_dict(),
                pccb_payload=None,
                preflight_evidence=call.preflight_evidence,
                request_id="test_payment_release_missing_proof",
                example_root=example_root,
            )
            payload = outcome.to_dict()

            self.assertFalse(payload["ok"])
            self.assertEqual("PCCB_REQUIRED", payload["refusal"]["reason_code"])
            self.assertEqual("refused", payload["receipt"]["outcome"])
            self.assertEqual("receipt", payload["var"]["artifact_kind"])

    def test_mcp_wrap_cli_prints_local_wrapper_pattern(self) -> None:
        code, stdout, stderr = self._run_cli(["mcp", "wrap", "--tool", "data.export", "--json"])

        self.assertEqual(0, code, stderr)
        payload = json.loads(stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual("data.export", payload["tool_name"])
        self.assertEqual("data.export", payload["capability"])
        self.assertIn("Actenon proof gate", payload["flow"])
        self.assertIn("Credential Broker", " ".join(payload["proof_gate_steps"]))
        self.assertFalse(payload["hosted_dependency"])
        self.assertFalse(payload["cloud_dependency"])


if __name__ == "__main__":
    unittest.main()
