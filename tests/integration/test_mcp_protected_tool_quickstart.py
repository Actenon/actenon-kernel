from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from examples.mcp_protected_tool.demo import main as mcp_quickstart_main
from examples.mcp_protected_tool.demo import run_demo


class MCPProtectedToolQuickstartTests(unittest.TestCase):
    def test_missing_proof_refuses_before_handler_and_emits_artifacts(self) -> None:
        with TemporaryDirectory() as tempdir:
            outcome = run_demo(scenario="missing-proof", artifact_root=Path(tempdir))
            payload = outcome.to_dict()

            self.assertFalse(payload["ok"])
            self.assertFalse(payload["handler_called"])
            self.assertFalse(payload["side_effect_executed"])
            self.assertEqual("PCCB_REQUIRED", payload["refusal"]["refusal_code"])
            self.assertEqual("refused", payload["receipt"]["outcome"])
            self.assertTrue(Path(payload["refusal_path"]).exists())
            self.assertTrue(Path(payload["receipt_path"]).exists())

    def test_valid_proof_allows_handler_and_emits_receipt(self) -> None:
        with TemporaryDirectory() as tempdir:
            outcome = run_demo(scenario="allow", artifact_root=Path(tempdir))
            payload = outcome.to_dict()
            serialized = json.dumps(payload, sort_keys=True)

            self.assertTrue(payload["ok"])
            self.assertTrue(payload["handler_called"])
            self.assertTrue(payload["side_effect_executed"])
            self.assertEqual("executed", payload["receipt"]["outcome"])
            self.assertEqual("filesystem.delete", payload["receipt"]["action"]["name"])
            self.assertFalse(payload["protected_response"]["credential_material_exposed"])
            self.assertTrue(Path(payload["receipt_path"]).exists())
            self.assertNotIn("actenon-mcp-protected-tool-demo-secret", serialized)

    def test_cli_entrypoint_runs_with_temp_artifact_root(self) -> None:
        with TemporaryDirectory() as tempdir:
            code = mcp_quickstart_main(["--scenario", "allow", "--artifact-root", tempdir, "--json"])

            self.assertEqual(0, code)
            self.assertTrue((Path(tempdir) / "outcomes" / "receipts" / "rcpt_mcp_quickstart_allow.json").exists())


if __name__ == "__main__":
    unittest.main()

