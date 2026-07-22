from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main
from actenon.demo.local_proof import run_local_proof_demo
from actenon.demo.portable_local_proof import run_portable_local_proof_demo


class EvidenceQueryCliIntegrationTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_evidence_query_by_intent_id_reports_verified_execution(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)

            code, stdout, stderr = self._run_cli(
                [
                    "evidence",
                    "query",
                    "--intent-id",
                    "intent_allow",
                    "--artifacts-dir",
                    str(artifact_root),
                ]
            )

            self.assertEqual(0, code, stderr)
            self.assertEqual("", stderr)
            self.assertIn("Verdict: VERIFIED_EXECUTION", stdout)
            self.assertIn("Chain length: 0", stdout)
            self.assertIn("Hash verification: passed", stdout)
            self.assertIn("Intent: intent_allow", stdout)

    def test_evidence_query_supports_json_output(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)

            code, stdout, stderr = self._run_cli(
                [
                    "evidence",
                    "query",
                    "--intent-id",
                    "intent_allow",
                    "--artifacts-dir",
                    str(artifact_root),
                    "--json",
                ]
            )

            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual("VERIFIED_EXECUTION", payload["verdict"])
            self.assertEqual("intent_id", payload["query"]["kind"])
            self.assertEqual("intent_allow", payload["query"]["value"])
            self.assertEqual(0, payload["chain_length"])
            self.assertEqual("passed", payload["hash_verification"])

    def test_evidence_query_reports_proof_not_found_for_missing_receipt(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)

            code, stdout, stderr = self._run_cli(
                [
                    "evidence",
                    "query",
                    "--receipt-id",
                    "rcpt_missing_001",
                    "--artifacts-dir",
                    str(artifact_root),
                    "--json",
                ]
            )

            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertFalse(payload["ok"])
            self.assertEqual("PROOF_NOT_FOUND", payload["verdict"])
            self.assertEqual("not_confirmed", payload["hash_verification"])

    def test_evidence_query_reports_chain_broken_when_outcome_chain_is_missing(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            run_portable_local_proof_demo(artifact_root)

            code, stdout, stderr = self._run_cli(
                [
                    "evidence",
                    "query",
                    "--pccb-id",
                    "pccb_portable_hello_world_001",
                    "--artifacts-dir",
                    str(artifact_root),
                    "--json",
                ]
            )

            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertFalse(payload["ok"])
            self.assertEqual("CHAIN_BROKEN", payload["verdict"])
            self.assertEqual("pccb_portable_hello_world_001", payload["pccb_id"])
            self.assertEqual("not_confirmed", payload["hash_verification"])


if __name__ == "__main__":
    unittest.main()
