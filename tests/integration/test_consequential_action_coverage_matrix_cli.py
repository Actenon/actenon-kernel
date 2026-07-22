from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main


class ConsequentialActionCoverageMatrixCliTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_coverage_run_cli_writes_evidence_and_prints_domain_counts(self) -> None:
        with TemporaryDirectory() as tempdir:
            evidence_path = Path(tempdir) / "coverage.json"
            code, stdout, stderr = self._run_cli(["coverage", "run", "--output", str(evidence_path)])

            self.assertEqual(0, code, stderr)
            self.assertEqual("", stderr)
            self.assertTrue(evidence_path.exists())
            self.assertIn("ACTENON CONSEQUENTIAL ACTION COVERAGE MATRIX", stdout)
            self.assertIn("Total scenarios: 540", stdout)
            self.assertIn("Domains covered: 9", stdout)
            self.assertIn("- DevOps:", stdout)
            self.assertIn("- Fintech:", stdout)
            self.assertIn("- IAM / Access Control:", stdout)
            self.assertIn("- Code Agent Operations:", stdout)
            self.assertIn("Result: PASS", stdout)
            self.assertIn("No valid proof, no execution.", stdout)

            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual("PASS", evidence["result"])
            self.assertGreaterEqual(evidence["total_scenarios"], 500)
            self.assertEqual(9, len(evidence["domains"]))
            self.assertTrue(all(count > 0 for count in evidence["per_domain_counts"].values()))
            self.assertEqual(
                evidence["check_counts"]["missing_proof_refused"],
                {"passed": 54, "total": 54},
            )
            self.assertEqual(
                evidence["check_counts"]["replay_attempt_refused"],
                {"passed": 54, "total": 54},
            )
            self.assertIn("artifact_samples", evidence)

    def test_coverage_run_cli_supports_json_output(self) -> None:
        with TemporaryDirectory() as tempdir:
            evidence_path = Path(tempdir) / "coverage.json"
            code, stdout, stderr = self._run_cli(["coverage", "run", "--output", str(evidence_path), "--json"])

            self.assertEqual(0, code, stderr)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertEqual("consequential_action_coverage_matrix", payload["contract"]["name"])
            self.assertEqual("PASS", payload["result"])
            self.assertEqual(540, payload["total_scenarios"])
            self.assertTrue(evidence_path.exists())


if __name__ == "__main__":
    unittest.main()
