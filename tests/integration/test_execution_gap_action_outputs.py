from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.scanner import scan_replay_harness


class ExecutionGapActionOutputIntegrationTests(unittest.TestCase):
    def test_emit_scan_outputs_script_exports_expected_outputs(self) -> None:
        with TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            report_path = root / "report.json"
            output_path = root / "github_output.txt"
            summary_path = root / "github_summary.md"
            report_path.write_text(json.dumps(scan_replay_harness().to_dict()), encoding="utf-8")

            script_path = Path(__file__).resolve().parents[2] / ".github" / "actions" / "execution-gap-scan" / "emit_scan_outputs.py"
            env = {
                **os.environ,
                "GITHUB_OUTPUT": str(output_path),
                "GITHUB_STEP_SUMMARY": str(summary_path),
            }
            subprocess.run([sys.executable, str(script_path), str(report_path)], check=True, env=env)

            output_text = output_path.read_text(encoding="utf-8")
            summary_text = summary_path.read_text(encoding="utf-8")

            self.assertIn("status=NO_OBVIOUS_EXECUTION_GAP_FOUND", output_text)
            self.assertIn("grade=", output_text)
            self.assertNotIn("static_advisory_rating=", output_text)
            self.assertIn("consequence_class=", output_text)
            self.assertIn("consequence_class_label=", output_text)
            self.assertIn("gating_status=", output_text)
            self.assertIn("runtime_reachability=Not proven", output_text)
            self.assertIn("vulnerability_claim=false", output_text)
            self.assertIn("runtime_source_candidate_paths=0", output_text)
            self.assertIn("additional_test_example_context_findings=0", output_text)
            self.assertIn("candidate_consequential_action_paths=0", output_text)
            self.assertIn("proof_binding=present", output_text)
            self.assertIn("replay_protection=present", output_text)
            self.assertIn("## Actenon Agentic Action Scan", summary_text)
            self.assertIn("Consequence Class:", summary_text)
            self.assertIn("Vulnerability Claim:", summary_text)
            self.assertIn("Proof check before action", summary_text)
            self.assertIn("Runtime-source candidate paths", summary_text)
            self.assertIn("not a vulnerability severity rating", summary_text)


if __name__ == "__main__":
    unittest.main()
