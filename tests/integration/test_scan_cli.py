from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main
from actenon.demo.portable_local_proof import run_portable_local_proof_demo


class ScanCliIntegrationTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_scan_replay_harness_reports_all_checks_present(self) -> None:
        code, stdout, stderr = self._run_cli(["scan", "--target", "replay-harness", "--json"])
        self.assertEqual(0, code, stderr)
        payload = json.loads(stdout)
        self.assertEqual("replay-harness", payload["mode"])
        self.assertEqual("NO_OBVIOUS_EXECUTION_GAP_FOUND", payload["status"])
        self.assertIn(payload["grade"], {"A", "B"})
        self.assertIn("badge_markdown", payload)
        self.assertEqual("present", payload["checks"]["proof_binding"]["status"])
        self.assertEqual("present", payload["checks"]["replay_protection"]["status"])
        self.assertEqual("present", payload["checks"]["audience_enforcement"]["status"])
        self.assertEqual("present", payload["checks"]["expiry_enforcement"]["status"])
        self.assertEqual("present", payload["checks"]["structured_refusals"]["status"])

    def test_scan_artifact_pair_reports_partial_scope_honestly(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            run_portable_local_proof_demo(artifact_root)
            code, stdout, stderr = self._run_cli(
                [
                    "scan",
                    "--intent",
                    str(artifact_root / "action_intent.json"),
                    "--pccb",
                    str(artifact_root / "pccb.json"),
                    "--audience",
                    "service:portable-hello-world-endpoint",
                    "--json",
                ]
            )
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("artifact-pair", payload["mode"])
            self.assertEqual("PARTIAL_SCAN_ONLY", payload["status"])
            self.assertEqual("B", payload["grade"])
            self.assertEqual("present", payload["checks"]["proof_binding"]["status"])
            self.assertEqual("not_assessed", payload["checks"]["replay_protection"]["status"])
            self.assertEqual("present", payload["checks"]["audience_enforcement"]["status"])
            self.assertEqual("present", payload["checks"]["expiry_enforcement"]["status"])
            self.assertEqual("present", payload["checks"]["structured_refusals"]["status"])

    def test_scan_artifact_pair_flags_broken_baseline_as_gap_present(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "portable"
            run_portable_local_proof_demo(artifact_root)
            intent_path = artifact_root / "action_intent.json"
            intent_payload = json.loads(intent_path.read_text(encoding="utf-8"))
            intent_payload["action"]["parameters"]["message"] = "mutated portable hello world"
            intent_path.write_text(json.dumps(intent_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            code, stdout, stderr = self._run_cli(
                [
                    "scan",
                    "--intent",
                    str(intent_path),
                    "--pccb",
                    str(artifact_root / "pccb.json"),
                    "--audience",
                    "service:portable-hello-world-endpoint",
                    "--json",
                ]
            )
            self.assertEqual(1, code)
            if stderr:
                self.assertIn("ACTENON LOCAL HMAC SIGNER IS FOR LOCAL/DEV/DEMO ONLY", stderr)
            payload = json.loads(stdout)
            self.assertEqual("EXECUTION_GAP_PRESENT", payload["status"])
            self.assertEqual("missing", payload["checks"]["proof_binding"]["status"])

    def test_scan_local_subcommand_runs_private_harness(self) -> None:
        code, stdout, stderr = self._run_cli(["scan", "local", "--json"])
        self.assertEqual(0, code, stderr)
        payload = json.loads(stdout)
        self.assertEqual("local", payload["mode"])
        self.assertEqual("PARTIAL_SCAN_ONLY", payload["status"])
        self.assertEqual("B", payload["grade"])
        self.assertEqual("present", payload["checks"]["proof_binding"]["status"])
        self.assertEqual("not_assessed", payload["checks"]["credential_broker"]["status"])

    def test_scan_repo_reports_grade_reports_and_badge(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = Path(tempdir) / "unsafe_repo"
            repo.mkdir()
            (repo / "agent_tool.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']",
                        "def dangerous_tool(db):",
                        "    return db.delete_database('prod-db-primary')",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            json_report = Path(tempdir) / "report.json"
            markdown_report = Path(tempdir) / "report.md"
            badge = Path(tempdir) / "badge.md"
            code, stdout, stderr = self._run_cli(
                [
                    "scan",
                    "repo",
                    "--path",
                    str(repo),
                    "--report-json",
                    str(json_report),
                    "--report-markdown",
                    str(markdown_report),
                    "--badge-output",
                    str(badge),
                    "--json",
                ]
            )
            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertEqual("repo", payload["mode"])
            self.assertEqual("EXECUTION_GAP_PRESENT", payload["status"])
            self.assertEqual("F", payload["grade"])
            self.assertEqual("High-impact candidate, if reachable and ungated", payload["consequence_class_label"])
            self.assertEqual("high_impact_candidate", payload["consequence_class"])
            self.assertNotIn("static_advisory_rating", payload)
            self.assertIn("Actenon Scan: Review required", payload["badge_labels"])
            self.assertFalse(payload["vulnerability_claim"])
            self.assertIsNone(payload["vulnerability_severity"])
            self.assertEqual("Not proven", payload["runtime_reachability"])
            self.assertEqual("Not Verified", payload["runtime_proof_status"])
            self.assertTrue(payload["manual_review_required"])
            self.assertEqual(2, payload["candidate_consequential_action_paths"])
            self.assertEqual(2, payload["runtime_source_candidate_paths"])
            self.assertEqual(0, payload["additional_test_example_context_findings"])
            self.assertIn("FILE_MUTATION_SIDE_EFFECT", payload["categories_detected"])
            self.assertIn("FILE_MUTATION_SIDE_EFFECT", payload["consequential_action_categories_detected"])
            self.assertEqual("2.1.0", payload["scanner_version"])
            self.assertEqual("capability_registry.v1", payload["registry_version"])
            self.assertTrue(payload["findings"])
            self.assertEqual("missing", payload["checks"]["proof_binding"]["status"])
            self.assertEqual("missing", payload["checks"]["standing_credentials"]["status"])
            self.assertTrue(json_report.exists())
            self.assertTrue(markdown_report.exists())
            self.assertTrue(badge.exists())
            markdown = markdown_report.read_text(encoding="utf-8")
            self.assertIn("# Actenon Agentic Action Scan", markdown)
            self.assertIn("## Executive Summary", markdown)
            self.assertIn("## Action Surface Map", markdown)
            self.assertIn("Runtime-source candidate paths", markdown)
            self.assertIn("Consequence Class", markdown)
            self.assertNotIn("Static Advisory Rating", markdown)
            badge_text = badge.read_text(encoding="utf-8")
            self.assertIn("Actenon Scan: Review required", badge_text)
            self.assertNotIn("Critical", badge_text)
            self.assertNotIn("-red)", badge_text)
            self.assertNotIn("-red\n", badge_text)

    def test_scan_repo_controls_exclusions_extensions_progress_and_partial_report(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = Path(tempdir) / "repo"
            repo.mkdir()
            (repo / "agent_tool.py").write_text(
                "def agent_tool(api):\n    return api.post('https://example.invalid', json={})\n",
                encoding="utf-8",
            )
            (repo / "ignored.js").write_text(
                "function agentTool(page) { return page.click('#pay'); }\n",
                encoding="utf-8",
            )
            code, stdout, stderr = self._run_cli(
                [
                    "scan",
                    "repo",
                    "--path",
                    str(repo),
                    "--extensions",
                    "py",
                    "--exclude",
                    "ignored.js",
                    "--max-files",
                    "1",
                    "--timeout-seconds",
                    "10",
                    "--partial-report-on-timeout",
                    "--progress",
                    "--json",
                ]
            )
            self.assertEqual(1, code)
            self.assertIn("actenon-kernel scan:", stderr)
            payload = json.loads(stdout)
            self.assertEqual(1, payload["metadata"]["files_scanned"])
            self.assertTrue(payload["metadata"]["partial"])
            self.assertIn("EXTERNAL_API_SIDE_EFFECT", payload["consequential_action_categories_detected"])

    def test_scan_mcp_flags_destructive_tool_without_proof(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = Path(tempdir) / "mcp_repo"
            repo.mkdir()
            (repo / "server.py").write_text(
                "\n".join(
                    [
                        "from mcp import FastMCP",
                        "mcp = FastMCP('demo')",
                        "@mcp.tool()",
                        "def delete_prod_volume():",
                        "    return delete_volume('prod-volume-1')",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            code, stdout, stderr = self._run_cli(["scan", "mcp", "--path", str(repo), "--json"])
            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertEqual("mcp", payload["mode"])
            self.assertEqual("EXECUTION_GAP_PRESENT", payload["status"])
            self.assertTrue(
                any(
                    item["surface_id"] in {"S1", "S10"}
                    and item["agent_control_context"] == "yes"
                    and "missing proof gate" in item["control_gaps"]
                    for item in payload["findings"]
                )
            )

    def test_scan_markdown_stdout_includes_remediation_and_no_upload_claim(self) -> None:
        with TemporaryDirectory() as tempdir:
            repo = Path(tempdir) / "weak_repo"
            repo.mkdir()
            (repo / "exporter.py").write_text(
                "def agent_tool(data):\n    return data.export('customers')\n",
                encoding="utf-8",
            )
            code, stdout, stderr = self._run_cli(["scan", "repo", "--path", str(repo), "--markdown"])
            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            self.assertIn("# Actenon Agentic Action Scan", stdout)
            self.assertIn("## Priority Fixes", stdout)
            self.assertIn("## Findings", stdout)
            self.assertIn("## Recommended Integration Points", stdout)
            self.assertIn("This is not a vulnerability severity rating", stdout)
            self.assertIn("does not upload source code or reports by default", stdout)

            code, stdout, stderr = self._run_cli(
                ["scan", "repo", "--path", str(repo), "--markdown", "--report-mode", "developer"]
            )
            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            self.assertIn("Report mode: `developer`", stdout)
            self.assertIn("Path type", stdout)

            code, stdout, stderr = self._run_cli(["scan", "repo", "--path", str(repo)])
            self.assertEqual(1, code)
            self.assertEqual("", stderr)
            self.assertIn("Consequence class:", stdout)
            self.assertIn("Actenon Scanner maps agent authority", stdout)
            self.assertIn("Vulnerability claim: no", stdout)
            self.assertNotIn("Static advisory rating:", stdout)


if __name__ == "__main__":
    unittest.main()
