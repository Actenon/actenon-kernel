from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from actenon.scanner import ScannerOptions, render_markdown_report, scan_repository


FAKE_SECRET = "sk_live_SUPER_SECRET_SHOULD_NOT_APPEAR"


class ScannerSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_scanner_does_not_execute_or_import_target_repo_code(self) -> None:
        sentinel = self.root / "executed.txt"
        target = self.repo / "target_payload.py"
        target.write_text(
            "\n".join(
                [
                    "from pathlib import Path",
                    f"Path({str(sentinel)!r}).write_text('executed')",
                    "raise RuntimeError('target code was imported or executed')",
                    "def agent_tool(api):",
                    "    return api.post('https://api.vendor.example/mutate', json={})",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        report = scan_repository(self.repo)

        self.assertFalse(sentinel.exists())
        self.assertNotIn("target_payload", sys.modules)
        self.assertTrue(report.findings)

    def test_scanner_does_not_follow_network_calls_during_static_analysis(self) -> None:
        (self.repo / "agent.py").write_text(
            "def agent_tool(api):\n    return api.post('https://api.vendor.example/mutate', json={})\n",
            encoding="utf-8",
        )

        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network fetch attempted")):
            with mock.patch("socket.create_connection", side_effect=AssertionError("network connection attempted")):
                report = scan_repository(self.repo)

        self.assertTrue(report.findings)

    def test_scanner_does_not_read_secret_values_outside_scan_path(self) -> None:
        outside_secret = self.root / "outside_secret.txt"
        outside_secret.write_text(FAKE_SECRET, encoding="utf-8")
        (self.repo / "agent.py").write_text(
            "\n".join(
                [
                    "from pathlib import Path",
                    "def agent_tool(api):",
                    "    secret_path = Path('../outside_secret.txt')",
                    "    token = secret_path.read_text()",
                    "    return api.post('https://api.vendor.example/mutate', headers={'Authorization': token})",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        report = scan_repository(self.repo)
        serialized = json.dumps(report.to_dict(), sort_keys=True)

        self.assertTrue(report.findings)
        self.assertNotIn(FAKE_SECRET, serialized)

    def test_scanner_redacts_secret_like_literals_from_markdown_and_json_reports(self) -> None:
        (self.repo / "agent.py").write_text(
            "\n".join(
                [
                    f'API_KEY = "{FAKE_SECRET}"',
                    "def agent_tool(api):",
                    "    return api.post('https://api.vendor.example/mutate', json={'api_key': API_KEY})",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        report = scan_repository(self.repo)
        markdown = render_markdown_report(report, mode="developer")
        structured = json.dumps(report.to_dict(), sort_keys=True)

        self.assertTrue(report.findings)
        self.assertNotIn(FAKE_SECRET, markdown)
        self.assertNotIn(FAKE_SECRET, structured)
        self.assertIn("[REDACTED]", markdown)
        self.assertIn("[REDACTED]", structured)

    def test_scanner_reports_remain_advisory_and_do_not_overclaim_exploitability(self) -> None:
        (self.repo / "agent.py").write_text(
            "def agent_tool(page):\n    page.fill('#amount', '1000')\n    return page.click('#submit')\n",
            encoding="utf-8",
        )

        report = scan_repository(self.repo, options=ScannerOptions(max_files=10))
        markdown = render_markdown_report(report, mode="executive")
        lower_markdown = markdown.lower()

        self.assertIn("static advisory", lower_markdown)
        self.assertIn("candidate", lower_markdown)
        self.assertIn("requires maintainer review", lower_markdown)
        self.assertIn("runtime exploitability not proven", lower_markdown)
        for forbidden in ("exploitable", "breached", "definitely reaches production", "caused harm", " unsafe"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lower_markdown)


if __name__ == "__main__":
    unittest.main()
