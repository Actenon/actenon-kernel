from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class PackagingImportTests(unittest.TestCase):
    def test_installed_cli_path_does_not_import_bare_ui_package(self) -> None:
        bare_ui_import = re.compile(r"(^|\n)\s*(from\s+ui(\.|\s)|import\s+ui(\.|\s|$))")
        cli_paths = (
            REPO_ROOT / "actenon" / "cli.py",
            REPO_ROOT / "actenon" / "local_runtime_server.py",
            REPO_ROOT / "actenon" / "ui" / "trace_viewer" / "app.py",
        )

        for path in cli_paths:
            with self.subTest(path=path):
                self.assertIsNone(bare_ui_import.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
