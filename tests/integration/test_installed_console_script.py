from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[2]


class InstalledConsoleScriptIntegrationTests(unittest.TestCase):
    def test_installed_actenon_console_script_and_packaged_viewer_work(self) -> None:
        with TemporaryDirectory() as tempdir:
            temp_root = Path(tempdir)
            venv_dir = temp_root / "venv"
            subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True, text=True, capture_output=True)

            bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
            python = bin_dir / ("python.exe" if os.name == "nt" else "python")
            actenon = bin_dir / ("actenon.exe" if os.name == "nt" else "actenon")

            subprocess.run(
                [str(python), "-m", "pip", "install", ".[asymmetric]"],
                check=True,
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                timeout=180,
            )

            help_result = subprocess.run(
                [str(actenon), "--help"],
                check=True,
                cwd=temp_root,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertIn("Local CLI", help_result.stdout)

            conformance_result = subprocess.run(
                [str(actenon), "conformance", "run", "--require-complete"],
                check=True,
                cwd=temp_root,
                text=True,
                capture_output=True,
                timeout=180,
            )
            self.assertIn("Conformance tests passed.", conformance_result.stdout)
            self.assertIn("Skipped: 0.", conformance_result.stdout)
            self.assertIn(
                "Actenon Verified (Conformance 1.0.0)",
                conformance_result.stdout,
            )

            viewer_help_result = subprocess.run(
                [str(python), "-m", "actenon.ui.trace_viewer.app", "--help"],
                check=True,
                cwd=temp_root,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertIn("read-only local artifact viewer", viewer_help_result.stdout)

            static_resource_result = subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "from importlib import resources; "
                        "print(resources.files('actenon.ui.trace_viewer').joinpath('static/index.html').is_file())"
                    ),
                ],
                check=True,
                cwd=temp_root,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual("True", static_resource_result.stdout.strip())

            schema_resource_result = subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "from importlib import resources; "
                        "print(resources.files('schemas').joinpath('pccb.v1.json').is_file())"
                    ),
                ],
                check=True,
                cwd=temp_root,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual("True", schema_resource_result.stdout.strip())

            trace_runtime_result = subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "from actenon.local_runtime_server import start_local_runtime_services; "
                        "session = start_local_runtime_services(runtime_dir='runtime', port=0, trace_viewer_port=0); "
                        "print(session.startup_info.trace_viewer_status); "
                        "session.close()"
                    ),
                ],
                check=True,
                cwd=temp_root,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual("started", trace_runtime_result.stdout.strip())


if __name__ == "__main__":
    unittest.main()
