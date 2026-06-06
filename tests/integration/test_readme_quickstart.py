from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_readme_quickstart_matches_documented_output() -> None:
    environment = dict(os.environ)
    environment["PYTHON"] = sys.executable
    completed = subprocess.run(
        ["bash", "scripts/verify_readme_quickstart.sh"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "valid: EXECUTED" in completed.stdout
    assert "mismatch: REFUSED (INTENT_MISMATCH)" in completed.stdout
    assert "replay: REFUSED (DUPLICATE_REPLAY)" in completed.stdout
    assert "side_effects: 1" in completed.stdout
