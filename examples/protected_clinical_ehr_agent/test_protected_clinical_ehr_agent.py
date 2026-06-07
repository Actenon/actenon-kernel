import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")


def test_protected_clinical_ehr_agent_example_passes() -> None:
    example = Path(__file__).with_name("protected_clinical_ehr_agent.py")

    result = subprocess.run(
        [sys.executable, str(example)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: ALL CHECKS PASSED" in result.stdout
    assert "No valid proof, no execution." in result.stdout
    assert "wrong patient" in result.stdout
    assert "overdose" in result.stdout
    assert "replay approved administration" in result.stdout
