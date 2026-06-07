import subprocess
import sys
from pathlib import Path


def test_protected_iam_control_plane_example_passes() -> None:
    example = Path(__file__).with_name("protected_iam_control_plane.py")

    result = subprocess.run(
        [sys.executable, str(example)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: ALL CHECKS PASSED" in result.stdout
    assert "No valid proof, no execution." in result.stdout
    assert "PREFLIGHT_PRIVILEGED_ACCESS_APPROVAL_REQUIRED" in result.stdout
    assert "INTENT_MISMATCH" in result.stdout
    assert "DUPLICATE_REPLAY" in result.stdout
