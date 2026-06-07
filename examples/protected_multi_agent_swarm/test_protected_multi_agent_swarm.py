import subprocess
import sys
from pathlib import Path


def test_protected_multi_agent_swarm_example_passes() -> None:
    example = Path(__file__).with_name("protected_multi_agent_swarm.py")

    result = subprocess.run(
        [sys.executable, str(example)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: ALL CHECKS PASSED" in result.stdout
    assert "SWARM CONCURRENCY" in result.stdout
    assert "exactly one winner under concurrency" in result.stdout
    assert "No valid proof, no execution." in result.stdout
