from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


pytest.importorskip("langchain_core")


def test_protected_langchain_finance_agent_example_passes() -> None:
    example = Path(__file__).with_name("protected_langchain_finance_agent.py")

    result = subprocess.run(
        [sys.executable, str(example)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: ALL CHECKS PASSED" in result.stdout
    assert "No valid proof, no execution." in result.stdout
    assert "proof_in_schema=False" in result.stdout
    assert "vendor:attacker" not in result.stdout.split("Final state:", 1)[-1]
