import subprocess
import sys
from pathlib import Path


def test_interactive_execution_demo_passes() -> None:
    demo = Path(__file__).parents[1] / "examples" / "interactive_execution_demo.py"

    result = subprocess.run(
        [sys.executable, str(demo), "--scripted"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Actenon 3-minute demo" in result.stdout
    assert "approved refund" in result.stdout
    assert "hallucinated refund" in result.stdout
    assert "INTENT_MISMATCH" in result.stdout
    assert "DUPLICATE_REPLAY" in result.stdout
    assert "PCCB_REQUIRED" in result.stdout
    assert "No valid proof, no execution." in result.stdout
    assert "Final ledger events: [{'order_id': 'ord-123', 'amount_cents': 2500}]" in result.stdout
