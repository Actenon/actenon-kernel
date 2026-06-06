from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.demo.local_proof import run_local_proof_demo


class RefundLocalProofIntegrationTests(unittest.TestCase):
    def test_local_refund_demo_covers_all_wedge_scenarios(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "artifacts"
            manifest = run_local_proof_demo(artifact_root)

            outcomes = {item["scenario"]: item["final_outcome"] for item in manifest["scenarios"]}
            self.assertEqual("executed", outcomes["allow"])
            self.assertEqual("deny", outcomes["deny"])
            self.assertEqual("approval-required", outcomes["approval_required"])
            self.assertEqual("needs-evidence", outcomes["needs_evidence"])

            allow_receipt = json.loads((artifact_root / "scenarios" / "allow" / "execution_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual("executed", allow_receipt["outcome"])
            self.assertEqual("refund", allow_receipt["details"]["wedge"])
            self.assertEqual(1500, allow_receipt["details"]["amount_minor"])

            approval_receipt = json.loads((artifact_root / "scenarios" / "approval_required" / "decision_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual("approval-required", approval_receipt["outcome"])
            self.assertIn("finance-operator", approval_receipt["follow_up"]["approver_types"])

            evidence_receipt = json.loads((artifact_root / "scenarios" / "needs_evidence" / "decision_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual("needs-evidence", evidence_receipt["outcome"])
            self.assertIn("external_id", evidence_receipt["follow_up"]["required_evidence"])

            refusal = json.loads((artifact_root / "scenarios" / "deny" / "refusal.json").read_text(encoding="utf-8"))
            self.assertEqual("WORKFLOW_DENY", refusal["reason_code"])


if __name__ == "__main__":
    unittest.main()
