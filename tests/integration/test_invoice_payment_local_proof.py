from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.demo.local_proof import run_invoice_payment_local_proof_demo


class InvoicePaymentLocalProofIntegrationTests(unittest.TestCase):
    def test_local_invoice_payment_demo_covers_wedge_scenarios(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "invoice_payment"
            manifest = run_invoice_payment_local_proof_demo(artifact_root)

            outcomes = {item["scenario"]: item["final_outcome"] for item in manifest["scenarios"]}
            self.assertEqual("executed", outcomes["allow"])
            self.assertEqual("deny", outcomes["duplicate_invoice_payment"])
            self.assertEqual("deny", outcomes["wrong_entity"])
            self.assertEqual("deny", outcomes["bank_mismatch"])
            self.assertEqual("approval-required", outcomes["approval_missing"])
            self.assertEqual("needs-evidence", outcomes["evidence_missing"])
            self.assertEqual("deny", outcomes["batch_hash_mismatch"])

            allow_receipt = json.loads((artifact_root / "scenarios" / "allow" / "execution_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual("executed", allow_receipt["outcome"])
            self.assertEqual("invoice_payment", allow_receipt["details"]["wedge"])
            self.assertTrue(allow_receipt["details"]["reconciliation_id"].startswith("recon_local_"))
            self.assertTrue(allow_receipt["side_effects"]["provider_reference"].startswith("provider_local_"))
            self.assertEqual("recorded-local", allow_receipt["side_effects"]["reconciliation_status"])

            approval_receipt = json.loads((artifact_root / "scenarios" / "approval_missing" / "decision_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual("approval-required", approval_receipt["outcome"])
            self.assertIn("finance-controller", approval_receipt["follow_up"]["approver_types"])

            evidence_receipt = json.loads((artifact_root / "scenarios" / "evidence_missing" / "decision_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual("needs-evidence", evidence_receipt["outcome"])
            self.assertIn("invoice_pdf", evidence_receipt["follow_up"]["required_evidence"])

            duplicate_refusal = json.loads((artifact_root / "scenarios" / "duplicate_invoice_payment" / "refusal.json").read_text(encoding="utf-8"))
            self.assertEqual("DUPLICATE_INVOICE_PAYMENT", duplicate_refusal["refusal_code"])

            wrong_entity_refusal = json.loads((artifact_root / "scenarios" / "wrong_entity" / "refusal.json").read_text(encoding="utf-8"))
            self.assertEqual("WRONG_ENTITY", wrong_entity_refusal["refusal_code"])

            bank_refusal = json.loads((artifact_root / "scenarios" / "bank_mismatch" / "refusal.json").read_text(encoding="utf-8"))
            self.assertEqual("BANK_MISMATCH", bank_refusal["refusal_code"])

            batch_hash_refusal = json.loads((artifact_root / "scenarios" / "batch_hash_mismatch" / "refusal.json").read_text(encoding="utf-8"))
            self.assertEqual("BATCH_HASH_MISMATCH", batch_hash_refusal["refusal_code"])


if __name__ == "__main__":
    unittest.main()
