"""Artifact-shape checks for the packaged conformance suite."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.demo.local_proof import run_invoice_payment_local_proof_demo, run_local_proof_demo
from actenon.models import Receipt, Refusal


class ArtifactShapeConformanceTests(unittest.TestCase):
    def test_refund_execution_receipt_matches_public_shape(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "refund"
            run_local_proof_demo(artifact_root)
            payload = json.loads((artifact_root / "scenarios" / "allow" / "execution_receipt.json").read_text(encoding="utf-8"))
            receipt = Receipt.from_dict(payload)

            self.assertEqual("receipt", payload["contract"]["name"])
            self.assertEqual("executed", receipt.outcome)
            self.assertEqual("execution", receipt.phase)
            self.assertEqual("completed", receipt.side_effects["state"])

    def test_invoice_payment_execution_receipt_exposes_portable_reconciliation_fields(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "invoice"
            run_invoice_payment_local_proof_demo(artifact_root)
            payload = json.loads((artifact_root / "scenarios" / "allow" / "execution_receipt.json").read_text(encoding="utf-8"))
            receipt = Receipt.from_dict(payload)

            self.assertEqual("receipt", payload["contract"]["name"])
            self.assertEqual("executed", receipt.outcome)
            self.assertTrue(receipt.side_effects["provider_reference"].startswith("provider_local_"))
            self.assertEqual("recorded-local", receipt.side_effects["reconciliation_status"])

    def test_policy_refusal_matches_public_shape(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "refund"
            run_local_proof_demo(artifact_root)
            payload = json.loads((artifact_root / "scenarios" / "deny" / "refusal.json").read_text(encoding="utf-8"))
            refusal = Refusal.from_dict(payload)

            self.assertEqual("refusal", payload["contract"]["name"])
            self.assertEqual("policy", refusal.category)
            self.assertEqual("WORKFLOW_DENY", refusal.refusal_code)
            self.assertFalse(refusal.retryable)


if __name__ == "__main__":
    unittest.main()
