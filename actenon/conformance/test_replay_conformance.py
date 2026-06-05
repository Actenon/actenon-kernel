"""Replay checks for the packaged conformance suite."""

from __future__ import annotations

import unittest
from tempfile import TemporaryDirectory

from actenon.models import Receipt, Refusal

from actenon.conformance.helpers import build_replay_kernel


class ReplayConformanceTests(unittest.TestCase):
    def test_duplicate_execution_is_replay_refused_with_portable_artifacts(self) -> None:
        with TemporaryDirectory() as tempdir:
            kernel, writer, payload, context = build_replay_kernel(tempdir)
            admission = kernel.submit_intent(payload, context)
            request = kernel.build_execution_request(intent=admission.intent, pccb=admission.pccb, context=context)

            first = kernel.execute(request, lambda req: {"external_reference": "exec_conformance_001"})
            duplicate = kernel.execute(request, lambda req: {"external_reference": "exec_conformance_002"})

            self.assertIsNone(first.refusal)
            self.assertIsNotNone(duplicate.refusal)
            self.assertEqual("DUPLICATE_REPLAY", duplicate.refusal.refusal_code)
            self.assertEqual("replay", duplicate.refusal.category)

            refusal = Refusal.from_dict(duplicate.refusal.to_dict())
            receipt = Receipt.from_dict(duplicate.receipt.to_dict())

            self.assertEqual("DUPLICATE_REPLAY", refusal.refusal_code)
            self.assertEqual("refused", receipt.outcome)
            self.assertEqual(refusal.refusal_id, receipt.correlation.refusal_id)
            self.assertIn("DUPLICATE_REPLAY", receipt.reason_codes)


if __name__ == "__main__":
    unittest.main()
