"""Receipt counter-signature checks for the packaged conformance suite."""

from __future__ import annotations

import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from actenon.verifier import (
    CounterSignatureVerificationError,
    verify_countersignature,
)


VECTOR_ROOT = (
    Path(__file__).resolve().parents[2]
    / "conformance"
    / "vectors"
    / "receipt_countersignature_v1"
)


def _load(relative_path: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / relative_path).read_text(encoding="utf-8"))


@unittest.skipUnless(
    find_spec("cryptography") is not None,
    "receipt counter-signature conformance requires the 'asymmetric' extra",
)
class CounterSignatureConformanceTests(unittest.TestCase):
    def test_valid_historical_kid_verifies_offline(self) -> None:
        verified = verify_countersignature(
            _load("receipt.json"),
            _load("countersignature.json"),
            _load("trusted_keys.json"),
        )

        self.assertEqual(
            "actenon-countersignature-fixture-2025-11",
            verified.key_id,
        )
        self.assertEqual(
            "47dbb2e07068f0f5459d0ad4c2ca425c721962b89ff9c29f3305c3b77bacfb1c",
            verified.receipt_digest.value,
        )

    def test_valid_digest_input_verifies(self) -> None:
        countersignature = _load("countersignature.json")

        verified = verify_countersignature(
            countersignature["receipt_digest"],
            countersignature,
            _load("trusted_keys.json"),
        )

        self.assertEqual(
            "actenon-countersignature-fixture",
            verified.witness.id,
        )

    def test_unknown_kid_is_rejected(self) -> None:
        with self.assertRaises(CounterSignatureVerificationError) as raised:
            verify_countersignature(
                _load("receipt.json"),
                _load("mutations/countersignature_unknown_kid.json"),
                _load("trusted_keys.json"),
            )

        self.assertEqual("UNKNOWN_KEY_ID", raised.exception.code)

    def test_wrong_public_key_is_rejected(self) -> None:
        with self.assertRaises(CounterSignatureVerificationError) as raised:
            verify_countersignature(
                _load("receipt.json"),
                _load("countersignature.json"),
                _load("mutations/trusted_keys_wrong_key.json"),
            )

        self.assertEqual("SIGNATURE_INVALID", raised.exception.code)

    def test_altered_digest_is_rejected(self) -> None:
        with self.assertRaises(CounterSignatureVerificationError) as raised:
            verify_countersignature(
                _load("receipt.json"),
                _load("mutations/countersignature_altered_digest.json"),
                _load("trusted_keys.json"),
            )

        self.assertEqual("RECEIPT_DIGEST_MISMATCH", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
