"""Issuer-status and approval-artifact checks for the packaged conformance suite."""

from __future__ import annotations

import json
import logging
import unittest
from datetime import UTC, datetime
from importlib.util import find_spec
from pathlib import Path

from actenon.verifier import (
    TrustArtifactVerificationError,
    verify_approval_artifact,
    verify_issuer_status,
)

VECTOR_ROOT = (
    Path(__file__).resolve().parents[2]
    / "conformance"
    / "vectors"
    / "trust_artifacts_v1"
)
NOW = datetime(2026, 6, 6, 12, 5, tzinfo=UTC)


def _load(relative_path: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / relative_path).read_text(encoding="utf-8"))


@unittest.skipUnless(
    find_spec("cryptography") is not None,
    "trust-artifact conformance requires the 'asymmetric' extra",
)
class TrustArtifactConformanceTests(unittest.TestCase):
    def test_good_status_and_exact_action_approval_verify(self) -> None:
        status = verify_issuer_status(
            _load("issuer.json"),
            _load("issuer_status_good.json"),
            _load("issuer_status_trusted_keys.json"),
            NOW,
        )
        approval = verify_approval_artifact(
            _load("approval.json"),
            _load("approval_trusted_keys.json"),
            expected_action=_load("action_intent.json"),
        )

        self.assertEqual("good_standing", status.status)
        self.assertEqual("finance_approver", approval.approval_type)

    def test_revoked_stale_expired_and_missing_status_fail_closed(self) -> None:
        cases = (
            ("issuer_status_revoked.json", "ISSUER_REVOKED"),
            ("issuer_status_stale.json", "ISSUER_STATUS_STALE"),
            ("issuer_status_expired.json", "ISSUER_STATUS_EXPIRED"),
            ("mutations/issuer_status_signature_changed.json", "SIGNATURE_INVALID"),
        )
        for fixture, expected_code in cases:
            with self.subTest(fixture=fixture), self.assertRaises(
                TrustArtifactVerificationError
            ) as raised:
                verify_issuer_status(
                    _load("issuer.json"),
                    _load(fixture),
                    _load("issuer_status_trusted_keys.json"),
                    NOW,
                )
            self.assertEqual(expected_code, raised.exception.code)

        with self.assertRaises(TrustArtifactVerificationError) as missing:
            verify_issuer_status(_load("issuer.json"), None, None, NOW)
        self.assertEqual("ISSUER_STATUS_REQUIRED", missing.exception.code)

    def test_disabled_status_policy_is_explicit_and_logged(self) -> None:
        with self.assertLogs(
            "actenon.verifier.trust_artifacts",
            level=logging.WARNING,
        ) as captured:
            result = verify_issuer_status(
                _load("issuer.json"),
                None,
                None,
                NOW,
                status_policy="disabled",
            )
        self.assertIsNone(result)
        self.assertEqual(1, len(captured.output))

    def test_forged_or_laundered_approval_is_rejected(self) -> None:
        for fixture, expected_code in (
            ("mutations/approval_action_changed.json", "APPROVAL_ACTION_MISMATCH"),
            ("mutations/approval_signature_changed.json", "SIGNATURE_INVALID"),
        ):
            with self.subTest(fixture=fixture), self.assertRaises(
                TrustArtifactVerificationError
            ) as raised:
                verify_approval_artifact(
                    _load(fixture),
                    _load("approval_trusted_keys.json"),
                    expected_action=_load("action_intent.json"),
                )
            self.assertEqual(expected_code, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
