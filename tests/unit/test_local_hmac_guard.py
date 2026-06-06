from __future__ import annotations

import os
import unittest
import warnings
from unittest.mock import patch

from actenon.proof import LOCAL_HMAC_WARNING_MESSAGE, LocalHmacProductionGuardError, build_local_proof_signer
from actenon.proof.signers.local import LOCAL_PROOF_SECRET


class LocalHmacGuardTests(unittest.TestCase):
    def test_local_signer_works_in_explicit_dev_mode_and_warns(self) -> None:
        with (
            patch.dict(os.environ, {"ACTENON_ENV": "dev"}, clear=True),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always")
            signer = build_local_proof_signer()

        signature = signer.sign(b"local-payload")
        self.assertTrue(signer.verify(b"local-payload", signature))
        self.assertFalse(signer.verify(b"tampered", signature))
        self.assertEqual(LOCAL_PROOF_SECRET, signer.secret)
        self.assertTrue(any(LOCAL_HMAC_WARNING_MESSAGE in str(item.message) for item in caught))

    def test_default_public_secret_refuses_in_production_mode(self) -> None:
        with patch.dict(os.environ, {"ACTENON_ENV": "production"}, clear=True):
            with self.assertRaises(LocalHmacProductionGuardError):
                build_local_proof_signer()

    def test_custom_secret_cannot_override_production_guard(self) -> None:
        with patch.dict(os.environ, {"ACTENON_ENV": "production"}, clear=True):
            with self.assertRaises(LocalHmacProductionGuardError):
                build_local_proof_signer(secret=b"tenant-specific-demo-secret")

        with patch.dict(
            os.environ,
            {"ACTENON_ENV": "production", "ACTENON_ALLOW_LOCAL_HMAC": "1"},
            clear=True,
        ):
            with self.assertRaises(LocalHmacProductionGuardError):
                build_local_proof_signer(secret=b"tenant-specific-demo-secret")

    def test_explicit_production_flags_are_non_bypassable(self) -> None:
        for flag in (
            "ACTENON_PRODUCTION",
            "ACTENON_CI_RELEASE",
            "ACTENON_RELEASE_BUILD",
        ):
            with self.subTest(flag=flag):
                with patch.dict(
                    os.environ,
                    {flag: "1", "ACTENON_ALLOW_LOCAL_HMAC": "1"},
                    clear=True,
                ):
                    with self.assertRaises(LocalHmacProductionGuardError):
                        build_local_proof_signer()

    def test_env_secret_is_accepted_in_explicit_demo_mode(self) -> None:
        with patch.dict(
            os.environ,
            {"ACTENON_ENV": "demo", "ACTENON_LOCAL_HMAC_SECRET": "demo-secret-from-env"},
            clear=True,
        ):
            signer = build_local_proof_signer()

        self.assertEqual(b"demo-secret-from-env", signer.secret)


if __name__ == "__main__":
    unittest.main()
