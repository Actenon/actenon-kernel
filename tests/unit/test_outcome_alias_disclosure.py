"""Kernel refusal codes that are protocol compatibility aliases must disclose
their canonical code, not OUTCOME_UNKNOWN (E2E F11)."""

from __future__ import annotations

import unittest

from actenon.outcomes import to_disclosed_code, to_retryable


class AliasDisclosureTests(unittest.TestCase):
    CASES = {
        # kernel / legacy code: (disclosed under "trusted", retryable)
        "DUPLICATE_REPLAY": ("REPLAY_DETECTED", False),
        "PCCB_REQUIRED": ("PROOF_MISSING", False),
        "PCCB_EXPIRED": ("PROOF_EXPIRED", False),
        "EXPIRED": ("PROOF_EXPIRED", False),
        "REVOKED": ("AUTHORITY_REVOKED", False),
        "ACTION_HASH_MISMATCH": ("PARAMETER_MISMATCH", False),
        "INTENT_MISMATCH": ("PARAMETER_MISMATCH", False),
    }

    def test_aliases_resolve_before_disclosure(self) -> None:
        for code, (canonical, retryable) in self.CASES.items():
            with self.subTest(code=code):
                self.assertEqual(to_disclosed_code(canonical, "trusted"), to_disclosed_code(code, "trusted"))
                self.assertEqual(to_disclosed_code(canonical, "public"), to_disclosed_code(code, "public"))
                self.assertNotEqual("OUTCOME_UNKNOWN", to_disclosed_code(code, "trusted"))
                self.assertIs(retryable, to_retryable(code))

    def test_unknown_codes_still_fall_back_to_outcome_unknown(self) -> None:
        self.assertEqual("OUTCOME_UNKNOWN", to_disclosed_code("NOT_A_REAL_CODE", "public"))
        self.assertTrue(to_retryable("NOT_A_REAL_CODE"))


if __name__ == "__main__":
    unittest.main()
