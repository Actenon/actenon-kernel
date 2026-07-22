"""Execution-state checks for the packaged conformance suite."""

from __future__ import annotations

import unittest

from actenon.models import (
    TERMINAL_EXECUTION_STATES,
    can_transition_execution_state,
    is_terminal_execution_state,
    validate_execution_state_path,
)
from actenon.models.execution import ExecutionStateTransitionError


class ExecutionStateConformanceTests(unittest.TestCase):
    def test_valid_execution_state_paths_are_accepted(self) -> None:
        validate_execution_state_path(
            (
                "received",
                "policy_allowed",
                "proof_minted",
                "escrow_issued",
                "execution_attempted",
                "confirmed",
            )
        )
        validate_execution_state_path(("received", "refused"))
        validate_execution_state_path(("received", "policy_allowed", "proof_minted", "escrow_issued", "replay_refused"))
        validate_execution_state_path(
            (
                "received",
                "policy_allowed",
                "proof_minted",
                "escrow_issued",
                "execution_attempted",
                "provider_pending",
                "confirmed",
            )
        )
        validate_execution_state_path(
            (
                "received",
                "policy_allowed",
                "proof_minted",
                "escrow_issued",
                "execution_attempted",
                "ambiguous",
                "confirmed",
            )
        )

    def test_invalid_execution_state_paths_are_rejected(self) -> None:
        with self.assertRaises(ExecutionStateTransitionError):
            validate_execution_state_path(("proof_minted", "confirmed"))
        with self.assertRaises(ExecutionStateTransitionError):
            validate_execution_state_path(("received", "proof_minted"))
        with self.assertRaises(ExecutionStateTransitionError):
            validate_execution_state_path(("received", "policy_allowed", "confirmed"))
        with self.assertRaises(ExecutionStateTransitionError):
            validate_execution_state_path(("received", "confirmed", "provider_pending"))

    def test_transition_helpers_match_published_state_model(self) -> None:
        self.assertTrue(can_transition_execution_state("escrow_issued", "replay_refused"))
        self.assertTrue(can_transition_execution_state("execution_attempted", "ambiguous"))
        self.assertTrue(can_transition_execution_state("provider_pending", "revoked"))
        self.assertTrue(can_transition_execution_state("policy_allowed", "expired"))
        self.assertFalse(can_transition_execution_state("confirmed", "provider_pending"))
        self.assertFalse(can_transition_execution_state("revoked", "confirmed"))
        self.assertTrue(is_terminal_execution_state("replay_refused"))
        self.assertTrue(is_terminal_execution_state("expired"))
        self.assertTrue(is_terminal_execution_state("revoked"))
        self.assertFalse(is_terminal_execution_state("ambiguous"))
        self.assertIn("confirmed", TERMINAL_EXECUTION_STATES)


if __name__ == "__main__":
    unittest.main()
