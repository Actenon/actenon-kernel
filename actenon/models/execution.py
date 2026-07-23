from __future__ import annotations

from typing import Literal, Sequence


ExecutionState = Literal[
    "received",
    "policy_allowed",
    "proof_minted",
    "escrow_issued",
    "execution_attempted",
    "provider_pending",
    "confirmed",
    "refused",
    "failed",
    "ambiguous",
    "replay_refused",
    "expired",
    "revoked",
]


TERMINAL_EXECUTION_STATES: frozenset[ExecutionState] = frozenset(
    {
        "confirmed",
        "refused",
        "failed",
        "replay_refused",
        "expired",
        "revoked",
    }
)


ALLOWED_EXECUTION_STATE_TRANSITIONS: dict[ExecutionState, frozenset[ExecutionState]] = {
    "received": frozenset({"policy_allowed", "refused", "expired", "revoked"}),
    "policy_allowed": frozenset({"proof_minted", "refused", "expired", "revoked"}),
    "proof_minted": frozenset({"escrow_issued", "refused", "expired", "revoked"}),
    "escrow_issued": frozenset({"execution_attempted", "replay_refused", "refused", "expired", "revoked"}),
    "execution_attempted": frozenset({"provider_pending", "confirmed", "failed", "ambiguous"}),
    "provider_pending": frozenset({"confirmed", "failed", "ambiguous", "expired", "revoked"}),
    "ambiguous": frozenset({"confirmed", "failed"}),
    "confirmed": frozenset(),
    "refused": frozenset(),
    "failed": frozenset(),
    "replay_refused": frozenset(),
    "expired": frozenset(),
    "revoked": frozenset(),
}


class ExecutionStateTransitionError(ValueError):
    """Raised when an execution state path violates the published state model."""


def is_terminal_execution_state(state: ExecutionState) -> bool:
    """Return ``True`` when the supplied execution state is terminal."""

    return state in TERMINAL_EXECUTION_STATES


def can_transition_execution_state(current: ExecutionState, nxt: ExecutionState) -> bool:
    """Return ``True`` when the state transition is allowed by the model."""

    return nxt in ALLOWED_EXECUTION_STATE_TRANSITIONS[current]


def validate_execution_state_path(states: Sequence[ExecutionState]) -> None:
    """Validate a full execution-state path against the published semantics.

    A valid path MUST:

    - contain at least one state
    - start at ``received``
    - use only allowed transitions
    - stop once a terminal state is reached
    """

    if not states:
        raise ExecutionStateTransitionError("execution state path must not be empty")
    if states[0] != "received":
        raise ExecutionStateTransitionError("execution state path must start at 'received'")

    for current, nxt in zip(states, states[1:]):
        if is_terminal_execution_state(current):
            raise ExecutionStateTransitionError(f"terminal state {current!r} cannot transition to {nxt!r}")
        if not can_transition_execution_state(current, nxt):
            raise ExecutionStateTransitionError(f"invalid execution state transition: {current!r} -> {nxt!r}")

