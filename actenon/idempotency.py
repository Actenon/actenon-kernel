"""Operation identity, idempotency, and outcome-state model.

This module formalises the distinction between:

  - **Replay protection**: prevents unauthorised reuse of proof authority.
    A consumed proof cannot be used again. Keyed by `proof_id` (pccb_id).

  - **Idempotency**: allows safe recovery or retry of an intended operation
    without duplicating its side effect. Keyed by `operation_id` +
    `action_hash`. If the same operation_id + same action_hash is
    presented again, the prior result is returned (not re-executed).
    If the same operation_id + different action_hash is presented, it is
    refused as IDEMPOTENCY_CONFLICT.

  - **Reconciliation**: resolves ambiguous provider outcomes (e.g.
    timeout after the provider accepted the call). Uses 8 outcome states.

An idempotency key is NOT permission to reuse a proof indefinitely.
The proof must still pass replay protection (single-use). Idempotency
only applies when a NEW proof is minted for the SAME operation_id +
SAME action_hash — in that case, the prior result is returned without
re-executing the handler.

Identifier model:
  - `proof_id` (pccb_id): unique per proof. Used for replay protection.
  - `operation_id`: caller-supplied, bound to the action_hash. Used for
    idempotency. Stored in `ActionIntent.metadata["operation_id"]`.
  - `attempt_id` (request_id): unique per execution attempt. Used for
    receipt linkage and reconciliation.
  - `reconciliation_state`: one of the 8 outcome states below.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from actenon.core.errors import RefusalException


class OutcomeState(str, Enum):
    """The 8 outcome states for evidence reconciliation.

    These distinguish what happened at the boundary:
      1. REFUSED_BEFORE_EXECUTION — the proof was refused; no execution
         was attempted.
      2. VERIFIED_NOT_EXECUTED — the proof was verified but execution
         was not attempted (e.g. policy denial after verification).
      3. EXECUTION_ATTEMPTED — the handler was called but the result is
         not yet known (e.g. handler raised an exception).
      4. PROVIDER_CONFIRMED_SUCCESS — the handler returned successfully;
         the provider confirmed the action completed.
      5. PROVIDER_CONFIRMED_FAILURE — the handler returned; the provider
         confirmed the action failed (non-exception failure).
      6. OUTCOME_UNKNOWN — the handler raised an exception after the
         provider may have accepted the call. Reconciliation is required.
      7. RECONCILED_SUCCESS — a reconciler determined the action
         completed successfully despite OUTCOME_UNKNOWN.
      8. RECONCILED_FAILURE — a reconciler determined the action did
         not complete despite OUTCOME_UNKNOWN.
    """

    REFUSED_BEFORE_EXECUTION = "refused_before_execution"
    VERIFIED_NOT_EXECUTED = "verified_not_executed"
    EXECUTION_ATTEMPTED = "execution_attempted"
    PROVIDER_CONFIRMED_SUCCESS = "provider_confirmed_success"
    PROVIDER_CONFIRMED_FAILURE = "provider_confirmed_failure"
    OUTCOME_UNKNOWN = "outcome_unknown"
    RECONCILED_SUCCESS = "reconciled_success"
    RECONCILED_FAILURE = "reconciled_failure"

    @property
    def is_terminal(self) -> bool:
        """True if the state is terminal (no further transitions)."""
        return self in {
            OutcomeState.REFUSED_BEFORE_EXECUTION,
            OutcomeState.PROVIDER_CONFIRMED_SUCCESS,
            OutcomeState.PROVIDER_CONFIRMED_FAILURE,
            OutcomeState.RECONCILED_SUCCESS,
            OutcomeState.RECONCILED_FAILURE,
        }

    @property
    def is_reconcilable(self) -> bool:
        """True if the state can be reconciled (transitioned to a terminal state)."""
        return self in {
            OutcomeState.OUTCOME_UNKNOWN,
            OutcomeState.EXECUTION_ATTEMPTED,
        }


class IdempotencyConflict(RefusalException):
    """Raised when the same operation_id is presented with a different action_hash."""

    def __init__(self, operation_id: str, expected_hash: str, actual_hash: str) -> None:
        super().__init__(
            category="idempotency",
            refusal_code="IDEMPOTENCY_CONFLICT",
            message=(
                f"Operation {operation_id!r} was already executed with a "
                f"different action_hash. Expected {expected_hash[:12]}..., "
                f"got {actual_hash[:12]}...."
            ),
            retryable=False,
            details={
                "operation_id": operation_id,
                "expected_action_hash": expected_hash,
                "actual_action_hash": actual_hash,
            },
        )


# Late import to avoid circular dependency
if False:  # TYPE_CHECKING
    from actenon.core.errors import RefusalException


class IdempotencyStore:
    """In-memory idempotency store for tracking operation_id → result mappings.

    This is a minimal in-memory implementation suitable for the kernel's
    local OSS deployment. Production deployments should use a persistent
    store (e.g. the same SQLite/Postgres database as the replay store).

    Thread-safe via a threading.Lock.
    """

    def __init__(self) -> None:
        import threading
        self._lock = threading.Lock()
        self._records: dict[str, dict[str, Any]] = {}

    def lookup(self, operation_id: str) -> dict[str, Any] | None:
        """Return the prior result for the given operation_id, or None."""
        with self._lock:
            return self._records.get(operation_id)

    def record(
        self,
        operation_id: str,
        action_hash: str,
        result: dict[str, Any],
    ) -> None:
        """Record the result of an operation. If the operation_id already
        exists with a different action_hash, raise IdempotencyConflict."""
        with self._lock:
            existing = self._records.get(operation_id)
            if existing is not None:
                if existing["action_hash"] != action_hash:
                    raise IdempotencyConflict(
                        operation_id=operation_id,
                        expected_hash=existing["action_hash"],
                        actual_hash=action_hash,
                    )
                # Same operation_id + same action_hash — already recorded.
                # This is an idempotent replay; the caller should return
                # the prior result.
                return
            self._records[operation_id] = {
                "action_hash": action_hash,
                "result": result,
            }
