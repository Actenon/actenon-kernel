"""Key-lifecycle state machine for managed signing keys.

Fable 5 Part 3C identified KMS custody as the universal gate across every
persona: the engineer, the CISO, the auditor, and the underwriter all
independently arrive at the KMS/HSM stub. The single most-cited blocker
for converting pilots into production is "no real KMS backend is wired."

This module defines the key-lifecycle state machine that any concrete
backend (AWS KMS, GCP KMS, Azure Key Vault, PKCS#11 HSM) must enforce.
The states and transitions are provider-neutral; backends map their
native key states onto these.

States
------

- ``active``      — key is minting new proofs. Exactly one active key per
                    (issuer, purpose) at any time.
- ``retired``     — key no longer mints, but still verifies. Used during
                    rotation: the new key is active, the old key is
                    retired so historical proofs still verify.
- ``suspended``   — key is temporarily blocked (suspected compromise,
                    operator investigation). Can return to ``active``.
- ``revoked``     — key is permanently blocked from minting. Existing
                    proofs SHOULD still verify (otherwise historical
                    receipts become unverifiable). Use this when the
                    key is compromised but you need to preserve audit.
- ``hard_revoked`` — key is permanently blocked from both minting AND
                     verifying. Use this when the key is compromised
                     AND you have an external anchor (transparency log
                     inclusion proof) that proves historical proofs
                     predated the compromise. Without an external
                     anchor, hard-revoking breaks historical verifiability.

Transitions
-----------

- active -> retired, suspended, revoked, hard_revoked
- retired -> suspended, revoked, hard_revoked  (NOT back to active —
             re-activating a retired key risks proof-of-stale-key)
- suspended -> active, retired, revoked, hard_revoked
- revoked -> hard_revoked  (one-way: revocation is permanent)
- hard_revoked -> (terminal, no transitions out)

The state machine is enforced by :class:`KeyLifecycleMachine`. Backends
SHOULD call :meth:`KeyLifecycleMachine.assert_can_sign` before every
sign operation and :meth:`KeyLifecycleMachine.assert_can_verify` before
every verify operation. Backends that do not enforce this are not
conformant.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class KeyLifecycleError(RuntimeError):
    """Raised when a key-lifecycle transition or operation is invalid."""


class KeyLifecycleState(str, Enum):
    """The five states a managed signing key can be in."""

    ACTIVE = "active"
    RETIRED = "retired"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    HARD_REVOKED = "hard_revoked"

    @classmethod
    def from_string(cls, value: str) -> "KeyLifecycleState":
        try:
            return cls(value.lower())
        except ValueError as e:
            raise KeyLifecycleError(
                f"unknown key lifecycle state {value!r}; "
                f"expected one of {[s.value for s in cls]}"
            ) from e


# States that allow signing (minting new proofs).
# Only `active` can mint. Suspended/retired/revoked/hard_revoked cannot.
SIGN_ALLOWED_STATES = frozenset({KeyLifecycleState.ACTIVE})

# States that allow verification (checking existing proofs).
# Everything except hard_revoked can verify. Hard-revoking breaks
# historical verifiability — only do this when an external anchor
# (transparency log) proves historical proofs predated the compromise.
VERIFY_ALLOWED_STATES = frozenset({
    KeyLifecycleState.ACTIVE,
    KeyLifecycleState.RETIRED,
    KeyLifecycleState.SUSPENDED,
    KeyLifecycleState.REVOKED,
})

# Allowed transitions. Anything not listed here is forbidden.
# Rationale:
#   active -> retired:       planned rotation, old key still verifies
#   active -> suspended:     suspected compromise, investigation ongoing
#   active -> revoked:       confirmed compromise, keep verifying for audit
#   active -> hard_revoked:  confirmed compromise, break historical verifiability
#   retired -> suspended:    retired key suspected of compromise
#   retired -> revoked:      retired key confirmed compromised
#   retired -> hard_revoked: retired key confirmed compromised, break history
#   suspended -> active:     investigation cleared the key
#   suspended -> retired:    investigation finished, rotate anyway
#   suspended -> revoked:    investigation confirmed compromise
#   suspended -> hard_revoked: investigation confirmed, break history
#   revoked -> hard_revoked: escalate a revocation to hard-revocation
#
# NOTE: `retired -> active` is intentionally NOT allowed. Re-activating a
# retired key risks "proof of stale key": a holder of the retired key's
# material could mint proofs that look fresh. If you need a key back in
# active rotation, mint a NEW key with a new key_id instead.
ALLOWED_TRANSITIONS: Mapping[KeyLifecycleState, frozenset[KeyLifecycleState]] = {
    KeyLifecycleState.ACTIVE: frozenset({
        KeyLifecycleState.RETIRED,
        KeyLifecycleState.SUSPENDED,
        KeyLifecycleState.REVOKED,
        KeyLifecycleState.HARD_REVOKED,
    }),
    KeyLifecycleState.RETIRED: frozenset({
        KeyLifecycleState.SUSPENDED,
        KeyLifecycleState.REVOKED,
        KeyLifecycleState.HARD_REVOKED,
    }),
    KeyLifecycleState.SUSPENDED: frozenset({
        KeyLifecycleState.ACTIVE,
        KeyLifecycleState.RETIRED,
        KeyLifecycleState.REVOKED,
        KeyLifecycleState.HARD_REVOKED,
    }),
    KeyLifecycleState.REVOKED: frozenset({
        KeyLifecycleState.HARD_REVOKED,
    }),
    KeyLifecycleState.HARD_REVOKED: frozenset(),  # terminal
}


@dataclass(frozen=True)
class KeyLifecycleMachine:
    """Validate state transitions and operation permissions for a managed key.

    The machine is stateless: it does not persist the current state. The
    caller (the backend) is responsible for storing and retrieving the
    current state. The machine only validates that a transition or
    operation is allowed given the current state.

    This separation is deliberate: it lets backends store state in any
    system (KMS tags, database rows, config files) without coupling the
    lifecycle rules to a specific storage backend.
    """

    def assert_can_transition(
        self,
        *,
        from_state: KeyLifecycleState | str,
        to_state: KeyLifecycleState | str,
    ) -> None:
        """Raise :class:`KeyLifecycleError` if the transition is not allowed.

        Allowed transitions are defined by :data:`ALLOWED_TRANSITIONS`.
        """
        current = from_state if isinstance(from_state, KeyLifecycleState) else KeyLifecycleState.from_string(from_state)
        target = to_state if isinstance(to_state, KeyLifecycleState) else KeyLifecycleState.from_string(to_state)
        allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
        if target not in allowed:
            raise KeyLifecycleError(
                f"invalid key lifecycle transition: {current.value} -> {target.value}. "
                f"Allowed transitions from {current.value}: "
                f"{sorted(s.value for s in allowed) or '(none — terminal state)'}."
            )

    def can_transition(
        self,
        *,
        from_state: KeyLifecycleState | str,
        to_state: KeyLifecycleState | str,
    ) -> bool:
        """Return True if the transition is allowed (non-raising version)."""
        try:
            self.assert_can_transition(from_state=from_state, to_state=to_state)
            return True
        except KeyLifecycleError:
            return False

    def assert_can_sign(self, state: KeyLifecycleState | str) -> None:
        """Raise :class:`KeyLifecycleError` if the key cannot mint new proofs.

        Only ``active`` keys can sign. This is the invariant that makes
        rotation safe: the moment a key moves to ``retired``, it stops
        minting, even if its material is still available.
        """
        current = state if isinstance(state, KeyLifecycleState) else KeyLifecycleState.from_string(state)
        if current not in SIGN_ALLOWED_STATES:
            raise KeyLifecycleError(
                f"key in state {current.value!r} cannot sign; "
                f"signing requires one of {sorted(s.value for s in SIGN_ALLOWED_STATES)}."
            )

    def assert_can_verify(self, state: KeyLifecycleState | str) -> None:
        """Raise :class:`KeyLifecycleError` if the key cannot verify proofs.

        Verification is allowed for every state except ``hard_revoked``.
        Hard-revoking is the explicit "break historical verifiability"
        action — it should only be used when an external anchor (e.g.,
        a transparency log inclusion proof) proves that historical
        proofs predated the compromise.
        """
        current = state if isinstance(state, KeyLifecycleState) else KeyLifecycleState.from_string(state)
        if current not in VERIFY_ALLOWED_STATES:
            raise KeyLifecycleError(
                f"key in state {current.value!r} cannot verify; "
                f"verification requires one of {sorted(s.value for s in VERIFY_ALLOWED_STATES)}. "
                f"Hard-revocation deliberately breaks historical verifiability."
            )

    def is_terminal(self, state: KeyLifecycleState | str) -> bool:
        """Return True if the state allows no further transitions."""
        current = state if isinstance(state, KeyLifecycleState) else KeyLifecycleState.from_string(state)
        return len(ALLOWED_TRANSITIONS.get(current, frozenset())) == 0


# Module-level singleton for convenience. The machine is stateless so a
# single shared instance is safe.
DEFAULT_MACHINE = KeyLifecycleMachine()
