"""Mode-aware execution results + resource receipt verification.

This module is the Kernel's contribution to the Prompt-9 execution-mode
formalisation. It provides:

  * ``ModeAwareExecutionResult`` — a Kernel-side wrapper around the
    Protocol-level discriminated union
    (``actenon_protocol.execution_results.ExecutionResult``). It carries
    the Kernel-specific metadata (PCCB id, action hash, verifier
    identity) that the Protocol model deliberately leaves out.

  * ``ResourceReceiptVerifier`` — cryptographically verifies resource
    receipts returned by resource boundaries in ``resource_owned``
    mode. A receipt whose signature does not verify against the
    resource's published signing key is rejected; the execution
    result is forced to ``outcome_unknown`` (never ``succeeded``).

  * ``BrokeredStateMachine`` / ``ResourceOwnedStateMachine`` —
    validate state transitions per the per-mode rules. The Protocol
    package enforces the *invariants* on a single result; the Kernel
    state machines enforce the *transitions* between results.

The Kernel is the verifier authority: it does not issue results, it
verifies them. A result constructed by Permit (brokered) or by a
resource boundary (resource_owned) is brought to the Kernel for
verification before it is written to the durable ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

from actenon_protocol.execution_results import (
    BrokeredExecutionResult,
    BrokeredExecutionState,
    FinalityStatus,
    ResourceOwnedExecutionResult,
    ResourceOwnedExecutionState,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ResourceReceiptVerificationError(RuntimeError):
    """Raised when a resource receipt fails cryptographic verification.

    The error message MUST NOT contain the receipt's claimed signature
    value (it may be a forged attempt to scrape key material). It only
    names the failure mode.
    """

    def __init__(self, reason: str, *, receipt_issuer: str | None = None):
        super().__init__(f"resource receipt verification failed: {reason}")
        self.reason = reason
        self.receipt_issuer = receipt_issuer


class StateTransitionError(ValueError):
    """Raised when a state transition violates the per-mode state machine."""


# ---------------------------------------------------------------------------
# Mode-aware result wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModeAwareExecutionResult:
    """Kernel-side wrapper around the Protocol-level ExecutionResult.

    Carries Kernel-specific metadata that the Protocol model deliberately
    leaves out (PCCB id, action hash, verifier identity). The Protocol
    result is the canonical cross-repo shape; this wrapper is what the
    Kernel stores in its ledger and what the Kernel's verifier produces
    when it signs off on a result.
    """

    protocol_result: BrokeredExecutionResult | ResourceOwnedExecutionResult
    pccb_id: str | None = None
    action_hash: str | None = None
    kernel_verifier_identity: str | None = None
    resource_signing_key_id: str | None = None  # set when resource_receipt_verified=True

    @property
    def mode(self) -> str:
        return self.protocol_result.mode

    @property
    def state(self) -> str:
        return self.protocol_result.state.value

    @property
    def finality(self) -> FinalityStatus:
        return self.protocol_result.finality

    @property
    def is_final(self) -> bool:
        return self.finality == FinalityStatus.FINAL

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict for ledger persistence."""
        from actenon_protocol.execution_results import serialise_result

        out = serialise_result(self.protocol_result)
        out["pccb_id"] = self.pccb_id
        out["action_hash"] = self.action_hash
        out["kernel_verifier_identity"] = self.kernel_verifier_identity
        out["resource_signing_key_id"] = self.resource_signing_key_id
        return out


# ---------------------------------------------------------------------------
# Resource receipt verifier
# ---------------------------------------------------------------------------


@dataclass
class ResourceSigningKey:
    """A published signing key for a resource boundary.

    The Kernel uses this to verify resource receipts. The key is
    identified by ``key_id`` (stable across rotations) and is
    expected to be published out-of-band (e.g. via a JWKS endpoint,
    a transparency log, or a pinned config).
    """

    resource_id: str
    key_id: str
    secret: bytes  # HMAC key. For asymmetric signing, future versions will add public_key.


@dataclass
class ResourceReceiptVerifier:
    """Verifies resource receipts returned by resource boundaries.

    A resource receipt is a JSON payload signed by the resource using
    HMAC-SHA256 over the canonical JSON of the receipt body. The
    verifier re-computes the HMAC and compares in constant time.

    If verification fails, the caller MUST treat the execution as
    ``outcome_unknown`` — never as ``succeeded``. This is the
    cryptographic boundary that prevents forged receipts from
    elevating the state.
    """

    keys: dict[str, ResourceSigningKey] = field(default_factory=dict)

    def register_key(self, key: ResourceSigningKey) -> None:
        self.keys[key.key_id] = key

    def verify(self, receipt: dict[str, Any]) -> tuple[bool, str | None]:
        """Verify a resource receipt.

        Returns ``(verified, key_id)``. ``verified`` is True iff the
        receipt's signature matches the canonical body using one of
        the registered keys. ``key_id`` is the key that verified it
        (or None if verification failed).

        Raises ``ResourceReceiptVerificationError`` if the receipt
        is malformed (no signature, no key_id, no body).
        """
        if not isinstance(receipt, dict):
            raise ResourceReceiptVerificationError("receipt is not a dict")
        signature = receipt.get("signature")
        key_id = receipt.get("signing_key_id")
        if not signature or not isinstance(signature, str):
            raise ResourceReceiptVerificationError("receipt missing 'signature' field")
        if not key_id or not isinstance(key_id, str):
            raise ResourceReceiptVerificationError("receipt missing 'signing_key_id' field")
        key = self.keys.get(key_id)
        if key is None:
            raise ResourceReceiptVerificationError(
                f"no key registered for key_id {key_id!r}",
                receipt_issuer=key_id,
            )
        # Canonicalise the body (everything except signature) and re-compute.
        body = {k: v for k, v in receipt.items() if k != "signature"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        expected = hmac.new(key.secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False, None
        return True, key_id

    def verify_or_raise(self, receipt: dict[str, Any]) -> str:
        """Verify and return the key_id, or raise ``ResourceReceiptVerificationError``."""
        ok, key_id = self.verify(receipt)
        if not ok:
            raise ResourceReceiptVerificationError(
                "signature mismatch", receipt_issuer=receipt.get("signing_key_id")
            )
        return key_id  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# State machines
# ---------------------------------------------------------------------------


# Brokered transitions: any state can transition to outcome_unknown
# (timeout, partial response) and from there back to succeeded/failed
# via reconciliation. refused is terminal.
BROKERED_TRANSITIONS: dict[BrokeredExecutionState, frozenset[BrokeredExecutionState]] = {
    BrokeredExecutionState.SUCCEEDED: frozenset(),  # terminal
    BrokeredExecutionState.FAILED: frozenset(),  # terminal
    BrokeredExecutionState.REFUSED: frozenset(),  # terminal
    BrokeredExecutionState.OUTCOME_UNKNOWN: frozenset({
        BrokeredExecutionState.SUCCEEDED,
        BrokeredExecutionState.FAILED,
        BrokeredExecutionState.OUTCOME_UNKNOWN,  # still unknown after reconcile
    }),
}

# Resource-owned transitions: submitted -> accepted/refused/outcome_unknown;
# accepted -> succeeded/failed/outcome_unknown; refused is terminal.
RESOURCE_OWNED_TRANSITIONS: dict[ResourceOwnedExecutionState, frozenset[ResourceOwnedExecutionState]] = {
    ResourceOwnedExecutionState.SUBMITTED: frozenset({
        ResourceOwnedExecutionState.ACCEPTED,
        ResourceOwnedExecutionState.REFUSED,
        ResourceOwnedExecutionState.SUCCEEDED,  # fast path: resource completes synchronously
        ResourceOwnedExecutionState.FAILED,
        ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
    }),
    ResourceOwnedExecutionState.ACCEPTED: frozenset({
        ResourceOwnedExecutionState.SUCCEEDED,
        ResourceOwnedExecutionState.FAILED,
        ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
    }),
    ResourceOwnedExecutionState.REFUSED: frozenset(),  # terminal
    ResourceOwnedExecutionState.SUCCEEDED: frozenset(),  # terminal
    ResourceOwnedExecutionState.FAILED: frozenset(),  # terminal
    ResourceOwnedExecutionState.OUTCOME_UNKNOWN: frozenset({
        ResourceOwnedExecutionState.SUCCEEDED,
        ResourceOwnedExecutionState.FAILED,
        ResourceOwnedExecutionState.OUTCOME_UNKNOWN,  # still unknown
    }),
}


class BrokeredStateMachine:
    """Validates transitions between brokered execution states."""

    @staticmethod
    def can_transition(current: BrokeredExecutionState, next_: BrokeredExecutionState) -> bool:
        return next_ in BROKERED_TRANSITIONS[current]

    @staticmethod
    def validate_transition(current: BrokeredExecutionState, next_: BrokeredExecutionState) -> None:
        if not BrokeredStateMachine.can_transition(current, next_):
            raise StateTransitionError(
                f"brokered state transition not allowed: {current.value!r} -> {next_.value!r}"
            )


class ResourceOwnedStateMachine:
    """Validates transitions between resource-owned execution states.

    Enforces the rule that ``submitted`` cannot transition directly to
    ``succeeded`` without going through ``accepted`` UNLESS the
    resource completed synchronously (returned a verified receipt in
    the same response). The state machine permits the fast path; the
    caller is responsible for only using it when a verified receipt
    is in hand.
    """

    @staticmethod
    def can_transition(current: ResourceOwnedExecutionState, next_: ResourceOwnedExecutionState) -> bool:
        return next_ in RESOURCE_OWNED_TRANSITIONS[current]

    @staticmethod
    def validate_transition(current: ResourceOwnedExecutionState, next_: ResourceOwnedExecutionState) -> None:
        if not ResourceOwnedStateMachine.can_transition(current, next_):
            raise StateTransitionError(
                f"resource_owned state transition not allowed: {current.value!r} -> {next_.value!r}"
            )


# ---------------------------------------------------------------------------
# Result builders (helpers that combine Protocol result + Kernel verification)
# ---------------------------------------------------------------------------


def build_brokered_result(
    *,
    state: BrokeredExecutionState,
    verified_by: str,
    executed_by: str,
    attempt_id: str,
    occurred_at: str,
    provider_execution_observed: bool,
    receipt_received: bool = False,
    receipt_verified: bool = False,
    provider_evidence: dict | None = None,
    reconciliation_status: str | None = None,
    pccb_id: str | None = None,
    action_hash: str | None = None,
    kernel_verifier_identity: str | None = None,
) -> ModeAwareExecutionResult:
    """Build a Kernel-verified brokered result.

    Raises ``ExecutionResultValidationError`` if the hard rules are
    violated (e.g. ``succeeded`` without ``provider_execution_observed``).
    """
    protocol_result = BrokeredExecutionResult(
        state=state,
        verified_by=verified_by,
        executed_by=executed_by,
        provider_execution_observed=provider_execution_observed,
        attempt_id=attempt_id,
        occurred_at=occurred_at,
        receipt_received=receipt_received,
        receipt_verified=receipt_verified,
        provider_evidence=provider_evidence or {},
        reconciliation_status=reconciliation_status,
    )
    return ModeAwareExecutionResult(
        protocol_result=protocol_result,
        pccb_id=pccb_id,
        action_hash=action_hash,
        kernel_verifier_identity=kernel_verifier_identity,
    )


def build_resource_owned_result(
    *,
    state: ResourceOwnedExecutionState,
    verified_by: str,
    executed_by: str,
    attempt_id: str,
    occurred_at: str,
    provider_execution_observed: bool = False,
    resource_receipt_received: bool = False,
    resource_receipt: dict | None = None,
    resource_receipt_verifier: ResourceReceiptVerifier | None = None,
    submission_reference: str | None = None,
    pccb_id: str | None = None,
    action_hash: str | None = None,
    kernel_verifier_identity: str | None = None,
) -> ModeAwareExecutionResult:
    """Build a Kernel-verified resource-owned result.

    If ``resource_receipt`` is provided and ``resource_receipt_verifier``
    is non-None, the receipt is cryptographically verified. The result's
    ``resource_receipt_verified`` field reflects the verification
    outcome.

    Hard rule: if ``state == SUCCEEDED`` and the receipt does not
    verify, this function raises ``ExecutionResultValidationError``
    (which prevents the succeeded state from being constructed). The
    caller MUST instead build an ``outcome_unknown`` result.
    """
    resource_receipt_verified = False
    resource_signing_key_id: str | None = None
    if resource_receipt is not None and resource_receipt_verifier is not None:
        try:
            resource_signing_key_id = resource_receipt_verifier.verify_or_raise(resource_receipt)
            resource_receipt_verified = True
        except ResourceReceiptVerificationError:
            resource_receipt_verified = False
    elif resource_receipt is not None and resource_receipt_verifier is None:
        # Caller passed a receipt but no verifier — we cannot verify it.
        # Treat as unverified.
        resource_receipt_verified = False

    protocol_result = ResourceOwnedExecutionResult(
        state=state,
        verified_by=verified_by,
        executed_by=executed_by,
        attempt_id=attempt_id,
        occurred_at=occurred_at,
        provider_execution_observed=provider_execution_observed,
        resource_receipt_received=resource_receipt_received,
        resource_receipt_verified=resource_receipt_verified,
        resource_receipt=resource_receipt,
        submission_reference=submission_reference,
    )
    return ModeAwareExecutionResult(
        protocol_result=protocol_result,
        pccb_id=pccb_id,
        action_hash=action_hash,
        kernel_verifier_identity=kernel_verifier_identity,
        resource_signing_key_id=resource_signing_key_id,
    )


__all__ = [
    "BROKERED_TRANSITIONS",
    "BrokeredStateMachine",
    "ModeAwareExecutionResult",
    "RESOURCE_OWNED_TRANSITIONS",
    "ResourceOwnedStateMachine",
    "ResourceReceiptVerificationError",
    "ResourceReceiptVerifier",
    "ResourceSigningKey",
    "StateTransitionError",
    "build_brokered_result",
    "build_resource_owned_result",
]
