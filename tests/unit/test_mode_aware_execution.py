"""Tests for the Kernel's mode-aware execution result + resource receipt
verifier (Prompt 9).

These tests cover the Kernel layer of the Prompt-9 spec:

  * ModeAwareExecutionResult wraps the Protocol-level discriminated
    union with Kernel-specific metadata (PCCB id, action hash, verifier
    identity).
  * ResourceReceiptVerifier cryptographically verifies resource
    receipts. Forged receipts are rejected; the execution result is
    forced to outcome_unknown, never succeeded.
  * BrokeredStateMachine and ResourceOwnedStateMachine validate
    per-mode transitions.
  * build_brokered_result / build_resource_owned_result enforce the
    hard rules from the Protocol layer and add Kernel verification.

The Protocol-layer invariants (brokered succeeded requires observation,
resource_owned succeeded requires verified receipt, etc.) are tested in
the Protocol conformance suite. These Kernel tests focus on the
Kernel-specific behaviour: state transitions, receipt verification, and
the wrapper.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from actenon.execution import (
    BROKERED_TRANSITIONS,
    BrokeredStateMachine,
    ModeAwareExecutionResult,
    ResourceOwnedStateMachine,
    ResourceReceiptVerificationError,
    ResourceReceiptVerifier,
    ResourceSigningKey,
    StateTransitionError,
    build_brokered_result,
    build_resource_owned_result,
)
from actenon_protocol.execution_results import (
    BrokeredExecutionState,
    FinalityStatus,
    ResourceOwnedExecutionState,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def verifier_with_key() -> tuple[ResourceReceiptVerifier, ResourceSigningKey]:
    key = ResourceSigningKey(
        resource_id="stripe",
        key_id="stripe-key-1",
        secret=b"test-secret-key-not-real",
    )
    v = ResourceReceiptVerifier()
    v.register_key(key)
    return v, key


def _sign_receipt(body: dict, secret: bytes) -> str:
    """Helper: produce a valid HMAC-SHA256 signature for a receipt body."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# 1. ModeAwareExecutionResult wrapper
# ---------------------------------------------------------------------------


def test_mode_aware_result_preserves_mode_and_state():
    r = build_brokered_result(
        state=BrokeredExecutionState.SUCCEEDED,
        verified_by="actenon-permit-broker",
        executed_by="actenon-permit-broker",
        attempt_id="exec_abc",
        occurred_at="2026-07-22T10:00:00Z",
        provider_execution_observed=True,
        receipt_received=True,
        receipt_verified=True,
        pccb_id="pccb_abc",
        action_hash="abc123" * 10,
        kernel_verifier_identity="actenon-kernel-v1",
    )
    assert isinstance(r, ModeAwareExecutionResult)
    assert r.mode == "brokered"
    assert r.state == "succeeded"
    assert r.finality == FinalityStatus.FINAL
    assert r.is_final is True
    assert r.pccb_id == "pccb_abc"
    d = r.to_dict()
    assert d["mode"] == "brokered"
    assert d["pccb_id"] == "pccb_abc"
    assert d["kernel_verifier_identity"] == "actenon-kernel-v1"


# ---------------------------------------------------------------------------
# 2. Brokered state machine
# ---------------------------------------------------------------------------


def test_brokered_state_machine_terminal_states_have_no_transitions():
    """succeeded, failed, refused are terminal — no transitions allowed."""
    for terminal in (
        BrokeredExecutionState.SUCCEEDED,
        BrokeredExecutionState.FAILED,
        BrokeredExecutionState.REFUSED,
    ):
        assert BROKERED_TRANSITIONS[terminal] == frozenset()


def test_brokered_state_machine_outcome_unknown_can_resolve():
    """outcome_unknown can transition to succeeded/failed/outcome_unknown."""
    nexts = BROKERED_TRANSITIONS[BrokeredExecutionState.OUTCOME_UNKNOWN]
    assert BrokeredExecutionState.SUCCEEDED in nexts
    assert BrokeredExecutionState.FAILED in nexts
    assert BrokeredExecutionState.OUTCOME_UNKNOWN in nexts
    # cannot go to refused (refused means "never attempted" in brokered)
    assert BrokeredExecutionState.REFUSED not in nexts


def test_brokered_state_machine_rejects_invalid_transition():
    """succeeded -> anything is invalid."""
    with pytest.raises(StateTransitionError):
        BrokeredStateMachine.validate_transition(
            BrokeredExecutionState.SUCCEEDED, BrokeredExecutionState.FAILED
        )


# ---------------------------------------------------------------------------
# 3. Resource-owned state machine
# ---------------------------------------------------------------------------


def test_resource_owned_state_machine_submitted_can_transition_to_accepted():
    """submitted -> accepted is the normal async path."""
    assert ResourceOwnedStateMachine.can_transition(
        ResourceOwnedExecutionState.SUBMITTED, ResourceOwnedExecutionState.ACCEPTED
    )


def test_resource_owned_state_machine_submitted_can_fast_path_to_succeeded():
    """submitted -> succeeded is the fast path (resource completed synchronously
    and returned a verified receipt)."""
    assert ResourceOwnedStateMachine.can_transition(
        ResourceOwnedExecutionState.SUBMITTED, ResourceOwnedExecutionState.SUCCEEDED
    )


def test_resource_owned_state_machine_accepted_cannot_go_back_to_submitted():
    """accepted -> submitted is invalid; you cannot 'unaccept'."""
    assert not ResourceOwnedStateMachine.can_transition(
        ResourceOwnedExecutionState.ACCEPTED, ResourceOwnedExecutionState.SUBMITTED
    )


def test_resource_owned_state_machine_succeeded_is_terminal():
    """succeeded -> anything is invalid."""
    for next_state in ResourceOwnedExecutionState:
        if next_state == ResourceOwnedExecutionState.SUCCEEDED:
            continue
        assert not ResourceOwnedStateMachine.can_transition(
            ResourceOwnedExecutionState.SUCCEEDED, next_state
        )


# ---------------------------------------------------------------------------
# 4. Resource receipt verifier — valid receipt
# ---------------------------------------------------------------------------


def test_resource_receipt_verifier_accepts_valid_signature(verifier_with_key):
    verifier, key = verifier_with_key
    body = {
        "resource_id": "stripe",
        "charge_id": "ch_123",
        "amount": 1000,
        "currency": "usd",
        "signing_key_id": key.key_id,
    }
    receipt = dict(body)
    receipt["signature"] = _sign_receipt(body, key.secret)

    ok, verified_key_id = verifier.verify(receipt)
    assert ok is True
    assert verified_key_id == key.key_id

    # verify_or_raise should not raise
    assert verifier.verify_or_raise(receipt) == key.key_id


# ---------------------------------------------------------------------------
# 5. Resource receipt verifier — forged receipt
# ---------------------------------------------------------------------------


def test_resource_receipt_verifier_rejects_forged_signature(verifier_with_key):
    """A receipt whose signature was computed with the wrong key MUST be
    rejected. The verifier returns (False, None); verify_or_raise raises."""
    verifier, key = verifier_with_key
    body = {
        "resource_id": "stripe",
        "charge_id": "ch_123",
        "amount": 1000,
        "currency": "usd",
        "signing_key_id": key.key_id,
    }
    receipt = dict(body)
    # Sign with the WRONG secret.
    receipt["signature"] = _sign_receipt(body, b"wrong-secret")

    ok, verified_key_id = verifier.verify(receipt)
    assert ok is False
    assert verified_key_id is None

    with pytest.raises(ResourceReceiptVerificationError):
        verifier.verify_or_raise(receipt)


def test_resource_receipt_verifier_rejects_unknown_key_id(verifier_with_key):
    """A receipt signed with a key_id we have no key for MUST be rejected."""
    verifier, _key = verifier_with_key
    body = {
        "resource_id": "stripe",
        "charge_id": "ch_123",
        "amount": 1000,
        "currency": "usd",
        "signing_key_id": "unknown-key-id",
    }
    receipt = dict(body)
    receipt["signature"] = "deadbeef" * 8

    with pytest.raises(ResourceReceiptVerificationError) as exc:
        verifier.verify_or_raise(receipt)
    assert "no key registered" in str(exc.value)


def test_resource_receipt_verifier_rejects_malformed_receipt(verifier_with_key):
    """A receipt missing 'signature' or 'signing_key_id' MUST be rejected."""
    verifier, _key = verifier_with_key

    # Missing signature
    with pytest.raises(ResourceReceiptVerificationError):
        verifier.verify_or_raise({"signing_key_id": "x", "charge_id": "ch_1"})

    # Missing signing_key_id
    with pytest.raises(ResourceReceiptVerificationError):
        verifier.verify_or_raise({"signature": "abc", "charge_id": "ch_1"})

    # Not a dict
    with pytest.raises(ResourceReceiptVerificationError):
        verifier.verify_or_raise("not a dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 6. build_resource_owned_result with verifier
# ---------------------------------------------------------------------------


def test_build_resource_owned_result_with_verified_receipt_succeeds(verifier_with_key):
    """When the resource receipt verifies, the result can be 'succeeded'."""
    verifier, key = verifier_with_key
    body = {
        "resource_id": "stripe",
        "charge_id": "ch_456",
        "amount": 2000,
        "currency": "usd",
        "signing_key_id": key.key_id,
    }
    receipt = dict(body)
    receipt["signature"] = _sign_receipt(body, key.secret)

    r = build_resource_owned_result(
        state=ResourceOwnedExecutionState.SUCCEEDED,
        verified_by="resource-boundary-stripe",
        executed_by="stripe",
        attempt_id="exec_def",
        occurred_at="2026-07-22T10:01:00Z",
        provider_execution_observed=True,
        resource_receipt_received=True,
        resource_receipt=receipt,
        resource_receipt_verifier=verifier,
        submission_reference="sub_1",
    )
    assert r.state == "succeeded"
    assert r.protocol_result.resource_receipt_verified is True
    assert r.resource_signing_key_id == key.key_id
    assert r.is_final is True


def test_build_resource_owned_result_with_forged_receipt_forces_non_success(verifier_with_key):
    """When the resource receipt does NOT verify, 'succeeded' is rejected
    at construction; the caller must build 'outcome_unknown' instead.

    This is the cryptographic boundary: a forged receipt cannot elevate
    the state to succeeded.
    """
    verifier, key = verifier_with_key
    body = {
        "resource_id": "stripe",
        "charge_id": "ch_789",
        "amount": 3000,
        "currency": "usd",
        "signing_key_id": key.key_id,
    }
    receipt = dict(body)
    # Forged signature.
    receipt["signature"] = _sign_receipt(body, b"wrong-secret")

    from actenon_protocol.execution_results import ExecutionResultValidationError

    with pytest.raises(ExecutionResultValidationError):
        build_resource_owned_result(
            state=ResourceOwnedExecutionState.SUCCEEDED,
            verified_by="resource-boundary-stripe",
            executed_by="stripe",
            attempt_id="exec_ghi",
            occurred_at="2026-07-22T10:02:00Z",
            provider_execution_observed=True,
            resource_receipt_received=True,
            resource_receipt=receipt,
            resource_receipt_verifier=verifier,
            submission_reference="sub_2",
        )

    # The caller MUST instead build outcome_unknown:
    r = build_resource_owned_result(
        state=ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
        verified_by="resource-boundary-stripe",
        executed_by="stripe",
        attempt_id="exec_ghi",
        occurred_at="2026-07-22T10:02:00Z",
        provider_execution_observed=True,
        resource_receipt_received=True,
        resource_receipt=receipt,
        resource_receipt_verifier=verifier,
        submission_reference="sub_2",
    )
    assert r.state == "outcome_unknown"
    assert r.protocol_result.resource_receipt_verified is False
    assert r.finality == FinalityStatus.NON_FINAL
    assert r.is_final is False


def test_build_resource_owned_result_submitted_without_receipt_is_non_final():
    """A submitted result with no receipt is non_final. Submission is not execution."""
    r = build_resource_owned_result(
        state=ResourceOwnedExecutionState.SUBMITTED,
        verified_by="resource-boundary-stripe",
        executed_by="stripe",
        attempt_id="exec_jkl",
        occurred_at="2026-07-22T10:03:00Z",
        submission_reference="sub_3",
    )
    assert r.state == "submitted"
    assert r.protocol_result.provider_execution_observed is False
    assert r.protocol_result.resource_receipt_received is False
    assert r.finality == FinalityStatus.NON_FINAL
    assert r.is_final is False


# ---------------------------------------------------------------------------
# 7. Cross-mode isolation
# ---------------------------------------------------------------------------


def test_brokered_result_does_not_carry_resource_owned_fields():
    """A brokered result MUST NOT carry resource_owned-only fields when
    serialised. This is what prevents mode confusion at the API layer."""
    r = build_brokered_result(
        state=BrokeredExecutionState.SUCCEEDED,
        verified_by="b",
        executed_by="b",
        attempt_id="exec_x",
        occurred_at="2026-07-22T10:00:00Z",
        provider_execution_observed=True,
        receipt_received=True,
        receipt_verified=True,
    )
    d = r.to_dict()
    resource_only = {
        "resource_receipt_received",
        "resource_receipt_verified",
        "resource_receipt",
        "submission_reference",
    }
    assert resource_only.isdisjoint(d.keys())


def test_resource_owned_result_does_not_carry_brokered_fields(verifier_with_key):
    """A resource_owned result MUST NOT carry brokered-only fields when
    serialised."""
    verifier, _key = verifier_with_key
    r = build_resource_owned_result(
        state=ResourceOwnedExecutionState.SUBMITTED,
        verified_by="r",
        executed_by="r",
        attempt_id="exec_y",
        occurred_at="2026-07-22T10:00:00Z",
        submission_reference="sub_z",
    )
    d = r.to_dict()
    brokered_only = {
        "receipt_received",
        "receipt_verified",
        "provider_evidence",
        "reconciliation_status",
    }
    assert brokered_only.isdisjoint(d.keys())
