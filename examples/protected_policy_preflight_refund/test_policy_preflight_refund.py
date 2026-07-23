import pytest

from examples.protected_policy_preflight_refund.policy_preflight_refund import (
    RefundLedger,
    build_refund_action,
    refund_preflight_policy,
)
from actenon import ActenonGate


def outcome_allowed(outcome):
    if hasattr(outcome, "allowed"):
        return bool(outcome.allowed)
    if isinstance(outcome, dict) and "allowed" in outcome:
        return bool(outcome["allowed"])
    return False


def test_positive_refund_preflight_mints_and_executes():
    gate = ActenonGate.local_dev(audience="service:refunds")
    ledger = RefundLedger()

    action = build_refund_action(gate, "ord-123", 2500)
    proof = gate.mint_proof_after_preflight(action, refund_preflight_policy)

    gate.protect(
        action,
        proof,
        lambda: ledger.issue_refund("ord-123", 2500),
        audience="service:refunds",
    )

    assert ledger.events == [{"order_id": "ord-123", "amount_cents": 2500}]


def test_negative_refund_is_denied_before_proof_issuance():
    gate = ActenonGate.local_dev(audience="service:refunds")
    ledger = RefundLedger()

    action = build_refund_action(gate, "ord-123", -2500)

    with pytest.raises(PermissionError, match="PREFLIGHT_POLICY_DENIED"):
        gate.mint_proof_after_preflight(action, refund_preflight_policy)

    assert ledger.events == []


def test_excessive_refund_is_denied_before_proof_issuance():
    gate = ActenonGate.local_dev(audience="service:refunds")
    ledger = RefundLedger()

    action = build_refund_action(gate, "ord-123", 500001)

    with pytest.raises(PermissionError, match="PREFLIGHT_POLICY_DENIED"):
        gate.mint_proof_after_preflight(action, refund_preflight_policy)

    assert ledger.events == []


def test_proof_for_small_refund_cannot_be_reused_for_larger_refund():
    gate = ActenonGate.local_dev(audience="service:refunds")
    ledger = RefundLedger()

    approved = build_refund_action(gate, "ord-123", 2500)
    proof = gate.mint_proof_after_preflight(approved, refund_preflight_policy)

    tampered = build_refund_action(gate, "ord-123", 250000)
    outcome = gate.protect(
        tampered,
        proof,
        lambda: ledger.issue_refund("ord-123", 250000),
        audience="service:refunds",
    )

    assert not outcome_allowed(outcome)
    assert ledger.events == []
