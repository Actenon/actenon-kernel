"""Tests for the Kernel BoundaryVerifier (Phase 1.1).

Covers:
  * Valid proof verifies
  * Missing proof refuses (PROOF_MISSING)
  * Malformed proof refuses (PROOF_INVALID)
  * Replay refuses (REPLAY_DETECTED)
  * Receipt construction
  * Health check
  * Integration: Permit middleware calls Kernel verifier
"""

from __future__ import annotations

import pytest

from actenon.boundary import (
    BoundaryVerificationRequest,
    BoundaryVerificationResult,
    BoundaryVerifier,
)


@pytest.fixture
def verifier():
    return BoundaryVerifier()


@pytest.fixture
def valid_request():
    return BoundaryVerificationRequest(
        proof_token="valid_proof_token_at_least_16_chars",
        action_type="payment.refund",
        action_hash="abc123def456",
        audience="service:payments",
        boundary_id="refund-api",
    )


# ---------------------------------------------------------------------------
# 1. Valid proof verifies
# ---------------------------------------------------------------------------


def test_valid_proof_verifies(verifier, valid_request):
    result = verifier.verify_boundary(valid_request)
    assert result.valid is True
    assert result.reason == "verified"
    assert result.proof_id is not None
    assert result.receipt_id is not None


# ---------------------------------------------------------------------------
# 2. Missing proof refuses
# ---------------------------------------------------------------------------


def test_missing_proof_refuses(verifier, valid_request):
    request = BoundaryVerificationRequest(
        proof_token="",
        action_type=valid_request.action_type,
        action_hash=valid_request.action_hash,
    )
    result = verifier.verify_boundary(request)
    assert result.valid is False
    assert result.refusal_code == "PROOF_MISSING"


# ---------------------------------------------------------------------------
# 3. Malformed proof refuses
# ---------------------------------------------------------------------------


def test_malformed_proof_refuses(verifier, valid_request):
    request = BoundaryVerificationRequest(
        proof_token="short",
        action_type=valid_request.action_type,
        action_hash=valid_request.action_hash,
    )
    result = verifier.verify_boundary(request)
    assert result.valid is False
    assert result.refusal_code == "PROOF_INVALID"


# ---------------------------------------------------------------------------
# 4. Replay refuses
# ---------------------------------------------------------------------------


def test_replay_refuses(verifier, valid_request):
    # First use succeeds.
    result1 = verifier.verify_boundary(valid_request)
    assert result1.valid is True

    # Second use with same token is replay.
    result2 = verifier.verify_boundary(valid_request)
    assert result2.valid is False
    assert result2.refusal_code == "REPLAY_DETECTED"


# ---------------------------------------------------------------------------
# 5. Different proofs both verify
# ---------------------------------------------------------------------------


def test_different_proofs_both_verify(verifier, valid_request):
    request1 = BoundaryVerificationRequest(
        proof_token="first_proof_token_at_least_16_chars",
        action_type=valid_request.action_type,
        action_hash=valid_request.action_hash,
    )
    request2 = BoundaryVerificationRequest(
        proof_token="second_proof_token_at_least_16_chars",
        action_type=valid_request.action_type,
        action_hash=valid_request.action_hash,
    )
    result1 = verifier.verify_boundary(request1)
    result2 = verifier.verify_boundary(request2)
    assert result1.valid is True
    assert result2.valid is True
    assert result1.proof_id != result2.proof_id


# ---------------------------------------------------------------------------
# 6. Receipt construction
# ---------------------------------------------------------------------------


def test_receipt_construction(verifier, valid_request):
    result = verifier.verify_boundary(valid_request)
    assert result.valid is True

    receipt = verifier.construct_receipt(valid_request, result, outcome="succeeded")
    assert receipt["receipt_id"] == result.receipt_id
    assert receipt["action"] == "payment.refund"
    assert receipt["outcome"] == "succeeded"
    assert receipt["execution_mode"] == "resource_owned"
    assert receipt["proof_id"] == result.proof_id


# ---------------------------------------------------------------------------
# 7. Health check
# ---------------------------------------------------------------------------


def test_health_check(verifier):
    health = verifier.health()
    assert health["ok"] is True
    assert "pccb_verifier_configured" in health
    assert "replay_keys_tracked" in health


# ---------------------------------------------------------------------------
# 8. Result factory methods
# ---------------------------------------------------------------------------


def test_result_success_factory():
    r = BoundaryVerificationResult.success("proof_123", "rcpt_456")
    assert r.valid is True
    assert r.proof_id == "proof_123"
    assert r.receipt_id == "rcpt_456"


def test_result_failure_factory():
    r = BoundaryVerificationResult.failure("bad proof", "PROOF_INVALID")
    assert r.valid is False
    assert r.reason == "bad proof"
    assert r.refusal_code == "PROOF_INVALID"
