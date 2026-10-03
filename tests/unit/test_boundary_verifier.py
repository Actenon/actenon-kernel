"""Tests for the Kernel BoundaryVerifier (Phase 1.1).

Covers:
  * Valid proof verifies
  * Missing proof refuses (PROOF_MISSING)
  * Malformed proof refuses (PROOF_INVALID)
  * Replay refuses (REPLAY_DETECTED)
  * Receipt construction
  * Health check
  * Integration: Permit middleware calls Kernel verifier

A "valid proof" here is a genuinely minted, signed PCCB presented with the
exact Action Intent it authorises. Adversarial cases live in
``tests/security/test_boundary_verifier_attacks.py``.
"""

from __future__ import annotations

import json

import pytest

from actenon.boundary import (
    BoundaryVerificationRequest,
    BoundaryVerificationResult,
    BoundaryVerifier,
)
from actenon.proof import PCCBVerifier
from tests.security.helpers import (
    NOW,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)


def _proof_request(*, pccb_id: str = "pccb_security_001", nonce: str = "nonce-security-001", proof_token: str | None = None):
    intent = build_security_intent()
    pccb = mint_security_pccb(intent=intent, pccb_id=pccb_id, nonce=nonce)
    return BoundaryVerificationRequest(
        proof_token=json.dumps(pccb.to_dict()) if proof_token is None else proof_token,
        action_type=intent.action.name,
        action_hash=pccb.action_hash.value,
        audience="service:payment-release-endpoint",
        boundary_id="refund-api",
        target=intent.target.resource_id,
        intent=intent.to_dict(),
        now=NOW,
    )


@pytest.fixture
def verifier():
    return BoundaryVerifier(pccb_verifier=PCCBVerifier(security_signer()))


@pytest.fixture
def valid_request():
    return _proof_request()


# ---------------------------------------------------------------------------
# 1. Valid proof verifies
# ---------------------------------------------------------------------------


def test_valid_proof_verifies(verifier, valid_request):
    result = verifier.verify_boundary(valid_request)
    assert result.valid is True
    assert result.reason == "verified"
    assert result.proof_id == "pccb_security_001"
    assert result.receipt_id is not None


def test_unverifiable_token_does_not_verify(verifier, valid_request):
    from dataclasses import replace

    result = verifier.verify_boundary(
        replace(valid_request, proof_token="valid_proof_token_at_least_16_chars")
    )
    assert result.valid is False
    assert result.refusal_code == "PROOF_INVALID"


def test_unconfigured_verifier_refuses(valid_request):
    result = BoundaryVerifier().verify_boundary(valid_request)
    assert result.valid is False
    assert result.refusal_code == "ISSUER_UNTRUSTED"


# ---------------------------------------------------------------------------
# 2. Missing proof refuses
# ---------------------------------------------------------------------------


def test_missing_proof_refuses(verifier, valid_request):
    request = _proof_request(proof_token="")
    result = verifier.verify_boundary(request)
    assert result.valid is False
    assert result.refusal_code == "PROOF_MISSING"


# ---------------------------------------------------------------------------
# 3. Malformed proof refuses
# ---------------------------------------------------------------------------


def test_malformed_proof_refuses(verifier, valid_request):
    request = _proof_request(proof_token="short")
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
    request1 = _proof_request(pccb_id="pccb_first", nonce="nonce-first")
    request2 = _proof_request(pccb_id="pccb_second", nonce="nonce-second")
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
    assert receipt["action"] == "payment.release"
    assert receipt["outcome"] == "succeeded"
    assert receipt["execution_mode"] == "resource_owned"
    assert receipt["proof_id"] == result.proof_id


# ---------------------------------------------------------------------------
# 7. Health check
# ---------------------------------------------------------------------------


def test_health_check(verifier):
    health = verifier.health()
    assert health["ok"] is True
    assert health["pccb_verifier_configured"] is True
    assert "replay_keys_tracked" in health


def test_health_check_reports_unconfigured_trust_root():
    health = BoundaryVerifier().health()
    assert health["ok"] is False
    assert health["pccb_verifier_configured"] is False


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
