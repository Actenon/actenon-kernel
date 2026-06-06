from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from actenon.models import (
    ActionIntent,
    ActionSpec,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.preflight import (
    PreflightEngine,
    PreflightEvidence,
    build_payments_policy_pack,
)
from actenon.proof import build_action_hash_input, canonicalize_bytes, sha256_hex
from actenon.verifier import TrustArtifactVerificationError

NOW = datetime(2026, 6, 6, 12, 0, tzinfo=UTC)


def _intent(amount_minor: int = 500_000) -> ActionIntent:
    return ActionIntent(
        intent_id="intent_signed_approval",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
        tenant=TenantRef("tenant-public-test"),
        requester=PartyRef(type="service", id="payment-agent"),
        action=ActionSpec(
            name="payment.transfer",
            capability="payment.transfer",
            parameters={"amount_minor": amount_minor},
        ),
        target=TargetRef(
            resource_type="payment_destination",
            resource_id="destination-approved",
        ),
    )


def _approval_fixture(intent: ActionIntent) -> tuple[dict, dict]:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    approver = {"type": "user", "id": "finance-reviewer"}
    action_hash = {
        "algorithm": "sha-256",
        "canonicalization": "RFC8785-JCS",
        "value": sha256_hex(build_action_hash_input(intent)),
    }
    statement = {
        "context": "actenon.approval-artifact.v1",
        "approval_id": "approval-signed-001",
        "approver": approver,
        "approval_type": "finance_approver",
        "decision": "approved",
        "action_hash": action_hash,
        "issued_at": "2026-06-06T12:00:00Z",
    }
    artifact = {
        "contract": {"name": "approval_artifact", "version": "v1"},
        **{key: value for key, value in statement.items() if key != "context"},
        "signature": {
            "algorithm": "EdDSA",
            "key_id": "finance-reviewer-2026",
            "encoding": "base64url",
            "value": base64.urlsafe_b64encode(
                private_key.sign(canonicalize_bytes(statement))
            )
            .decode("ascii")
            .rstrip("="),
        },
    }
    trusted_keys = {
        "contract": {"name": "key_discovery", "version": "v1"},
        "issuer": approver,
        "keys": [
            {
                "key_id": "finance-reviewer-2026",
                "algorithm": "EdDSA",
                "use": "approval_artifact",
                "status": "active",
                "not_before": "2026-01-01T00:00:00Z",
                "expires_at": "2027-01-01T00:00:00Z",
                "public_key_jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "finance-reviewer-2026",
                    "alg": "EdDSA",
                    "use": "sig",
                    "x": base64.urlsafe_b64encode(public_key)
                    .decode("ascii")
                    .rstrip("="),
                },
            }
        ],
    }
    return artifact, trusted_keys


def test_verified_approval_satisfies_preflight_without_caller_assertion() -> None:
    intent = _intent()
    approval, trusted_keys = _approval_fixture(intent)
    engine = PreflightEngine(build_payments_policy_pack())

    refused = engine.check(intent)
    allowed = engine.check(
        intent,
        evidence_context=PreflightEvidence(
            approval_artifacts=(approval,),
            approval_trusted_keys=(trusted_keys,),
        ),
    )

    assert refused.reason_code == "PREFLIGHT_PAYMENT_APPROVAL_REQUIRED"
    assert allowed.outcome == "allow"


def test_forged_or_different_action_approval_fails_closed() -> None:
    approved_intent = _intent()
    approval, trusted_keys = _approval_fixture(approved_intent)
    different_intent = _intent(amount_minor=900_000)
    engine = PreflightEngine(build_payments_policy_pack())

    with pytest.raises(
        TrustArtifactVerificationError,
        match="APPROVAL_ACTION_MISMATCH",
    ):
        engine.check(
            different_intent,
            evidence_context={
                "approval_artifacts": [approval],
                "approval_trusted_keys": [trusted_keys],
            },
        )

    forged = {**approval, "approval_type": "security_admin"}
    with pytest.raises(
        TrustArtifactVerificationError,
        match="SIGNATURE_INVALID",
    ):
        engine.check(
            approved_intent,
            evidence_context={
                "approval_artifacts": [forged],
                "approval_trusted_keys": [trusted_keys],
            },
        )


def test_legacy_caller_asserted_approval_remains_available() -> None:
    decision = PreflightEngine(build_payments_policy_pack()).check(
        _intent(),
        evidence_context={
            "approval_present": True,
            "approver_types": ["finance_approver"],
        },
    )
    assert decision.outcome == "allow"
