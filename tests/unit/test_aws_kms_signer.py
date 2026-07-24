"""Tests for the AWS KMS signing backend and key-lifecycle state machine.

These tests exercise:
  - the key-lifecycle state machine (transitions, sign/verify permissions)
  - the AWS KMS backend with a mock KMS client
  - lifecycle enforcement (revoked/suspended/retired refuse to sign)
  - hard_revoked refuses to verify
  - algorithm and key_id round-trip
  - rotation: new key active, old key retired but still verifies

The tests do NOT call real AWS KMS. The backend is designed to accept
any kms_client that quacks like boto3's KMS client; tests pass a mock.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from actenon.proof.signers.aws_kms import (
    AWS_KMS_ALGORITHMS,
    AWS_KMS_KEY_STATE_MAP,
    AwsKmsSigningBackend,
)
from actenon.proof.signers.external_managed import (
    ACTIVE_KEY_STATUS,
    ExternalManagedSigningError,
    ManagedKeyReference,
    PROOF_ISSUANCE_PURPOSE,
)
from actenon.proof.signers.key_lifecycle import (
    ALLOWED_TRANSITIONS,
    DEFAULT_MACHINE,
    KeyLifecycleError,
    KeyLifecycleMachine,
    KeyLifecycleState,
    SIGN_ALLOWED_STATES,
    VERIFY_ALLOWED_STATES,
)


# ---------------------------------------------------------------------------
# Key lifecycle state machine tests
# ---------------------------------------------------------------------------


class TestKeyLifecycleStateMachine(unittest.TestCase):
    """Tests for the key-lifecycle state machine (key_lifecycle.py)."""

    def test_five_states_exist(self):
        self.assertEqual(
            {s.value for s in KeyLifecycleState},
            {"active", "retired", "suspended", "revoked", "hard_revoked"},
        )

    def test_from_string_round_trip(self):
        for state in KeyLifecycleState:
            self.assertEqual(KeyLifecycleState.from_string(state.value), state)
            self.assertEqual(KeyLifecycleState.from_string(state.value.upper()), state)

    def test_from_string_rejects_unknown(self):
        with self.assertRaises(KeyLifecycleError) as ctx:
            KeyLifecycleState.from_string("garbage")
        self.assertIn("unknown key lifecycle state", str(ctx.exception))

    def test_only_active_can_sign(self):
        self.assertEqual(SIGN_ALLOWED_STATES, {KeyLifecycleState.ACTIVE})

    def test_hard_revoked_cannot_verify(self):
        # Everything except hard_revoked can verify.
        self.assertNotIn(KeyLifecycleState.HARD_REVOKED, VERIFY_ALLOWED_STATES)
        self.assertIn(KeyLifecycleState.ACTIVE, VERIFY_ALLOWED_STATES)
        self.assertIn(KeyLifecycleState.RETIRED, VERIFY_ALLOWED_STATES)
        self.assertIn(KeyLifecycleState.SUSPENDED, VERIFY_ALLOWED_STATES)
        self.assertIn(KeyLifecycleState.REVOKED, VERIFY_ALLOWED_STATES)

    def test_active_can_transition_to_all_other_states(self):
        for target in [KeyLifecycleState.RETIRED, KeyLifecycleState.SUSPENDED,
                       KeyLifecycleState.REVOKED, KeyLifecycleState.HARD_REVOKED]:
            self.assertTrue(
                DEFAULT_MACHINE.can_transition(
                    from_state=KeyLifecycleState.ACTIVE, to_state=target
                ),
                f"active should be able to transition to {target.value}",
            )

    def test_retired_cannot_transition_back_to_active(self):
        """Re-activating a retired key risks proof-of-stale-key.

        If you need a key back in active rotation, mint a NEW key with
        a new key_id instead.
        """
        self.assertFalse(
            DEFAULT_MACHINE.can_transition(
                from_state=KeyLifecycleState.RETIRED, to_state=KeyLifecycleState.ACTIVE
            ),
            "retired -> active is forbidden (proof-of-stale-key risk)",
        )

    def test_revoked_can_only_escalate_to_hard_revoked(self):
        """Revocation is permanent; the only transition is escalation."""
        allowed = ALLOWED_TRANSITIONS[KeyLifecycleState.REVOKED]
        self.assertEqual(allowed, {KeyLifecycleState.HARD_REVOKED})

    def test_hard_revoked_is_terminal(self):
        """No transitions out of hard_revoked."""
        self.assertEqual(ALLOWED_TRANSITIONS[KeyLifecycleState.HARD_REVOKED], frozenset())
        self.assertTrue(DEFAULT_MACHINE.is_terminal(KeyLifecycleState.HARD_REVOKED))

    def test_suspended_can_return_to_active(self):
        """Suspended is the only non-active state that can return to active."""
        self.assertTrue(
            DEFAULT_MACHINE.can_transition(
                from_state=KeyLifecycleState.SUSPENDED, to_state=KeyLifecycleState.ACTIVE
            ),
            "suspended -> active should be allowed (investigation cleared)",
        )

    def test_assert_can_sign_active_passes(self):
        DEFAULT_MACHINE.assert_can_sign(KeyLifecycleState.ACTIVE)  # no exception

    def test_assert_can_sign_retired_fails(self):
        with self.assertRaises(KeyLifecycleError) as ctx:
            DEFAULT_MACHINE.assert_can_sign(KeyLifecycleState.RETIRED)
        self.assertIn("cannot sign", str(ctx.exception))

    def test_assert_can_sign_revoked_fails(self):
        with self.assertRaises(KeyLifecycleError):
            DEFAULT_MACHINE.assert_can_sign(KeyLifecycleState.REVOKED)

    def test_assert_can_verify_hard_revoked_fails(self):
        with self.assertRaises(KeyLifecycleError) as ctx:
            DEFAULT_MACHINE.assert_can_verify(KeyLifecycleState.HARD_REVOKED)
        self.assertIn("cannot verify", str(ctx.exception))
        self.assertIn("Hard-revocation", str(ctx.exception))

    def test_assert_can_verify_revoked_passes(self):
        """Revoked keys still verify — historical verifiability."""
        DEFAULT_MACHINE.assert_can_verify(KeyLifecycleState.REVOKED)  # no exception

    def test_assert_can_verify_retired_passes(self):
        DEFAULT_MACHINE.assert_can_verify(KeyLifecycleState.RETIRED)  # no exception

    def test_invalid_transition_raises(self):
        with self.assertRaises(KeyLifecycleError) as ctx:
            DEFAULT_MACHINE.assert_can_transition(
                from_state=KeyLifecycleState.HARD_REVOKED,
                to_state=KeyLifecycleState.ACTIVE,
            )
        self.assertIn("invalid key lifecycle transition", str(ctx.exception))
        self.assertIn("terminal", str(ctx.exception))

    def test_machine_is_stateless(self):
        """The machine is stateless — same instance reusable across calls."""
        m1 = KeyLifecycleMachine()
        m2 = KeyLifecycleMachine()
        # Both should give the same answer; neither should remember state.
        m1.assert_can_sign(KeyLifecycleState.ACTIVE)
        m2.assert_can_sign(KeyLifecycleState.ACTIVE)
        with self.assertRaises(KeyLifecycleError):
            m1.assert_can_sign(KeyLifecycleState.RETIRED)
        with self.assertRaises(KeyLifecycleError):
            m2.assert_can_sign(KeyLifecycleState.RETIRED)


# ---------------------------------------------------------------------------
# AWS KMS backend tests (with mock KMS client)
# ---------------------------------------------------------------------------


def _make_key(
    *,
    status: str = ACTIVE_KEY_STATUS,
    algorithm: str = "EdDSA",
    key_id: str = "issuer:prod:2026-07",
    provider_key_ref: str = "arn:aws:kms:eu-west-2:123456789012:key/abcd-1234",
) -> ManagedKeyReference:
    return ManagedKeyReference(
        provider="aws-kms",
        provider_key_ref=provider_key_ref,
        key_id=key_id,
        algorithm=algorithm,
        purpose=PROOF_ISSUANCE_PURPOSE,
        tenant_id="tenant-acme",
        public_key_ref=f"aws-kms://{provider_key_ref}",
        key_version="2026-07",
        status=status,
    )


def _make_mock_kms_client(
    *,
    aws_key_state: str = "Enabled",
    signature: bytes = b"fake-signature-bytes",
    signature_valid: bool = True,
) -> MagicMock:
    """Build a mock KMS client that mimics boto3's KMS client shape."""
    client = MagicMock()
    client.describe_key.return_value = {
        "KeyMetadata": {"KeyState": aws_key_state}
    }
    client.sign.return_value = {
        "Signature": signature,
        "SigningAlgorithm": "EdDSA",
    }
    client.verify.return_value = {
        "SignatureValid": signature_valid
    }
    return client


class TestAwsKmsBackend(unittest.TestCase):
    """Tests for the AWS KMS backend (aws_kms.py)."""

    def test_get_key_status_returns_active_when_aws_enabled(self):
        client = _make_mock_kms_client(aws_key_state="Enabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")
        self.assertEqual(backend.get_key_status(key=key), "active")

    def test_get_key_status_returns_suspended_when_aws_disabled(self):
        """AWS Disabled maps to Actenon suspended."""
        client = _make_mock_kms_client(aws_key_state="Disabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")  # operator says active, AWS says disabled
        self.assertEqual(backend.get_key_status(key=key), "suspended")

    def test_get_key_status_more_restrictive_wins(self):
        """When operator and AWS disagree, the more restrictive state wins."""
        client = _make_mock_kms_client(aws_key_state="PendingDeletion")
        backend = AwsKmsSigningBackend(kms_client=client)
        # Operator says retired (restrictiveness 1), AWS says revoked (3).
        # Revoked should win.
        key = _make_key(status="retired")
        self.assertEqual(backend.get_key_status(key=key), "revoked")

    def test_get_key_status_hard_revoked_always_wins(self):
        """Operator hard_revoked is the most restrictive — always wins."""
        client = _make_mock_kms_client(aws_key_state="Enabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="hard_revoked")
        self.assertEqual(backend.get_key_status(key=key), "hard_revoked")

    def test_get_key_status_fails_on_unknown_aws_state(self):
        client = _make_mock_kms_client(aws_key_state="SomeNewAWSState")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")
        with self.assertRaises(ExternalManagedSigningError) as ctx:
            backend.get_key_status(key=key)
        self.assertIn("unknown AWS KMS key state", str(ctx.exception))

    def test_get_key_status_fails_when_describe_key_raises(self):
        client = MagicMock()
        client.describe_key.side_effect = RuntimeError("network error")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")
        with self.assertRaises(ExternalManagedSigningError) as ctx:
            backend.get_key_status(key=key)
        self.assertIn("failed to describe KMS key", str(ctx.exception))

    def test_sign_happy_path(self):
        payload = b'{"action":"payment.refund","amount":2500}'
        client = _make_mock_kms_client(signature=b"sig-bytes")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active", algorithm="EdDSA")
        result = backend.sign_canonical_bytes(
            key=key,
            payload=payload,
            audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
        )
        self.assertEqual(result.algorithm, "EdDSA")
        self.assertEqual(result.key_id, "issuer:prod:2026-07")
        self.assertEqual(result.signature, b"sig-bytes")
        self.assertEqual(result.public_key_ref, "aws-kms://arn:aws:kms:eu-west-2:123456789012:key/abcd-1234")
        # The provider operation ID is deterministic (sha256 prefix of signature)
        self.assertTrue(result.provider_operation_id.startswith("aws-kms-sign-"))

        # Verify the KMS Sign API was called correctly.
        client.sign.assert_called_once()
        call_kwargs = client.sign.call_args.kwargs
        self.assertEqual(call_kwargs["KeyId"], key.provider_key_ref)
        self.assertEqual(call_kwargs["Message"], payload)
        self.assertEqual(call_kwargs["MessageType"], "RAW")
        self.assertEqual(call_kwargs["SigningAlgorithm"], "EdDSA")

    def test_sign_revoked_refuses(self):
        """A revoked key MUST NOT sign. This is the universal gate."""
        client = _make_mock_kms_client(aws_key_state="Enabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="revoked")
        with self.assertRaises(ExternalManagedSigningError) as ctx:
            backend.sign_canonical_bytes(
                key=key,
                payload=b"test",
                audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
            )
        self.assertIn("cannot sign", str(ctx.exception))
        # KMS Sign API MUST NOT have been called.
        client.sign.assert_not_called()

    def test_sign_suspended_refuses(self):
        client = _make_mock_kms_client(aws_key_state="Enabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="suspended")
        with self.assertRaises(ExternalManagedSigningError):
            backend.sign_canonical_bytes(
                key=key,
                payload=b"test",
                audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
            )

    def test_sign_retired_refuses(self):
        """Retired keys verify but do not sign — the rotation invariant."""
        client = _make_mock_kms_client(aws_key_state="Enabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="retired")
        with self.assertRaises(ExternalManagedSigningError):
            backend.sign_canonical_bytes(
                key=key,
                payload=b"test",
                audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
            )

    def test_sign_hard_revoked_refuses(self):
        client = _make_mock_kms_client(aws_key_state="Enabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="hard_revoked")
        with self.assertRaises(ExternalManagedSigningError):
            backend.sign_canonical_bytes(
                key=key,
                payload=b"test",
                audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
            )

    def test_sign_aws_disabled_refuses(self):
        """If AWS says the key is Disabled, sign refuses even if operator says active."""
        client = _make_mock_kms_client(aws_key_state="Disabled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")
        with self.assertRaises(ExternalManagedSigningError) as ctx:
            backend.sign_canonical_bytes(
                key=key,
                payload=b"test",
                audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
            )
        self.assertIn("cannot sign", str(ctx.exception))

    def test_sign_unsupported_algorithm_refuses(self):
        """Algorithms not supported by AWS KMS are rejected before the API call."""
        client = _make_mock_kms_client()
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active", algorithm="HS256")  # HMAC not supported by KMS Sign
        with self.assertRaises(ExternalManagedSigningError) as ctx:
            backend.sign_canonical_bytes(
                key=key,
                payload=b"test",
                audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
            )
        self.assertIn("does not support algorithm", str(ctx.exception))
        client.sign.assert_not_called()

    def test_sign_kms_api_failure_wraps_error(self):
        client = _make_mock_kms_client()
        client.sign.side_effect = RuntimeError("throttled")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")
        with self.assertRaises(ExternalManagedSigningError) as ctx:
            backend.sign_canonical_bytes(
                key=key,
                payload=b"test",
                audit_metadata={"operation_id": "op-1", "purpose": PROOF_ISSUANCE_PURPOSE},
            )
        self.assertIn("AWS KMS Sign failed", str(ctx.exception))

    def test_verify_happy_path_returns_true(self):
        client = _make_mock_kms_client(signature_valid=True)
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")
        result = backend.verify_canonical_bytes(
            key=key,
            payload=b"test",
            signature=b"sig",
        )
        self.assertTrue(result)
        client.verify.assert_called_once()

    def test_verify_invalid_signature_returns_false(self):
        """KMS raises on invalid signatures; we catch and return False."""
        client = _make_mock_kms_client()
        client.verify.side_effect = RuntimeError("InvalidSignatureException")
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="active")
        result = backend.verify_canonical_bytes(
            key=key,
            payload=b"test",
            signature=b"bad-sig",
        )
        self.assertFalse(result)

    def test_verify_hard_revoked_returns_false(self):
        """Hard-revoked keys break historical verifiability — they refuse to verify."""
        client = _make_mock_kms_client()
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="hard_revoked")
        result = backend.verify_canonical_bytes(
            key=key,
            payload=b"test",
            signature=b"sig",
        )
        self.assertFalse(result)
        # KMS Verify API MUST NOT have been called.
        client.verify.assert_not_called()

    def test_verify_revoked_still_verifies(self):
        """Revoked keys still verify — historical verifiability is preserved.

        This is the difference between revoked and hard_revoked:
          - revoked:        can't mint, can verify (audit trail intact)
          - hard_revoked:   can't mint, can't verify (history broken)
        """
        client = _make_mock_kms_client(signature_valid=True)
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="revoked")
        result = backend.verify_canonical_bytes(
            key=key,
            payload=b"test",
            signature=b"sig",
        )
        self.assertTrue(result)
        client.verify.assert_called_once()

    def test_verify_retired_still_verifies(self):
        """Retired keys verify — rotation invariant."""
        client = _make_mock_kms_client(signature_valid=True)
        backend = AwsKmsSigningBackend(kms_client=client)
        key = _make_key(status="retired")
        self.assertTrue(
            backend.verify_canonical_bytes(
                key=key, payload=b"test", signature=b"sig",
            )
        )

    def test_aws_kms_algorithms_includes_eddsa(self):
        """EdDSA is the natural production migration path from pilot_local_eddsa."""
        self.assertIn("EdDSA", AWS_KMS_ALGORITHMS)
        self.assertIn("ES256", AWS_KMS_ALGORITHMS)
        self.assertIn("PS256", AWS_KMS_ALGORITHMS)

    def test_aws_kms_key_state_map_covers_all_states(self):
        """All documented AWS KMS KeyState values are mapped."""
        expected_aws_states = {"Enabled", "Disabled", "PendingDeletion", "PendingImport", "Unavailable", "Updating"}
        self.assertEqual(set(AWS_KMS_KEY_STATE_MAP.keys()), expected_aws_states)


# ---------------------------------------------------------------------------
# Rotation scenario test
# ---------------------------------------------------------------------------


class TestKeyRotationScenario(unittest.TestCase):
    """End-to-end rotation scenario: new key active, old key retired.

    This is the scenario Fable 5's CISO persona (Elena) and auditor
    persona (Katherine) both need to see work. The invariant:
      1. New key mints new proofs.
      2. Old key cannot mint.
      3. Old key still verifies proofs it minted before retirement.
      4. Old key's historical receipts remain auditable.

    Hard-revoking the old key would break (3) and (4) — only do that
    if an external anchor proves historical proofs predated compromise.
    """

    def test_rotation_new_signs_old_verifies(self):
        # Old key (retired) — was active, now retired.
        old_client = _make_mock_kms_client(
            aws_key_state="Enabled", signature=b"old-sig", signature_valid=True,
        )
        old_backend = AwsKmsSigningBackend(kms_client=old_client)
        old_key = _make_key(
            key_id="issuer:prod:2026-06",
            provider_key_ref="arn:aws:kms:eu-west-2:123456789012:key/old-5678",
            status="retired",
        )

        # New key (active) — current minting key.
        new_client = _make_mock_kms_client(
            aws_key_state="Enabled", signature=b"new-sig", signature_valid=True,
        )
        new_backend = AwsKmsSigningBackend(kms_client=new_client)
        new_key = _make_key(
            key_id="issuer:prod:2026-07",
            provider_key_ref="arn:aws:kms:eu-west-2:123456789012:key/new-1234",
            status="active",
        )

        payload = b'{"action":"payment.refund","amount":2500}'

        # 1. New key mints new proofs.
        new_result = new_backend.sign_canonical_bytes(
            key=new_key,
            payload=payload,
            audit_metadata={"operation_id": "op-new", "purpose": PROOF_ISSUANCE_PURPOSE},
        )
        self.assertEqual(new_result.signature, b"new-sig")
        self.assertEqual(new_result.key_id, "issuer:prod:2026-07")

        # 2. Old key cannot mint.
        with self.assertRaises(ExternalManagedSigningError):
            old_backend.sign_canonical_bytes(
                key=old_key,
                payload=payload,
                audit_metadata={"operation_id": "op-old", "purpose": PROOF_ISSUANCE_PURPOSE},
            )

        # 3. Old key still verifies proofs it minted before retirement.
        old_proof_signature = b"old-sig-from-history"
        self.assertTrue(
            old_backend.verify_canonical_bytes(
                key=old_key,
                payload=payload,
                signature=old_proof_signature,
            )
        )

        # 4. Old key's historical receipts remain auditable (verify works).
        # New key's proofs also verify with the new key.
        self.assertTrue(
            new_backend.verify_canonical_bytes(
                key=new_key,
                payload=payload,
                signature=new_result.signature,
            )
        )

    def test_hard_revocation_breaks_historical_verifiability(self):
        """If the old key is hard_revoked, it cannot verify historical proofs.

        This is why hard-revocation requires an external anchor (e.g.,
        transparency log inclusion proof) to be safe: without the anchor,
        you can no longer prove that historical receipts were validly
        signed before the compromise.
        """
        old_client = _make_mock_kms_client(signature_valid=True)
        old_backend = AwsKmsSigningBackend(kms_client=old_client)
        old_key = _make_key(
            key_id="issuer:prod:2026-06",
            provider_key_ref="arn:aws:kms:eu-west-2:123456789012:key/old-5678",
            status="hard_revoked",
        )

        # Old key cannot mint.
        with self.assertRaises(ExternalManagedSigningError):
            old_backend.sign_canonical_bytes(
                key=old_key,
                payload=b"test",
                audit_metadata={"operation_id": "op", "purpose": PROOF_ISSUANCE_PURPOSE},
            )

        # Old key also cannot verify — historical verifiability is broken.
        self.assertFalse(
            old_backend.verify_canonical_bytes(
                key=old_key,
                payload=b"test",
                signature=b"historical-sig",
            )
        )

        # KMS Verify API was not called — the lifecycle gate fired first.
        old_client.verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
