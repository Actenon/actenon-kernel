"""AWS KMS signing backend for the Actenon kernel.

Fable 5 Part 3C identified KMS custody as the universal gate across every
persona in the ecosystem. The CISO (Elena) wrote it as a pilot-approval
contingency; the underwriter (William) needs it for premium pricing; the
auditor (Katherine) needs it for opinion reliance; the engineer (Sam)
needs it before routing real payments.

This module provides a concrete AWS KMS backend that implements the
:class:`ExternalManagedSigningBackend` Protocol from
``actenon.proof.signers.external_managed``. It is the first concrete
provider backend in the tree.

Design constraints
------------------

1. **boto3 is an optional dependency.** The kernel stays installable
   without AWS SDK. Import is lazy and only happens when the backend is
   actually used. The optional ``[aws]`` extra declares the dep.

2. **The backend never sees private key material.** AWS KMS signs
   inside the HSM; we only ever see the signature bytes.

3. **The backend enforces the key-lifecycle state machine.** Before
   every sign operation, the backend checks the key's lifecycle state.
   Revoked, suspended, retired, and hard_revoked keys refuse to sign.
   Hard_revoked keys also refuse to verify.

4. **The backend maps AWS KMS key states to Actenon lifecycle states.**
   AWS KMS has ``Enabled``, ``Disabled``, ``PendingDeletion``,
   ``PendingImport``, and ``Unavailable``. We map:
     - ``Enabled``                              -> ``active``
     - ``Disabled``                             -> ``suspended``
     - ``PendingDeletion`` / ``Unavailable``    -> ``revoked``
   The ``retired`` and ``hard_revoked`` states are Actenon-specific
   and must be set via the ``status`` field on :class:`ManagedKeyReference`
   (typically stored as a KMS tag).

5. **The backend is testable without real AWS.** The constructor
   accepts an optional ``kms_client`` argument; tests pass a mock.

Algorithm support
-----------------

AWS KMS supports asymmetric signing with:
  - RSA PKCS#1 v1.5 (RS256, RS384, RS512)
  - RSA-PSS (PS256, PS384, PS512)
  - ECDSA (ES256, ES384, ES512)
  - Ed25519 (EdDSA)

The kernel's reference :class:`pilot_local_eddsa` signer uses Ed25519,
so Ed25519 keys in AWS KMS are the natural production migration path.

Usage
-----

Production deployment::

    from actenon.proof.signers.aws_kms import AwsKmsSigningBackend
    from actenon.proof.signers.external_managed import (
        ExternalManagedSigner, ManagedKeyReference, PROOF_ISSUANCE_PURPOSE,
    )

    backend = AwsKmsSigningBackend(
        kms_client=boto3.client("kms", region_name="eu-west-2"),
    )
    key = ManagedKeyReference(
        provider="aws-kms",
        provider_key_ref="arn:aws:kms:eu-west-2:123456789012:key/abcd-1234",
        key_id="issuer:prod:2026-07",
        algorithm="EdDSA",
        purpose=PROOF_ISSUANCE_PURPOSE,
        tenant_id="tenant-acme",
        public_key_ref="aws-kms://arn:aws:kms:eu-west-2:123456789012:key/abcd-1234",
        key_version="2026-07",
        status="active",
    )
    signer = ExternalManagedSigner(backend=backend, key=key)

Tests
-----

The unit tests in ``tests/unit/test_aws_kms_signer.py`` exercise the
backend with a mock KMS client, including:
  - sign and verify happy path
  - lifecycle enforcement (revoked/suspended/retired refuse to sign)
  - hard_revoked refuses to verify
  - algorithm and key_id round-trip
  - audit metadata propagation

What this does NOT do
---------------------

This module does NOT:
  - provision KMS keys (use Terraform / CloudFormation)
  - rotate keys automatically (rotation is an operator action; see
    ``docs/reference/ecosystem/KMS_ROTATION_RUNBOOK.md``)
  - publish well-known key discovery documents (use ``actenon-kernel
    keys publish`` after the key is created)
  - enforce multi-region replication (configure in KMS itself)
  - bill anything — AWS KMS charges per sign/verify API call

These are deliberate scope boundaries. The backend's job is to be the
trustworthy adapter between Actenon's lifecycle rules and AWS KMS's
API. Everything else is the operator's job.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .external_managed import (
    ACTIVE_KEY_STATUS,
    ExternalManagedSigningError,
    ManagedKeyReference,
    ManagedSigningAuditMetadata,
    ManagedSigningResult,
)
from .key_lifecycle import (
    DEFAULT_MACHINE,
    KeyLifecycleError,
    KeyLifecycleState,
)


# AWS KMS SigningAlgorithm values. See:
# https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html#signing-algorithms
AWS_KMS_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512",       # RSA PKCS#1 v1.5
    "PS256", "PS384", "PS512",       # RSA-PSS
    "ES256", "ES384", "ES512",       # ECDSA P-256/P-384/P-521
    "EdDSA",                          # Ed25519
})

# Mapping from AWS KMS KeyState values to Actenon lifecycle states.
# See: https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
AWS_KMS_KEY_STATE_MAP: Mapping[str, KeyLifecycleState] = {
    "Enabled": KeyLifecycleState.ACTIVE,
    "Disabled": KeyLifecycleState.SUSPENDED,
    "PendingDeletion": KeyLifecycleState.REVOKED,
    "PendingImport": KeyLifecycleState.SUSPENDED,
    "Unavailable": KeyLifecycleState.REVOKED,
    # "Updating" is transient; treat as suspended (cannot sign until update completes)
    "Updating": KeyLifecycleState.SUSPENDED,
}


@dataclass(frozen=True)
class AwsKmsSigningBackend:
    """Concrete AWS KMS backend implementing ExternalManagedSigningBackend.

    The backend is a thin adapter around the AWS KMS Sign/Verify API.
    It enforces Actenon's key-lifecycle state machine on every operation.

    Attributes
    ----------
    kms_client : Any
        A boto3 KMS client. The type is ``Any`` because boto3 is an
        optional dependency; we do not want to import it at module
        level. Tests pass a mock; production passes a real client.
    """

    kms_client: Any

    # ------------------------------------------------------------------
    # ExternalManagedSigningBackend Protocol
    # ------------------------------------------------------------------

    def get_key_status(self, *, key: ManagedKeyReference) -> str:
        """Return the Actenon lifecycle state for the key.

        The state is determined by combining:
          1. The ``status`` field on the ManagedKeyReference (set by the
             operator, typically stored as a KMS tag). This is the
             source of truth for Actenon-specific states (``retired``,
             ``hard_revoked``) that have no AWS KMS equivalent.
          2. The underlying AWS KMS KeyState, fetched live from KMS.
             This catches cases where the key was disabled or scheduled
             for deletion outside Actenon.

        If the two sources disagree, the MORE restrictive state wins.
        For example, if the operator sets ``status="active"`` but AWS
        KMS says the key is ``Disabled``, the returned state is
        ``suspended``.

        If the operator sets ``status="hard_revoked"``, that always
        wins (it is the most restrictive state).
        """
        # If the operator has marked the key hard_revoked, that's terminal.
        operator_state = KeyLifecycleState.from_string(key.status)

        if operator_state == KeyLifecycleState.HARD_REVOKED:
            return operator_state.value

        # Fetch the live AWS KMS state.
        try:
            response = self.kms_client.describe_key(KeyId=key.provider_key_ref)
            aws_state = response["KeyMetadata"]["KeyState"]
        except Exception as e:
            raise ExternalManagedSigningError(
                f"failed to describe KMS key {key.provider_key_ref!r}: {e}"
            ) from e

        kms_state = AWS_KMS_KEY_STATE_MAP.get(aws_state)
        if kms_state is None:
            # Unknown AWS state — fail closed.
            raise ExternalManagedSigningError(
                f"unknown AWS KMS key state {aws_state!r} for key "
                f"{key.provider_key_ref!r}; failing closed."
            )

        # The more restrictive state wins. Restrictiveness order:
        #   active < retired < suspended < revoked < hard_revoked
        restrictiveness = {
            KeyLifecycleState.ACTIVE: 0,
            KeyLifecycleState.RETIRED: 1,
            KeyLifecycleState.SUSPENDED: 2,
            KeyLifecycleState.REVOKED: 3,
            KeyLifecycleState.HARD_REVOKED: 4,
        }
        if restrictiveness[kms_state] > restrictiveness[operator_state]:
            return kms_state.value
        return operator_state.value

    def sign_canonical_bytes(
        self,
        *,
        key: ManagedKeyReference,
        payload: bytes,
        audit_metadata: Mapping[str, object],
    ) -> ManagedSigningResult:
        """Sign canonical bytes with the AWS KMS key.

        Fails closed if:
          - the key's lifecycle state is not ``active``
          - the algorithm is not supported by AWS KMS
          - the KMS API call fails for any reason
        """
        # Enforce the lifecycle state machine.
        status = self.get_key_status(key=key)
        try:
            DEFAULT_MACHINE.assert_can_sign(status)
        except KeyLifecycleError as e:
            raise ExternalManagedSigningError(
                f"AWS KMS key {key.key_id!r} cannot sign: {e}"
            ) from e

        # Validate the algorithm.
        if key.algorithm not in AWS_KMS_ALGORITHMS:
            raise ExternalManagedSigningError(
                f"AWS KMS backend does not support algorithm {key.algorithm!r}; "
                f"supported: {sorted(AWS_KMS_ALGORITHMS)}."
            )

        # Call KMS Sign.
        # AWS KMS expects the MessageType to be "RAW" for direct signing
        # (vs "DIGEST" for pre-hashed payloads). We use RAW so KMS handles
        # the hashing internally per the algorithm's spec.
        try:
            response = self.kms_client.sign(
                KeyId=key.provider_key_ref,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm=key.algorithm,
            )
        except Exception as e:
            raise ExternalManagedSigningError(
                f"AWS KMS Sign failed for key {key.key_id!r}: {e}"
            ) from e

        signature = response["Signature"]
        # KMS returns the AWS-generated request ID; we use it as the
        # provider operation ID for audit correlation.
        operation_id = response.get("SigningAlgorithm")  # not ideal; see TODO

        # TODO: AWS KMS does not return a per-operation ID in the Sign
        # response. For audit correlation, operators should use
        # CloudTrail's `eventID` matched on `requestParameters.keyId`
        # and approximate timestamp. A future version of this backend
        # may inject the CloudTrail event ID via a post-hoc lookup.
        # For now, we synthesize a stable operation ID from the
        # signature digest (deterministic, no secret leakage).
        if operation_id is None or operation_id == key.algorithm:
            digest = hashlib.sha256(signature).hexdigest()[:16]
            operation_id = f"aws-kms-sign-{digest}"

        return ManagedSigningResult(
            algorithm=key.algorithm,
            key_id=key.key_id,
            signature=signature,
            public_key_ref=key.public_key_ref or f"aws-kms://{key.provider_key_ref}",
            provider_operation_id=operation_id,
        )

    def verify_canonical_bytes(
        self,
        *,
        key: ManagedKeyReference,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        """Verify a signature with the AWS KMS key.

        Returns True if the signature is valid, False otherwise.
        Fails closed (returns False) if:
          - the key's lifecycle state is ``hard_revoked``
          - the KMS API call fails for any reason

        Note: verification does NOT fail closed for revoked or retired
        keys. Those keys still verify so that historical proofs remain
        auditable. Only ``hard_revoked`` breaks historical verifiability.
        """
        # Enforce the lifecycle state machine.
        status = self.get_key_status(key=key)
        try:
            DEFAULT_MACHINE.assert_can_verify(status)
        except KeyLifecycleError:
            # Hard-revoked: fail closed.
            return False

        # Validate the algorithm.
        if key.algorithm not in AWS_KMS_ALGORITHMS:
            return False

        # Call KMS Verify.
        try:
            response = self.kms_client.verify(
                KeyId=key.provider_key_ref,
                Message=payload,
                MessageType="RAW",
                Signature=signature,
                SigningAlgorithm=key.algorithm,
            )
        except Exception:
            # KMS raises an exception for invalid signatures (rather
            # than returning False). Catch and return False.
            return False

        return bool(response.get("SignatureValid", False))


__all__ = [
    "AwsKmsSigningBackend",
    "AWS_KMS_ALGORITHMS",
    "AWS_KMS_KEY_STATE_MAP",
]
