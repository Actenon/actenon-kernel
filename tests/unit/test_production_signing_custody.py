from __future__ import annotations

import hmac
import os
import unittest
from hashlib import sha256
from unittest.mock import patch

from actenon.proof import (
    DEVELOPMENT_LOCAL_HMAC_BACKEND,
    EXTERNAL_MANAGED_BACKEND,
    PILOT_LOCAL_EDDSA_BACKEND,
    PROOF_ISSUANCE_PURPOSE,
    ExternalManagedSigner,
    ExternalManagedSigningError,
    LocalHmacProductionGuardError,
    ManagedKeyReference,
    ManagedSigningAuditMetadata,
    ManagedSigningResult,
    ProductionSigningGuardError,
    build_local_proof_signer,
    validate_signing_backend_for_environment,
)


class _MockExternalManagedBackend:
    def __init__(self, *, status: str = "active") -> None:
        self.status = status
        self.secret = b"mock-external-managed-provider-key"
        self.audit_records: list[dict[str, object]] = []

    def get_key_status(self, *, key: ManagedKeyReference) -> str:
        return self.status

    def sign_canonical_bytes(
        self,
        *,
        key: ManagedKeyReference,
        payload: bytes,
        audit_metadata: dict[str, object],
    ) -> ManagedSigningResult:
        self.audit_records.append(dict(audit_metadata))
        key_material = f"{key.provider}:{key.provider_key_ref}:{key.key_id}:{key.purpose}".encode("utf-8")
        signature = hmac.new(self.secret + key_material, payload, sha256).digest()
        return ManagedSigningResult(
            algorithm=key.algorithm,
            key_id=key.key_id,
            signature=signature,
            public_key_ref=key.public_key_ref or f"{key.provider_key_ref}#public",
            provider_operation_id="mock-provider-op-001",
        )

    def verify_canonical_bytes(self, *, key: ManagedKeyReference, payload: bytes, signature: bytes) -> bool:
        expected = self.sign_canonical_bytes(key=key, payload=payload, audit_metadata={}).signature
        return hmac.compare_digest(expected, signature)


def _managed_key(*, status: str = "active", purpose: str = PROOF_ISSUANCE_PURPOSE) -> ManagedKeyReference:
    return ManagedKeyReference(
        provider="mock-kms",
        provider_key_ref="kms://tenant-a/proof-key",
        key_id="tenant-a-proof-2026-06",
        algorithm="EdDSA",
        purpose=purpose,
        tenant_id="tenant-a",
        public_key_ref="https://issuer.example/.well-known/actenon/keys.json#tenant-a-proof-2026-06",
        key_version="1",
        status=status,
    )


class ProductionSigningCustodyTests(unittest.TestCase):
    def test_production_mode_rejects_local_hmac_signer(self) -> None:
        with patch.dict(os.environ, {"ACTENON_ENV": "production"}, clear=True):
            with self.assertRaises(LocalHmacProductionGuardError):
                build_local_proof_signer()

        with self.assertRaises(ProductionSigningGuardError):
            validate_signing_backend_for_environment(DEVELOPMENT_LOCAL_HMAC_BACKEND, production=True)

    def test_production_mode_rejects_pilot_local_eddsa_unless_unsafe_override_is_explicit(self) -> None:
        with self.assertRaises(ProductionSigningGuardError):
            validate_signing_backend_for_environment(PILOT_LOCAL_EDDSA_BACKEND, production=True)

        validate_signing_backend_for_environment(
            PILOT_LOCAL_EDDSA_BACKEND,
            production=True,
            environment={"ACTENON_ALLOW_PILOT_LOCAL_EDDSA_IN_PRODUCTION": "1"},
        )

    def test_external_managed_backend_can_be_mocked_and_records_audit_metadata(self) -> None:
        backend = _MockExternalManagedBackend()
        signer = ExternalManagedSigner(
            backend=backend,
            key=_managed_key(),
            audit_metadata=ManagedSigningAuditMetadata(
                operation_id="sign-op-001",
                purpose=PROOF_ISSUANCE_PURPOSE,
                tenant_id="tenant-a",
                request_id="req-001",
                correlation_id="corr-001",
                payload_digest="sha256:payload",
                extra={"issuer_id": "issuer-a"},
            ),
        )

        managed_result = signer.sign_managed(b"canonical-pccb-bytes")
        signature = managed_result.to_signature_spec()

        self.assertEqual("EdDSA", signature.algorithm)
        self.assertEqual("tenant-a-proof-2026-06", signature.key_id)
        self.assertEqual(
            "https://issuer.example/.well-known/actenon/keys.json#tenant-a-proof-2026-06",
            managed_result.public_key_ref,
        )
        self.assertTrue(signer.verify(b"canonical-pccb-bytes", signature))
        self.assertEqual("sign-op-001", backend.audit_records[0]["operation_id"])
        self.assertEqual(PROOF_ISSUANCE_PURPOSE, backend.audit_records[0]["purpose"])
        self.assertEqual("tenant-a", backend.audit_records[0]["tenant_id"])
        self.assertNotIn("private_key", backend.audit_records[0])
        self.assertNotIn("secret", backend.audit_records[0])

    def test_suspended_or_revoked_external_managed_key_cannot_sign(self) -> None:
        for status in ("suspended", "revoked", "hard_revoked"):
            with self.subTest(status=status):
                signer = ExternalManagedSigner(
                    backend=_MockExternalManagedBackend(status=status),
                    key=_managed_key(status="active"),
                )
                with self.assertRaises(ExternalManagedSigningError):
                    signer.sign(b"payload")

    def test_key_purpose_mismatch_cannot_sign(self) -> None:
        signer = ExternalManagedSigner(
            backend=_MockExternalManagedBackend(),
            key=_managed_key(purpose="outcome_attestation"),
        )
        with self.assertRaises(ExternalManagedSigningError):
            signer.sign(b"payload")

    def test_external_managed_backend_is_valid_for_production(self) -> None:
        validate_signing_backend_for_environment(EXTERNAL_MANAGED_BACKEND, production=True)


if __name__ == "__main__":
    unittest.main()
