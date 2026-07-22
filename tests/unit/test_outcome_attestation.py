from __future__ import annotations

import hmac
import unittest
from datetime import datetime, timezone
from hashlib import sha256

from actenon.models import ActionSpec, CorrelationRef, PartyRef, Receipt, Refusal, TargetRef, TenantRef
from actenon.proof.signers import KmsKeyHandle, KmsSigner
from actenon.receipts import (
    OutcomeAttestationService,
    OutcomeAttestationVerificationError,
)
from actenon.proof import build_local_proof_signer


class _FakeKmsBackend:
    def __init__(self) -> None:
        self.secret = b"receipt-v2-kms-secret"

    def sign(self, *, key: KmsKeyHandle, payload: bytes) -> bytes:
        return hmac.new(self.secret + key.key_id.encode("utf-8"), payload, sha256).digest()

    def verify(self, *, key: KmsKeyHandle, payload: bytes, signature: bytes) -> bool:
        expected = self.sign(key=key, payload=payload)
        return hmac.compare_digest(expected, signature)


class OutcomeAttestationTests(unittest.TestCase):
    def _build_receipt(self) -> Receipt:
        return Receipt(
            receipt_id="rcpt_attestation_001",
            intent_id="intent_attestation_001",
            occurred_at=datetime(2026, 4, 10, 9, 0, tzinfo=timezone.utc),
            outcome="executed",
            tenant=TenantRef(tenant_id="tenant_alpha"),
            subject=PartyRef(type="service", id="actor_123"),
            action=ActionSpec(
                name="refund.create",
                capability="refund.execute",
                parameters={"amount_minor": 1000, "currency": "USD"},
            ),
            target=TargetRef(resource_type="payment", resource_id="pay_001"),
            summary="Refund executed through the protected endpoint.",
            phase="execution",
            correlation=CorrelationRef(pccb_id="pccb_001", request_id="req_001"),
            side_effects={"external_reference": "refund_exec_001"},
        )

    def _build_refusal(self) -> Refusal:
        return Refusal(
            refusal_id="rfsl_attestation_001",
            category="proof",
            reason_code="AUDIENCE_MISMATCH",
            message="The proof audience does not match this endpoint.",
            retryable=False,
            refused_at=datetime(2026, 4, 10, 9, 1, tzinfo=timezone.utc),
            intent_id="intent_attestation_001",
            tenant=TenantRef(tenant_id="tenant_alpha"),
            subject=PartyRef(type="service", id="actor_123"),
            action=ActionSpec(
                name="refund.create",
                capability="refund.execute",
                parameters={"amount_minor": 1000, "currency": "USD"},
            ),
            target=TargetRef(resource_type="payment", resource_id="pay_001"),
            correlation=CorrelationRef(pccb_id="pccb_001", request_id="req_001"),
            details={"expected_audience": "service:payments", "observed_audience": "service:wrong-endpoint"},
        )

    def test_receipt_attestation_round_trip_with_local_signer(self) -> None:
        service = OutcomeAttestationService(
            signer=build_local_proof_signer(),
            issuer=PartyRef(type="service", id="protected-endpoint", display_name="Protected Endpoint"),
            attestation_id_factory=lambda: "att_receipt_001",
        )
        receipt = self._build_receipt()

        attestation = service.attest_receipt(
            receipt,
            issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc),
            metadata={"attestation_scope": "active-v2alpha1"},
        )
        verified = service.verify_receipt_attestation(attestation.to_dict())

        self.assertEqual("att_receipt_001", attestation.attestation_id)
        self.assertEqual("receipt_attestation", attestation.to_dict()["contract"]["name"])
        self.assertEqual("v2alpha1", attestation.to_dict()["contract"]["version"])
        self.assertIn("unsigned_payload", attestation.to_dict())
        self.assertEqual("receipt", attestation.to_dict()["unsigned_payload"]["artifact_type"])
        self.assertEqual([], attestation.to_dict()["external_anchors"])
        self.assertNotIn("external_anchors", attestation.to_dict()["unsigned_payload"])
        self.assertEqual("local-proof-v1", attestation.signature.key_id)
        self.assertEqual(receipt.receipt_id, verified.receipt_id)

    def test_receipt_attestation_detects_embedded_receipt_tampering(self) -> None:
        service = OutcomeAttestationService(
            signer=build_local_proof_signer(),
            issuer=PartyRef(type="service", id="protected-endpoint"),
            attestation_id_factory=lambda: "att_receipt_002",
        )
        attestation_payload = service.attest_receipt(self._build_receipt()).to_dict()
        attestation_payload["unsigned_payload"]["outcome_artifact"]["summary"] = "Tampered summary."

        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_receipt_attestation(attestation_payload)

    def test_refusal_attestation_round_trip_with_kms_signer(self) -> None:
        signer = KmsSigner(
            backend=_FakeKmsBackend(),
            key=KmsKeyHandle(
                provider="generic-kms",
                key_uri="kms://tenant/outcome-attestation-key",
                key_id="kms-receipt-v2",
                algorithm="KMS_TEST",
                key_version="1",
            ),
        )
        service = OutcomeAttestationService(
            signer=signer,
            issuer=PartyRef(type="service", id="protected-endpoint"),
            attestation_id_factory=lambda: "att_refusal_001",
        )
        refusal = self._build_refusal()

        attestation = service.attest_refusal(refusal)
        verified = service.verify_refusal_attestation(attestation.to_dict(), verifier=signer)

        self.assertEqual("kms-receipt-v2", attestation.signature.key_id)
        self.assertEqual("refusal_attestation", attestation.to_dict()["contract"]["name"])
        self.assertEqual("refusal", attestation.to_dict()["unsigned_payload"]["artifact_type"])
        self.assertEqual(refusal.refusal_id, verified.refusal_id)


if __name__ == "__main__":
    unittest.main()
