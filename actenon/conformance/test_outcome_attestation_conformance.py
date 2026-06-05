"""Outcome-attestation checks for the packaged conformance suite."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.models import ActionSpec, CorrelationRef, PartyRef, Receipt, Refusal, TargetRef, TenantRef
from actenon.proof import HmacSha256Signer, build_local_proof_signer
from actenon.receipts import OutcomeAttestationService, OutcomeAttestationVerificationError


class OutcomeAttestationConformanceTests(unittest.TestCase):
    def _service(self) -> OutcomeAttestationService:
        return OutcomeAttestationService(
            signer=build_local_proof_signer(),
            issuer=PartyRef(type="service", id="protected-endpoint"),
            attestation_id_factory=lambda: "att_conformance_001",
        )

    def _receipt(self) -> Receipt:
        return Receipt(
            receipt_id="rcpt_attestation_conformance_001",
            intent_id="intent_attestation_conformance_001",
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

    def _refusal(self) -> Refusal:
        return Refusal(
            refusal_id="rfsl_attestation_conformance_001",
            category="proof",
            refusal_code="AUDIENCE_MISMATCH",
            message="The proof audience does not match this endpoint.",
            retryable=False,
            refused_at=datetime(2026, 4, 10, 9, 1, tzinfo=timezone.utc),
            intent_id="intent_attestation_conformance_001",
            tenant=TenantRef(tenant_id="tenant_alpha"),
            subject=PartyRef(type="service", id="actor_123"),
            action=ActionSpec(
                name="refund.create",
                capability="refund.execute",
                parameters={"amount_minor": 1000, "currency": "USD"},
            ),
            target=TargetRef(resource_type="payment", resource_id="pay_001"),
            correlation=CorrelationRef(pccb_id="pccb_001", request_id="req_001"),
        )

    def test_attested_receipt_creation(self) -> None:
        attestation = self._service().attest_receipt(self._receipt())
        payload = attestation.to_dict()

        self.assertEqual("receipt_attestation", payload["contract"]["name"])
        self.assertEqual("v2alpha1", payload["contract"]["version"])
        self.assertEqual("receipt", payload["unsigned_payload"]["artifact_type"])
        self.assertEqual("receipt", payload["unsigned_payload"]["outcome_artifact"]["contract"]["name"])
        self.assertEqual("sha-256", payload["unsigned_payload"]["artifact_digest"]["algorithm"])
        self.assertEqual([], payload["external_anchors"])

    def test_attested_refusal_creation(self) -> None:
        attestation = self._service().attest_refusal(self._refusal())
        payload = attestation.to_dict()

        self.assertEqual("refusal_attestation", payload["contract"]["name"])
        self.assertEqual("v2alpha1", payload["contract"]["version"])
        self.assertEqual("refusal", payload["unsigned_payload"]["artifact_type"])
        self.assertEqual("refusal", payload["unsigned_payload"]["outcome_artifact"]["contract"]["name"])
        self.assertEqual("sha-256", payload["unsigned_payload"]["artifact_digest"]["algorithm"])

    def test_signature_verification_success(self) -> None:
        service = self._service()
        receipt = self._receipt()
        attestation = service.attest_receipt(receipt)

        verified = service.verify_receipt_attestation(attestation.to_dict())

        self.assertEqual(receipt.receipt_id, verified.receipt_id)

    def test_tamper_detection_failure(self) -> None:
        service = self._service()
        payload = service.attest_receipt(self._receipt()).to_dict()
        payload["unsigned_payload"]["outcome_artifact"]["summary"] = "Tampered summary."

        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_receipt_attestation(payload)

    def test_wrong_key_failure(self) -> None:
        service = self._service()
        payload = service.attest_refusal(self._refusal()).to_dict()
        wrong_verifier = HmacSha256Signer(secret=b"wrong-attestation-secret", key_id="wrong-key")

        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_refusal_attestation(payload, verifier=wrong_verifier)


if __name__ == "__main__":
    unittest.main()
