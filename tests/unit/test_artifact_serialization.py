from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.models import (
    ARTIFACT_HASH_ALGORITHM,
    ARTIFACT_HASH_CANONICALIZATION,
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    CorrelationRef,
    PartyRef,
    PCCB,
    Receipt,
    Refusal,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
    AudienceRef,
    build_artifact_digest,
    canonicalize_artifact_bytes,
    canonicalize_artifact_json,
    sha256_artifact_hex,
)
from actenon.proof.canonical import canonicalize_bytes, canonicalize_json, sha256_hex
from actenon.proof.service import build_action_hash_input


class ArtifactSerializationTests(unittest.TestCase):
    def _build_action_intent(self) -> ActionIntent:
        return ActionIntent(
            intent_id="intent_serialization_001",
            issued_at=datetime(2026, 4, 11, 11, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 4, 11, 11, 5, tzinfo=timezone.utc),
            tenant=TenantRef(tenant_id="tenant_alpha", attributes={"region": "uk"}),
            requester=PartyRef(type="service", id="requester_001"),
            action=ActionSpec(
                name="invoice_payment.execute",
                capability="invoice_payment.execute",
                parameters={"amount_minor": 12500, "currency": "GBP", "invoice_id": "inv_001"},
                constraints={"exact_amount_minor": 12500},
            ),
            target=TargetRef(resource_type="invoice", resource_id="inv_001"),
            justification="Execute invoice payment after approval.",
            metadata={"trace": "serialization"},
            extensions={"demo": {"mode": "unit-test"}},
        )

    def _build_pccb(self, intent: ActionIntent) -> PCCB:
        return PCCB(
            pccb_id="pccb_serialization_001",
            intent_id=intent.intent_id,
            issued_at=intent.issued_at,
            not_before=intent.issued_at,
            expires_at=intent.expires_at,
            issuer=PartyRef(type="service", id="issuer_001"),
            subject=intent.requester,
            tenant=intent.tenant,
            audience=AudienceRef(type="service", id="invoice-payment-endpoint"),
            action=intent.action,
            target=intent.target,
            scope=ScopeSpec(
                mode="exact",
                capabilities=(intent.action.capability,),
                single_use=True,
                parameter_constraints={"exact_amount_minor": 12500},
            ),
            nonce="nonce_serialization_001",
            action_hash=ActionHashSpec(
                algorithm="sha-256",
                canonicalization="RFC8785-JCS",
                value=sha256_hex(build_action_hash_input(intent)),
            ),
            signature=SignatureSpec(
                algorithm="HS256",
                key_id="local-proof-v1",
                encoding="base64url",
                value="signature_serialization_001",
            ),
            extensions={"demo": {"mode": "unit-test"}},
        )

    def _build_receipt(self, intent: ActionIntent, pccb: PCCB) -> Receipt:
        return Receipt(
            receipt_id="rcpt_serialization_001",
            intent_id=intent.intent_id,
            occurred_at=datetime(2026, 4, 11, 11, 1, tzinfo=timezone.utc),
            outcome="executed",
            tenant=intent.tenant,
            subject=intent.requester,
            action=intent.action,
            target=intent.target,
            summary="Invoice payment executed.",
            phase="execution",
            correlation=CorrelationRef(pccb_id=pccb.pccb_id, request_id="req_serialization_001", action_hash=pccb.action_hash),
            side_effects={"provider_reference": "payexec_001"},
            metadata={"trace": "serialization"},
        )

    def _build_refusal(self, intent: ActionIntent, pccb: PCCB) -> Refusal:
        return Refusal(
            refusal_id="rfsl_serialization_001",
            category="proof",
            refusal_code="AUDIENCE_MISMATCH",
            message="The proof audience does not match this endpoint.",
            retryable=False,
            refused_at=datetime(2026, 4, 11, 11, 2, tzinfo=timezone.utc),
            intent_id=intent.intent_id,
            tenant=intent.tenant,
            subject=intent.requester,
            audience=AudienceRef(type="service", id="wrong-endpoint"),
            action=intent.action,
            target=intent.target,
            correlation=CorrelationRef(pccb_id=pccb.pccb_id, request_id="req_serialization_002", action_hash=pccb.action_hash),
            details={"expected_audience": "service:invoice-payment-endpoint"},
        )

    def test_artifact_helpers_match_existing_low_level_canonicalizer(self) -> None:
        intent = self._build_action_intent()
        pccb = self._build_pccb(intent)
        receipt = self._build_receipt(intent, pccb)
        refusal = self._build_refusal(intent, pccb)

        for artifact in (intent, pccb, receipt, refusal):
            with self.subTest(artifact=type(artifact).__name__):
                payload = artifact.to_dict()
                self.assertEqual(canonicalize_json(payload), canonicalize_artifact_json(artifact))
                self.assertEqual(canonicalize_bytes(payload), canonicalize_artifact_bytes(artifact))
                self.assertEqual(sha256_hex(payload), sha256_artifact_hex(artifact))
                self.assertEqual(sha256_artifact_hex(payload), sha256_artifact_hex(artifact))

    def test_build_artifact_digest_uses_shared_metadata(self) -> None:
        digest = build_artifact_digest(self._build_action_intent())

        self.assertEqual(ARTIFACT_HASH_ALGORITHM, digest.algorithm)
        self.assertEqual(ARTIFACT_HASH_CANONICALIZATION, digest.canonicalization)
        self.assertEqual(
            sha256_artifact_hex(self._build_action_intent()),
            digest.value,
        )


if __name__ == "__main__":
    unittest.main()
