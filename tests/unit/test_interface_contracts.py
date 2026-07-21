from __future__ import annotations

import hmac
import unittest
from datetime import datetime, timezone
from hashlib import sha256

from actenon.adapters import ProviderAdapterRequest
from actenon.api.intake import ActionIntentIntakeService
from actenon.demo.portable_local_proof import build_hello_world_action_intent_payload
from actenon.models import AudienceRef, PolicyBundle, PolicyBundleRule, PolicyDecision, ProtectedExecutionRequest
from actenon.proof import PCCBMinter, PCCBVerifier, VerifierDisclosureMode, build_local_proof_signer
from actenon.proof.local import HmacSha256Signer as CompatHmacSha256Signer
from actenon.proof.signers import HmacSha256Signer, HsmKeyHandle, HsmSigner, KmsKeyHandle, KmsSigner
from actenon.reconciliation import ProviderReconciliationSnapshot, ProviderStateMapping, StaticReconciliationMapper
from actenon.verifier import VerifierSDK


class _FakeKmsBackend:
    def __init__(self) -> None:
        self.secret = b"kms-test-secret"

    def sign(self, *, key: KmsKeyHandle, payload: bytes) -> bytes:
        return hmac.new(self.secret + key.key_id.encode("utf-8"), payload, sha256).digest()

    def verify(self, *, key: KmsKeyHandle, payload: bytes, signature: bytes) -> bool:
        expected = self.sign(key=key, payload=payload)
        return hmac.compare_digest(expected, signature)


class _FakeHsmBackend:
    def __init__(self) -> None:
        self.secret = b"hsm-test-secret"

    def sign(self, *, key: HsmKeyHandle, payload: bytes) -> bytes:
        key_material = f"{key.module}:{key.key_label}:{key.key_id}".encode("utf-8")
        return hmac.new(self.secret + key_material, payload, sha256).digest()

    def verify(self, *, key: HsmKeyHandle, payload: bytes, signature: bytes) -> bool:
        expected = self.sign(key=key, payload=payload)
        return hmac.compare_digest(expected, signature)


class _MetadataAwareVerifier:
    algorithm = "dynamic"
    key_id = "dynamic"

    def __init__(self) -> None:
        self.seen_issuer = None
        self.seen_issued_at = None

    def verify(self, payload: bytes, signature) -> bool:
        return False

    def verify_with_metadata(self, payload: bytes, signature, *, issuer=None, issued_at=None) -> bool:
        self.seen_issuer = issuer
        self.seen_issued_at = issued_at
        return True


class InterfaceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.intake = ActionIntentIntakeService()
        self.signer = build_local_proof_signer()
        self.sdk = VerifierSDK(self.signer)

    def _build_execution_request(self) -> ProtectedExecutionRequest:
        payload = build_hello_world_action_intent_payload()
        intent = self.intake.parse(payload)
        context = self.sdk.build_context(
            request_id="req_interfaces_001",
            audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
            now=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
            scope_capabilities=("protected_resource.read",),
            parameter_constraints={"exact_message": "portable hello world"},
            resource_selectors=({"resource_id": "hello_resource_demo_001"},),
        )
        pccb = PCCBMinter(
            signer=self.signer,
            issuer=intent.requester,
            pccb_id_factory=lambda: "pccb_interfaces_001",
            nonce_factory=lambda: "nonce-interfaces-00000001",
        ).mint(
            intent,
            decision=PolicyDecision(
                outcome="allow",
                summary="Interface test allow.",
                rule_evaluations=(),
                reason_codes=("LOCAL_PROOF_ALLOW",),
            ),
            context=context,
        )
        return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

    def test_local_signer_behavior_is_preserved(self) -> None:
        self.assertIsInstance(self.signer, HmacSha256Signer)
        self.assertIsInstance(self.signer, CompatHmacSha256Signer)
        signature = self.signer.sign(b"portable-payload")
        self.assertTrue(self.signer.verify(b"portable-payload", signature))
        self.assertFalse(self.signer.verify(b"tampered-payload", signature))
        self.assertEqual("local-proof-v1", signature.key_id)

    def test_kms_signer_delegates_to_backend(self) -> None:
        signer = KmsSigner(
            backend=_FakeKmsBackend(),
            key=KmsKeyHandle(
                provider="generic-kms",
                key_uri="kms://tenant/signing-key",
                key_id="kms-proof-v1",
                algorithm="KMS_TEST",
                key_version="1",
            ),
        )
        signature = signer.sign(b"kms-payload")
        self.assertEqual("KMS_TEST", signature.algorithm)
        self.assertTrue(signer.verify(b"kms-payload", signature))
        self.assertFalse(signer.verify(b"tampered", signature))

    def test_hsm_signer_delegates_to_backend(self) -> None:
        signer = HsmSigner(
            backend=_FakeHsmBackend(),
            key=HsmKeyHandle(
                module="pkcs11-module-a",
                slot="slot-7",
                key_label="proof-key",
                key_id="hsm-proof-v1",
                algorithm="HSM_TEST",
            ),
        )
        signature = signer.sign(b"hsm-payload")
        self.assertEqual("HSM_TEST", signature.algorithm)
        self.assertTrue(signer.verify(b"hsm-payload", signature))
        self.assertFalse(signer.verify(b"tampered", signature))

    def test_pccb_verifier_uses_metadata_aware_verifier_hook_when_available(self) -> None:
        execution_request = self._build_execution_request()
        verifier = _MetadataAwareVerifier()

        PCCBVerifier(verifier, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG).verify(
            execution_request.intent,
            execution_request.pccb,
            execution_request.context,
        )

        self.assertEqual(execution_request.pccb.issuer, verifier.seen_issuer)
        self.assertEqual(execution_request.pccb.issued_at, verifier.seen_issued_at)

    def test_provider_adapter_request_normalizes_verified_execution_request(self) -> None:
        execution_request = self._build_execution_request()
        adapter_request = ProviderAdapterRequest.from_execution_request(
            execution_request,
            metadata={"adapter_hint": "portable"},
        )
        self.assertEqual("hello_world.read", adapter_request.action.name)
        self.assertEqual("portable-hello-world-endpoint", adapter_request.context.audience.split(":", 1)[1])
        self.assertEqual("pccb_interfaces_001", adapter_request.context.pccb_id)
        self.assertEqual("portable", adapter_request.metadata["adapter_hint"])

    def test_static_reconciliation_mapper_maps_provider_state(self) -> None:
        mapper = StaticReconciliationMapper(
            mappings={
                "accepted": ProviderStateMapping(
                    provider_state="accepted",
                    kernel_status="provider-pending",
                    terminal=False,
                    description="Provider accepted the operation but has not confirmed finality.",
                ),
                "settled": ProviderStateMapping(
                    provider_state="settled",
                    kernel_status="provider-confirmed",
                    terminal=True,
                    description="Provider confirmed the operation.",
                ),
            }
        )
        snapshot = ProviderReconciliationSnapshot(
            provider_name="example-provider",
            provider_reference="prov_123",
            provider_state="accepted",
            observed_at=datetime(2026, 4, 6, 10, 0, tzinfo=timezone.utc),
            metadata={"batch": "b_001"},
        )
        record = mapper.reconcile(snapshot, reconciliation_id="recon_001")
        self.assertEqual("provider-pending", record.kernel_status)
        self.assertFalse(record.terminal)
        self.assertEqual("Provider accepted the operation but has not confirmed finality.", record.metadata["mapping_description"])

    def test_policy_bundle_round_trip_and_filtering(self) -> None:
        bundle = PolicyBundle(
            bundle_id="pb_001",
            issued_at=datetime(2026, 4, 6, 10, 0, tzinfo=timezone.utc),
            issuer="control-plane.example",
            tenant_id="tenant_demo",
            audiences=("service:protected-endpoint",),
            capabilities=("refund.execute",),
            rules=(
                PolicyBundleRule(
                    rule_id="tenant_demo.refund.approval",
                    effect="approval-required",
                    summary="Large refunds require approval.",
                    reason_code="APPROVAL_REQUIRED",
                    capabilities=("refund.execute",),
                    audiences=("service:protected-endpoint",),
                    approver_types=("finance-operator",),
                ),
                PolicyBundleRule(
                    rule_id="tenant_demo.refund.evidence",
                    effect="needs-evidence",
                    summary="Refunds over review threshold require evidence.",
                    reason_code="EVIDENCE_REQUIRED",
                    capabilities=("refund.execute",),
                    required_evidence_types=("external_id",),
                ),
            ),
        )
        payload = bundle.to_dict()
        restored = PolicyBundle.from_dict(payload)
        matched = restored.rules_for(capability="refund.execute", audience="service:protected-endpoint")
        self.assertEqual("policy_bundle", payload["contract"]["name"])
        self.assertEqual(2, len(restored.rules))
        self.assertEqual(2, len(matched))
        self.assertEqual("finance-operator", matched[0].approver_types[0])


if __name__ == "__main__":
    unittest.main()
