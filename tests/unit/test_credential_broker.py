from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PartyRef,
    PolicyDecision,
    ProtectedExecutionRequest,
    TargetRef,
    TenantRef,
)
from actenon.proof import PCCBMinter, PCCBVerifier
from actenon.proof.signers import HmacSha256Signer


class CredentialBrokerTests(unittest.TestCase):
    def _request(self, *, now: datetime | None = None) -> ProtectedExecutionRequest:
        resolved_now = now or datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        intent = ActionIntent(
            intent_id="intent_broker_001",
            issued_at=resolved_now,
            expires_at=resolved_now + timedelta(minutes=10),
            tenant=TenantRef(tenant_id="tenant_alpha"),
            requester=PartyRef(type="agent", id="agent_planner"),
            action=ActionSpec(
                name="volume.delete",
                capability="infrastructure.delete",
                parameters={"environment": "sandbox", "resource_id": "sandbox-volume-001"},
            ),
            target=TargetRef(resource_type="volume", resource_id="sandbox-volume-001"),
            justification="Remove disposable sandbox volume.",
        )
        context = DynamicContextInput(
            request_id="req_broker_001",
            audience=AudienceRef(type="service", id="infra-delete-protected-endpoint"),
            scope_capabilities=("infrastructure.delete",),
            now=resolved_now,
        )
        signer = HmacSha256Signer(secret=b"broker-test-secret", key_id="broker-test-key")
        pccb = PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="actenon-kernel"),
            pccb_id_factory=lambda: "pccb_broker_001",
            nonce_factory=lambda: "nonce-broker-001",
        ).mint(
            intent,
            decision=PolicyDecision(
                outcome="allow",
                summary="Sandbox infrastructure delete is allowed.",
                rule_evaluations=(),
                reason_codes=("INFRA_DELETE_ALLOWED_SANDBOX",),
            ),
            context=context,
        )
        PCCBVerifier(signer).verify(intent, pccb, context)
        return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

    def test_in_memory_broker_issues_short_lived_reference_without_raw_secret(self) -> None:
        request = self._request()
        broker = InMemoryCredentialBroker(
            ttl=timedelta(seconds=30),
            credential_id_factory=lambda: "cred_broker_001",
        )

        credential = broker.acquire(request.intent, request.pccb, request.context)
        public = credential.to_public_dict()

        self.assertIsInstance(credential, BrokeredCredential)
        self.assertEqual("cred_broker_001", credential.credential_id)
        self.assertEqual(("infrastructure.delete",), credential.scope)
        self.assertLessEqual(credential.expires_at, request.context.now + timedelta(seconds=30))
        self.assertLessEqual(credential.expires_at, request.pccb.expires_at)
        self.assertIn("secret_reference", public)
        self.assertNotIn("secret", public)
        self.assertNotIn("raw_secret", public)

    def test_in_memory_broker_records_release_without_revealing_secret(self) -> None:
        request = self._request()
        broker = InMemoryCredentialBroker(credential_id_factory=lambda: "cred_broker_001")
        credential = broker.acquire(request.intent, request.pccb, request.context)

        broker.release(credential, {"outcome": "executed"})

        self.assertEqual([(credential, {"outcome": "executed"})], broker.released_credentials)


if __name__ == "__main__":
    unittest.main()
