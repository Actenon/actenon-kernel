from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from actenon.anchors import LocalAppendOnlyAnchorLog
from actenon.models import ActionSpec, CorrelationRef, PartyRef, Receipt, Refusal, TargetRef, TenantRef
from actenon.proof import WellKnownKeyResolver, WellKnownKeySignatureVerifier, build_local_proof_signer
from actenon.proof.signers.base import b64url_encode
from actenon.receipts import OutcomeAttestationService, OutcomeAttestationVerificationError

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except Exception:  # pragma: no cover - exercised in core-only environments
    serialization = None
    ed25519 = None


class _StubFetcher:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __call__(self, url: str, timeout_seconds: float) -> tuple[dict[str, str], bytes]:
        del url, timeout_seconds
        return {"cache-control": "max-age=300"}, json.dumps(self.payload).encode("utf-8")


class _Ed25519Signer:
    algorithm = "EdDSA"
    key_id = "outcome-hard-revoked-key"

    def __init__(self) -> None:
        if ed25519 is None:
            raise RuntimeError("cryptography is required for Ed25519 tests")
        self.private_key = ed25519.Ed25519PrivateKey.generate()

    def sign(self, payload: bytes):
        from actenon.models import SignatureSpec

        return SignatureSpec(
            algorithm=self.algorithm,
            key_id=self.key_id,
            encoding="base64url",
            value=b64url_encode(self.private_key.sign(payload)),
        )

    def verify(self, payload: bytes, signature) -> bool:
        return False

    def public_jwk(self) -> dict[str, str]:
        public_key = self.private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.key_id,
            "alg": "EdDSA",
            "use": "sig",
            "x": b64url_encode(public_bytes),
        }


def _receipt() -> Receipt:
    return Receipt(
        receipt_id="rcpt_anchor_001",
        intent_id="intent_anchor_001",
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


def _refusal() -> Refusal:
    return Refusal(
        refusal_id="rfsl_anchor_001",
        category="proof",
            reason_code="AUDIENCE_MISMATCH",
        message="The proof audience does not match this endpoint.",
        retryable=False,
        refused_at=datetime(2026, 4, 10, 9, 1, tzinfo=timezone.utc),
        intent_id="intent_anchor_001",
        tenant=TenantRef(tenant_id="tenant_alpha"),
        subject=PartyRef(type="service", id="actor_123"),
        action=ActionSpec(
            name="refund.create",
            capability="refund.execute",
            parameters={"amount_minor": 1000, "currency": "USD"},
        ),
        target=TargetRef(resource_type="payment", resource_id="pay_001"),
        correlation=CorrelationRef(pccb_id="pccb_001", request_id="req_001"),
        details={"expected_audience": "service:payments", "observed_audience": "service:wrong"},
    )


def _local_service(anchor_log: LocalAppendOnlyAnchorLog) -> OutcomeAttestationService:
    return OutcomeAttestationService(
        signer=build_local_proof_signer(),
        issuer=PartyRef(type="service", id="protected-endpoint"),
        attestation_id_factory=lambda: "att_anchor_001",
        external_anchor_verifier=anchor_log,
    )


def _opaque_anchor(artifact_digest: dict[str, str]) -> dict[str, object]:
    return {
        "type": "opaque",
        "anchor_id": "anchor_opaque_demo",
        "anchored_at": "2026-04-10T09:03:00Z",
        "artifact_digest": dict(artifact_digest),
        "trust_root": {"type": "network_id", "id": "demo"},
        "proof": {"format": "opaque", "value": None},
        "metadata": {},
    }


class LocalExternalAnchorTests(unittest.TestCase):
    def test_anchor_can_be_added_after_signature_and_signature_remains_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service = _local_service(anchor_log)
            attestation = service.attest_receipt(_receipt())
            signature_before = attestation.signature
            unsigned_before = attestation.unsigned_payload()

            anchored = anchor_log.append_anchor_to_attestation(
                attestation,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )
            verified = service.verify_receipt_attestation(anchored)

            self.assertEqual(signature_before, anchored.signature)
            self.assertEqual(unsigned_before, anchored.unsigned_payload())
            self.assertNotIn("external_anchors", anchored.unsigned_payload())
            self.assertEqual(_receipt().receipt_id, verified.receipt_id)

    def test_refusal_anchor_commits_to_refusal_artifact_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service = _local_service(anchor_log)
            attestation = service.attest_refusal(_refusal())

            anchored = anchor_log.append_anchor_to_attestation(
                attestation,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )
            anchor = anchored.external_anchors[0]
            verified = service.verify_refusal_attestation(anchored)

            self.assertEqual("refusal", anchor["artifact_type"])
            self.assertEqual(attestation.artifact_digest, anchor["artifact_digest"])
            self.assertEqual(_refusal().refusal_id, verified.refusal_id)

    def test_wrong_digest_anchor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service = _local_service(anchor_log)
            attestation = service.attest_receipt(_receipt())
            wrong_anchor = anchor_log.anchor_artifact_digest(
                {"algorithm": "sha-256", "value": "0" * 64},
                artifact_type="receipt",
                artifact_id=_receipt().receipt_id,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )
            anchored = replace(attestation, external_anchors=[wrong_anchor.to_dict()])

            with self.assertRaisesRegex(OutcomeAttestationVerificationError, "artifact_digest"):
                service.verify_receipt_attestation(anchored)

    def test_opaque_anchor_without_verifier_is_advisory_for_issuer_signature(self) -> None:
        service = OutcomeAttestationService(
            signer=build_local_proof_signer(),
            issuer=PartyRef(type="service", id="protected-endpoint"),
            attestation_id_factory=lambda: "att_anchor_001",
        )
        attestation = service.attest_receipt(_receipt())
        anchored = replace(
            attestation,
            external_anchors=[_opaque_anchor(attestation.artifact_digest)],
        )

        verified = service.verify_receipt_attestation(anchored)

        self.assertEqual(_receipt().receipt_id, verified.receipt_id)
        self.assertEqual(attestation.signature, anchored.signature)
        self.assertEqual(attestation.unsigned_payload(), anchored.unsigned_payload())

    def test_opaque_anchor_with_local_verifier_is_advisory_when_unrecognized(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service = _local_service(anchor_log)
            attestation = service.attest_receipt(_receipt())
            anchored = replace(
                attestation,
                external_anchors=[_opaque_anchor(attestation.artifact_digest)],
            )

            verified = service.verify_receipt_attestation(anchored)

            self.assertEqual(_receipt().receipt_id, verified.receipt_id)


@unittest.skipIf(ed25519 is None or serialization is None, "cryptography is not installed")
class HardRevokedOutcomeAttestationAnchorTests(unittest.TestCase):
    def _service_and_verifier_for_status(
        self,
        signer: _Ed25519Signer,
        *,
        status: str,
        anchor_log: LocalAppendOnlyAnchorLog | None,
        hard_revoked_at: str | None = None,
        revoked_at: str | None = None,
    ) -> tuple[OutcomeAttestationService, WellKnownKeySignatureVerifier]:
        issuer = PartyRef(type="service", id="protected-endpoint")
        key_payload: dict[str, object] = {
            "key_id": signer.key_id,
            "algorithm": "EdDSA",
            "use": "outcome_attestation",
            "status": status,
            "not_before": "2026-04-01T00:00:00Z",
            "public_key_jwk": signer.public_jwk(),
        }
        if hard_revoked_at is not None:
            key_payload["hard_revoked_at"] = hard_revoked_at
        if revoked_at is not None:
            key_payload["revoked_at"] = revoked_at
        discovery_payload: dict[str, object] = {
            "contract": {"name": "key_discovery", "version": "v1"},
            "issuer": issuer.to_dict(),
            "origin": "https://trust.example",
            "published_at": "2026-04-10T10:01:00Z",
            "cache": {"max_age_seconds": 300},
            "keys": [key_payload],
        }
        resolver = WellKnownKeyResolver(
            issuer_origin="https://trust.example",
            fetch_document=_StubFetcher(discovery_payload),
        )
        return (
            OutcomeAttestationService(
                signer=signer,
                issuer=issuer,
                attestation_id_factory=lambda: "att_hard_revoked_001",
                external_anchor_verifier=anchor_log,
            ),
            WellKnownKeySignatureVerifier(
                resolver=resolver,
                required_use="outcome_attestation",
            ),
        )

    def _service_and_verifier(
        self,
        anchor_log: LocalAppendOnlyAnchorLog,
        signer: _Ed25519Signer,
    ) -> tuple[OutcomeAttestationService, WellKnownKeySignatureVerifier]:
        return self._service_and_verifier_for_status(
            signer,
            status="hard_revoked",
            anchor_log=anchor_log,
            hard_revoked_at="2026-04-10T10:00:00Z",
        )

    def test_active_key_with_anchor_and_no_anchor_verifier_passes_issuer_verification(self) -> None:
        signer = _Ed25519Signer()
        service, verifier = self._service_and_verifier_for_status(
            signer,
            status="active",
            anchor_log=None,
        )
        attestation = service.attest_receipt(
            _receipt(),
            issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc),
        )
        anchored = replace(attestation, external_anchors=[_opaque_anchor(attestation.artifact_digest)])

        verified = service.verify_receipt_attestation(anchored, verifier=verifier)

        self.assertEqual(_receipt().receipt_id, verified.receipt_id)

    def test_retired_key_with_anchor_and_no_anchor_verifier_passes_historical_issuer_verification(self) -> None:
        signer = _Ed25519Signer()
        service, verifier = self._service_and_verifier_for_status(
            signer,
            status="retired",
            anchor_log=None,
        )
        attestation = service.attest_receipt(
            _receipt(),
            issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc),
        )
        anchored = replace(attestation, external_anchors=[_opaque_anchor(attestation.artifact_digest)])

        verified = service.verify_receipt_attestation(anchored, verifier=verifier)

        self.assertEqual(_receipt().receipt_id, verified.receipt_id)

    def test_soft_revoked_historical_key_with_anchor_and_no_anchor_verifier_passes_issuer_verification(self) -> None:
        signer = _Ed25519Signer()
        service, verifier = self._service_and_verifier_for_status(
            signer,
            status="revoked",
            anchor_log=None,
            revoked_at="2026-04-10T10:00:00Z",
        )
        attestation = service.attest_receipt(
            _receipt(),
            issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc),
        )
        anchored = replace(attestation, external_anchors=[_opaque_anchor(attestation.artifact_digest)])

        verified = service.verify_receipt_attestation(anchored, verifier=verifier)

        self.assertEqual(_receipt().receipt_id, verified.receipt_id)

    def test_hard_revoked_without_anchor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            signer = _Ed25519Signer()
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service, verifier = self._service_and_verifier(anchor_log, signer)
            attestation = service.attest_receipt(
                _receipt(),
                issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc),
            )

            with self.assertRaises(OutcomeAttestationVerificationError):
                service.verify_receipt_attestation(attestation, verifier=verifier)

    def test_hard_revoked_with_anchor_but_no_anchor_verifier_fails(self) -> None:
        signer = _Ed25519Signer()
        service, verifier = self._service_and_verifier_for_status(
            signer,
            status="hard_revoked",
            anchor_log=None,
            hard_revoked_at="2026-04-10T10:00:00Z",
        )
        attestation = service.attest_receipt(
            _receipt(),
            issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc),
        )
        anchored = replace(attestation, external_anchors=[_opaque_anchor(attestation.artifact_digest)])

        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_receipt_attestation(anchored, verifier=verifier)

    def test_hard_revoked_with_valid_local_anchor_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            signer = _Ed25519Signer()
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service, verifier = self._service_and_verifier(anchor_log, signer)
            attestation = service.attest_receipt(
                _receipt(),
                issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc),
            )
            anchored = anchor_log.append_anchor_to_attestation(
                attestation,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )

            verified = service.verify_receipt_attestation(anchored, verifier=verifier)

            self.assertEqual(_receipt().receipt_id, verified.receipt_id)


if __name__ == "__main__":
    unittest.main()
