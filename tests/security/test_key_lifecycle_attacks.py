from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from actenon.anchors import LocalAppendOnlyAnchorLog
from actenon.models import ActionSpec, CorrelationRef, PartyRef, Receipt, TargetRef, TenantRef
from actenon.proof import WellKnownKeyResolver, WellKnownKeySignatureVerifier
from actenon.proof.signers.base import b64url_encode
from actenon.receipts import OutcomeAttestationService, OutcomeAttestationVerificationError

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except Exception:  # pragma: no cover - exercised in core-only environments
    ed25519 = None
    serialization = None


class _StubFetcher:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __call__(self, url: str, timeout_seconds: float) -> tuple[dict[str, str], bytes]:
        del url, timeout_seconds
        return {"cache-control": "max-age=300"}, json.dumps(self.payload).encode("utf-8")


class _Ed25519Signer:
    algorithm = "EdDSA"
    key_id = "security-outcome-key"

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
        del payload, signature
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
        receipt_id="rcpt_security_anchor_001",
        intent_id="intent_security_anchor_001",
        occurred_at=datetime(2026, 4, 10, 9, 0, tzinfo=timezone.utc),
        outcome="executed",
        tenant=TenantRef(tenant_id="tenant_security"),
        subject=PartyRef(type="service", id="protected_endpoint"),
        action=ActionSpec(
            name="payment.release",
            capability="payment.release",
            parameters={"amount_minor": 1000, "currency": "USD"},
        ),
        target=TargetRef(resource_type="payment", resource_id="payment_001"),
        summary="Payment release executed through the protected endpoint.",
        phase="execution",
        correlation=CorrelationRef(pccb_id="pccb_security_001", request_id="req_security_001"),
        side_effects={"external_reference": "payment_release_001"},
    )


def _opaque_anchor(artifact_digest: dict[str, str]) -> dict[str, object]:
    return {
        "type": "opaque",
        "anchor_id": "anchor_opaque_security",
        "anchored_at": "2026-04-10T09:03:00Z",
        "artifact_digest": dict(artifact_digest),
        "trust_root": {"type": "network_id", "id": "local-security-test"},
        "proof": {"format": "opaque", "value": None},
        "metadata": {},
    }


def _service_and_verifier(
    signer: _Ed25519Signer,
    *,
    status: str,
    anchor_log: LocalAppendOnlyAnchorLog | None,
    hard_revoked_at: str | None = None,
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
            attestation_id_factory=lambda: "att_security_anchor_001",
            external_anchor_verifier=anchor_log,
        ),
        WellKnownKeySignatureVerifier(
            resolver=resolver,
            required_use="outcome_attestation",
        ),
    )


@unittest.skipIf(ed25519 is None or serialization is None, "cryptography is not installed")
class ExternalAnchorAttackTests(unittest.TestCase):
    def test_external_anchor_is_outside_unsigned_payload_and_signature_still_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            signer = _Ed25519Signer()
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service, verifier = _service_and_verifier(signer, status="active", anchor_log=anchor_log)
            attestation = service.attest_receipt(_receipt(), issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc))
            signature_before = attestation.signature
            unsigned_before = attestation.unsigned_payload()

            anchored = anchor_log.append_anchor_to_attestation(
                attestation,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )
            verified = service.verify_receipt_attestation(anchored, verifier=verifier)

            self.assertNotIn("external_anchors", anchored.unsigned_payload())
            self.assertEqual(unsigned_before, anchored.unsigned_payload())
            self.assertEqual(signature_before, anchored.signature)
            self.assertEqual(_receipt().receipt_id, verified.receipt_id)

    def test_opaque_anchor_without_verifier_does_not_invalidate_active_issuer_signature(self) -> None:
        signer = _Ed25519Signer()
        service, verifier = _service_and_verifier(signer, status="active", anchor_log=None)
        attestation = service.attest_receipt(_receipt(), issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc))
        anchored = replace(attestation, external_anchors=[_opaque_anchor(attestation.artifact_digest)])

        verified = service.verify_receipt_attestation(anchored, verifier=verifier)

        self.assertEqual(_receipt().receipt_id, verified.receipt_id)
        self.assertEqual(attestation.signature, anchored.signature)
        self.assertEqual(attestation.unsigned_payload(), anchored.unsigned_payload())

    def test_wrong_anchor_digest_fails_when_verifier_is_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            signer = _Ed25519Signer()
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service, verifier = _service_and_verifier(signer, status="active", anchor_log=anchor_log)
            attestation = service.attest_receipt(_receipt(), issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc))
            wrong_anchor = anchor_log.anchor_artifact_digest(
                {"algorithm": "sha-256", "value": "0" * 64},
                artifact_type="receipt",
                artifact_id=_receipt().receipt_id,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )
            anchored = replace(attestation, external_anchors=[wrong_anchor.to_dict()])

            with self.assertRaisesRegex(OutcomeAttestationVerificationError, "artifact_digest"):
                service.verify_receipt_attestation(anchored, verifier=verifier)

    def test_hard_revoked_without_anchor_fails(self) -> None:
        signer = _Ed25519Signer()
        service, verifier = _service_and_verifier(
            signer,
            status="hard_revoked",
            anchor_log=None,
            hard_revoked_at="2026-04-10T10:00:00Z",
        )
        attestation = service.attest_receipt(_receipt(), issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc))

        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_receipt_attestation(attestation, verifier=verifier)

    def test_hard_revoked_with_anchor_but_no_anchor_verifier_fails(self) -> None:
        signer = _Ed25519Signer()
        service, verifier = _service_and_verifier(
            signer,
            status="hard_revoked",
            anchor_log=None,
            hard_revoked_at="2026-04-10T10:00:00Z",
        )
        attestation = service.attest_receipt(_receipt(), issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc))
        anchored = replace(attestation, external_anchors=[_opaque_anchor(attestation.artifact_digest)])

        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_receipt_attestation(anchored, verifier=verifier)

    def test_hard_revoked_with_valid_local_anchor_recovers_historical_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            signer = _Ed25519Signer()
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service, verifier = _service_and_verifier(
                signer,
                status="hard_revoked",
                anchor_log=anchor_log,
                hard_revoked_at="2026-04-10T10:00:00Z",
            )
            attestation = service.attest_receipt(_receipt(), issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc))
            anchored = anchor_log.append_anchor_to_attestation(
                attestation,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )

            verified = service.verify_receipt_attestation(anchored, verifier=verifier)

            self.assertEqual(_receipt().receipt_id, verified.receipt_id)

    def test_anchor_added_after_signing_does_not_change_artifact_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            signer = _Ed25519Signer()
            anchor_log = LocalAppendOnlyAnchorLog(Path(tempdir) / "anchors.jsonl")
            service, _verifier = _service_and_verifier(signer, status="active", anchor_log=anchor_log)
            attestation = service.attest_receipt(_receipt(), issued_at=datetime(2026, 4, 10, 9, 2, tzinfo=timezone.utc))

            anchored = anchor_log.append_anchor_to_attestation(
                attestation,
                anchored_at=datetime(2026, 4, 10, 9, 3, tzinfo=timezone.utc),
            )

            self.assertEqual(attestation.artifact_digest, anchored.artifact_digest)
            self.assertEqual(attestation.unsigned_payload(), anchored.unsigned_payload())


if __name__ == "__main__":
    unittest.main()
