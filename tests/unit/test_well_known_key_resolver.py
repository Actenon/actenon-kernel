from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.request import Request

from actenon.core.errors import ProofVerificationError
from actenon.models import (
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
)
from actenon.proof import (
    ExpiredKeyError,
    KeyDiscoveryFetchError,
    KeyNotFoundError,
    KeyPurposeMismatchError,
    PCCBVerifier,
    RevokedKeyError,
    VerifierDisclosureMode,
    WellKnownKeyResolver,
    WellKnownKeySignatureVerifier,
    build_action_hash_input,
    canonicalize_bytes,
    sha256_hex,
)
from actenon.proof.signers import well_known as well_known_module
from actenon.proof.signers.base import b64url_encode

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
except Exception:  # pragma: no cover - exercised in core-only environments
    hashes = None
    padding = None
    rsa = None
    serialization = None
    ed25519 = None


class _StubFetcher:
    def __init__(self, payload: dict[str, object], headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.headers = headers or {"cache-control": "max-age=300"}
        self.calls = 0

    def __call__(self, url: str, timeout_seconds: float) -> tuple[dict[str, str], bytes]:
        self.calls += 1
        return self.headers, json.dumps(self.payload).encode("utf-8")


def _discovery_payload() -> dict[str, object]:
    return {
        "contract": {"name": "key_discovery", "version": "v1"},
        "issuer": {"type": "service", "id": "acme-proof-issuer"},
        "origin": "https://trust.acme.example",
        "published_at": "2026-04-11T12:00:00Z",
        "cache": {"max_age_seconds": 300},
        "keys": [
            {
                "key_id": "acme-proof-ed25519-2026-04",
                "algorithm": "EdDSA",
                "use": "verify",
                "status": "active",
                "not_before": "2026-04-01T00:00:00Z",
                "expires_at": "2027-04-01T00:00:00Z",
                "public_key_jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "acme-proof-ed25519-2026-04",
                    "alg": "EdDSA",
                    "x": "11qYAYLef1YF8TtN4b4x2zZC7FQ5a0jvL7vG64F8S4M",
                },
            },
            {
                "key_id": "acme-proof-ed25519-2025-10",
                "algorithm": "EdDSA",
                "use": "verify",
                "status": "retired",
                "not_before": "2025-10-01T00:00:00Z",
                "expires_at": "2026-06-01T00:00:00Z",
                "replaced_by": "acme-proof-ed25519-2026-04",
                "public_key_jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "acme-proof-ed25519-2025-10",
                    "alg": "EdDSA",
                    "x": "D75a98bz2Vj83Xk6d8Q2K7RZ4v8mR7P0iXJqZ6G8K9Q",
                },
            },
            {
                "key_id": "acme-proof-ed25519-2025-03",
                "algorithm": "EdDSA",
                "use": "verify",
                "status": "revoked",
                "not_before": "2025-03-01T00:00:00Z",
                "revoked_at": "2025-07-15T13:00:00Z",
                "revocation_reason": "signing-service-compromise",
                "public_key_jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "acme-proof-ed25519-2025-03",
                    "alg": "EdDSA",
                    "x": "nWGxne_9WmXo7vBvV9Y3h9kJ4q8gY5sM2y6N3sR8v1U",
                },
            },
            {
                "key_id": "acme-proof-ed25519-hard-revoked",
                "algorithm": "EdDSA",
                "use": "proof_issuance",
                "status": "hard_revoked",
                "not_before": "2025-03-01T00:00:00Z",
                "hard_revoked_at": "2025-07-15T13:00:00Z",
                "revocation_reason": {
                    "code": "timestamp_trust_loss",
                    "detail": "issuer timestamps are no longer trustworthy",
                },
                "public_key_jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "acme-proof-ed25519-hard-revoked",
                    "alg": "EdDSA",
                    "x": "nWGxne_9WmXo7vBvV9Y3h9kJ4q8gY5sM2y6N3sR8v1U",
                },
            },
        ],
    }


def _issued_at() -> datetime:
    return datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc)


def _test_intent() -> ActionIntent:
    return ActionIntent(
        intent_id="intent_well_known_001",
        issued_at=datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 4, 11, 12, 45, tzinfo=timezone.utc),
        tenant=TenantRef(tenant_id="tenant_acme"),
        requester=PartyRef(type="service", id="agent-runner"),
        action=ActionSpec(
            name="invoice_payment.execute",
            capability="invoice_payment.execute",
            parameters={"amount_minor": 4200, "currency": "USD", "invoice_id": "inv_001"},
        ),
        target=TargetRef(resource_type="invoice", resource_id="inv_001"),
    )


def _unsigned_pccb(intent: ActionIntent, *, key_id: str = "acme-proof-ed25519-2026-04") -> PCCB:
    return PCCB(
        pccb_id="pccb_well_known_001",
        intent_id=intent.intent_id,
        issued_at=_issued_at(),
        not_before=datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 4, 11, 12, 45, tzinfo=timezone.utc),
        issuer=PartyRef(type="service", id="acme-proof-issuer"),
        subject=intent.requester,
        tenant=intent.tenant,
        audience=AudienceRef(type="service", id="invoice-payment-endpoint"),
        action=intent.action,
        target=intent.target,
        scope=ScopeSpec(
            mode="exact",
            capabilities=("invoice_payment.execute",),
            single_use=True,
        ),
        nonce="nonce_well_known_001",
        action_hash=ActionHashSpec(
            algorithm="sha-256",
            canonicalization="RFC8785-JCS",
            value=sha256_hex(build_action_hash_input(intent)),
        ),
        signature=SignatureSpec(
            algorithm="EdDSA",
            key_id=key_id,
            encoding="base64url",
            value="pending",
        ),
    )


def _context() -> DynamicContextInput:
    return DynamicContextInput(
        request_id="req_well_known_001",
        audience=AudienceRef(type="service", id="invoice-payment-endpoint"),
        scope_capabilities=("invoice_payment.execute",),
        now=datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc),
    )


def _int_to_b64url(value: int) -> str:
    return b64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _fake_rsa_jwk(*, modulus_bits: int, exponent: int = 65537, key_id: str = "rsa-test") -> dict[str, object]:
    modulus = (1 << (modulus_bits - 1)) | 65537
    return {
        "kty": "RSA",
        "kid": key_id,
        "alg": "RS256",
        "n": _int_to_b64url(modulus),
        "e": _int_to_b64url(exponent),
    }


def _resolved_rsa_key(public_key_jwk: dict[str, object], *, key_id: str = "rsa-test") -> well_known_module.ResolvedVerificationKey:
    return well_known_module.ResolvedVerificationKey(
        issuer=PartyRef(type="service", id="rsa-issuer"),
        origin="https://trust.acme.example",
        published_at=datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
        key=well_known_module.DiscoveredVerificationKey(
            key_id=key_id,
            algorithm="RS256",
            use=("proof_issuance",),
            status="active",
            public_key_jwk=public_key_jwk,
        ),
    )


@unittest.skipIf(ed25519 is None or serialization is None, "cryptography is not installed")
class WellKnownEdDsaPCCBVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        self.private_key = private_key
        self.public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = "acme-proof-ed25519-2026-04"
        self.issuer = PartyRef(type="service", id="acme-proof-issuer")

    def _discovery_payload(self, *, use: str | list[str] = "proof_issuance", status: str = "active") -> dict[str, object]:
        return {
            "contract": {"name": "key_discovery", "version": "v1"},
            "issuer": {"type": "service", "id": "acme-proof-issuer"},
            "origin": "https://trust.acme.example",
            "published_at": "2026-04-11T12:00:00Z",
            "cache": {"max_age_seconds": 300},
            "keys": [
                {
                    "key_id": self.key_id,
                    "algorithm": "EdDSA",
                    "use": use,
                    "status": status,
                    "not_before": "2026-04-01T00:00:00Z",
                    "expires_at": "2027-04-01T00:00:00Z",
                    "public_key_jwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": self.key_id,
                        "alg": "EdDSA",
                        "x": b64url_encode(self.public_key_bytes),
                    },
                }
            ],
        }

    def _signed_pccb(self, *, signature_key_id: str | None = None, algorithm: str = "EdDSA", signature_value: str | None = None) -> tuple[ActionIntent, PCCB]:
        intent = _test_intent()
        unsigned = _unsigned_pccb(intent, key_id=signature_key_id or self.key_id)
        raw_signature = self.private_key.sign(canonicalize_bytes(unsigned.unsigned_payload()))
        signature = SignatureSpec(
            algorithm=algorithm,
            key_id=signature_key_id or self.key_id,
            encoding="base64url",
            value=signature_value or b64url_encode(raw_signature),
        )
        return intent, replace(unsigned, signature=signature)

    def _verifier(self, payload: dict[str, object]) -> PCCBVerifier:
        resolver = WellKnownKeyResolver(
            issuer_origin="https://trust.acme.example",
            fetch_document=_StubFetcher(payload),
        )
        return PCCBVerifier(WellKnownKeySignatureVerifier(resolver=resolver), disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG)

    def test_valid_ed25519_pccb_verifies_through_well_known_resolver(self) -> None:
        intent, pccb = self._signed_pccb()

        self._verifier(self._discovery_payload()).verify(intent, pccb, _context())

    def test_wrong_kid_fails_pccb_verification(self) -> None:
        intent, pccb = self._signed_pccb(signature_key_id="wrong-kid")

        with self.assertRaisesRegex(ProofVerificationError, "SIGNATURE_INVALID"):
            self._verifier(self._discovery_payload()).verify(intent, pccb, _context())

    def test_wrong_purpose_use_fails_pccb_verification(self) -> None:
        intent, pccb = self._signed_pccb()

        with self.assertRaisesRegex(ProofVerificationError, "SIGNATURE_INVALID"):
            self._verifier(self._discovery_payload(use="outcome_attestation")).verify(intent, pccb, _context())

    def test_algorithm_mismatch_fails_pccb_verification(self) -> None:
        intent, pccb = self._signed_pccb(algorithm="RS256")

        with self.assertRaisesRegex(ProofVerificationError, "SIGNATURE_INVALID"):
            self._verifier(self._discovery_payload()).verify(intent, pccb, _context())

    def test_padded_base64_signature_fails_pccb_verification(self) -> None:
        intent, pccb = self._signed_pccb()
        pccb = replace(pccb, signature=replace(pccb.signature, value=pccb.signature.value + "="))

        with self.assertRaisesRegex(ProofVerificationError, "SIGNATURE_INVALID"):
            self._verifier(self._discovery_payload()).verify(intent, pccb, _context())

    def test_der_wrapped_signature_fails_pccb_verification(self) -> None:
        intent = _test_intent()
        unsigned = _unsigned_pccb(intent, key_id=self.key_id)
        raw_signature = self.private_key.sign(canonicalize_bytes(unsigned.unsigned_payload()))
        der_like_signature = b64url_encode(b"\x30\x44" + raw_signature)
        pccb = replace(unsigned, signature=replace(unsigned.signature, value=der_like_signature))

        with self.assertRaisesRegex(ProofVerificationError, "SIGNATURE_INVALID"):
            self._verifier(self._discovery_payload()).verify(intent, pccb, _context())


@unittest.skipIf(rsa is None or padding is None or hashes is None, "cryptography is not installed")
class WellKnownRs256StrengthTests(unittest.TestCase):
    def test_512_bit_rsa_key_is_rejected(self) -> None:
        signature = SignatureSpec(
            algorithm="RS256",
            key_id="rsa-test",
            encoding="base64url",
            value=b64url_encode(b"signature"),
        )

        with self.assertRaisesRegex(well_known_module.KeyDiscoveryFormatError, "modulus size"):
            well_known_module._verify_signature_with_resolved_key(
                payload=b"payload",
                signature=signature,
                resolved_key=_resolved_rsa_key(_fake_rsa_jwk(modulus_bits=512)),
            )

    def test_1024_bit_rsa_key_is_rejected(self) -> None:
        signature = SignatureSpec(
            algorithm="RS256",
            key_id="rsa-test",
            encoding="base64url",
            value=b64url_encode(b"signature"),
        )

        with self.assertRaisesRegex(well_known_module.KeyDiscoveryFormatError, "modulus size"):
            well_known_module._verify_signature_with_resolved_key(
                payload=b"payload",
                signature=signature,
                resolved_key=_resolved_rsa_key(_fake_rsa_jwk(modulus_bits=1024)),
            )

    def test_2048_bit_rsa_key_is_accepted(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = private_key.public_key().public_numbers()
        payload = b"rsa-payload"
        raw_signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        signature = SignatureSpec(
            algorithm="RS256",
            key_id="rsa-test",
            encoding="base64url",
            value=b64url_encode(raw_signature),
        )
        jwk = {
            "kty": "RSA",
            "kid": "rsa-test",
            "alg": "RS256",
            "n": _int_to_b64url(public_numbers.n),
            "e": _int_to_b64url(public_numbers.e),
        }

        self.assertTrue(
            well_known_module._verify_signature_with_resolved_key(
                payload=payload,
                signature=signature,
                resolved_key=_resolved_rsa_key(jwk),
            )
        )

    def test_bad_rsa_public_exponent_is_rejected(self) -> None:
        signature = SignatureSpec(
            algorithm="RS256",
            key_id="rsa-test",
            encoding="base64url",
            value=b64url_encode(b"signature"),
        )

        with self.assertRaisesRegex(well_known_module.KeyDiscoveryFormatError, "public exponent 65537"):
            well_known_module._verify_signature_with_resolved_key(
                payload=b"payload",
                signature=signature,
                resolved_key=_resolved_rsa_key(_fake_rsa_jwk(modulus_bits=2048, exponent=3)),
            )


class WellKnownKeyResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fetcher = _StubFetcher(_discovery_payload())
        self.resolver = WellKnownKeyResolver(
            issuer_origin="https://trust.acme.example",
            fetch_document=self.fetcher,
        )
        self.issuer = PartyRef(type="service", id="acme-proof-issuer")

    def test_successful_resolution(self) -> None:
        resolved = self.resolver.resolve_key(
            key_id="acme-proof-ed25519-2026-04",
            algorithm="EdDSA",
            issued_at=datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc),
            issuer=self.issuer,
        )

        self.assertEqual("acme-proof-ed25519-2026-04", resolved.key.key_id)
        self.assertEqual("EdDSA", resolved.key.algorithm)
        self.assertEqual("active", resolved.key.status)
        self.assertEqual("https://trust.acme.example", resolved.origin)

    def test_retired_key_resolves_for_historical_issuance_time(self) -> None:
        resolved = self.resolver.resolve_key(
            key_id="acme-proof-ed25519-2025-10",
            algorithm="EdDSA",
            issued_at=datetime(2026, 5, 15, 12, 30, tzinfo=timezone.utc),
            issuer=self.issuer,
        )

        self.assertEqual("retired", resolved.key.status)

    def test_key_id_mismatch_raises_not_found(self) -> None:
        with self.assertRaises(KeyNotFoundError):
            self.resolver.resolve_key(
                key_id="missing-key",
                algorithm="EdDSA",
                issued_at=datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc),
                issuer=self.issuer,
            )

    def test_duplicate_key_in_discovery_document_is_rejected(self) -> None:
        body = b"""
        {
          "contract": {"name": "key_discovery", "name": "shadow", "version": "v1"},
          "issuer": {"type": "service", "id": "acme-proof-issuer"},
          "origin": "https://trust.acme.example",
          "published_at": "2026-04-11T12:00:00Z",
          "keys": []
        }
        """

        with self.assertRaisesRegex(well_known_module.KeyDiscoveryFormatError, "duplicate object keys"):
            well_known_module._parse_discovery_document(
                body=body,
                expected_origin="https://trust.acme.example",
                fetched_url="https://trust.acme.example/.well-known/actenon/keys.json",
            )

    def test_required_purpose_mismatch_is_rejected(self) -> None:
        with self.assertRaises(KeyPurposeMismatchError):
            self.resolver.resolve_key(
                key_id="acme-proof-ed25519-2026-04",
                algorithm="EdDSA",
                issued_at=datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc),
                issuer=self.issuer,
                required_use="proof_issuance",
            )

    def test_revoked_key_resolves_for_artifact_issued_before_revoked_at(self) -> None:
        resolved = self.resolver.resolve_key(
            key_id="acme-proof-ed25519-2025-03",
            algorithm="EdDSA",
            issued_at=datetime(2025, 7, 1, 12, 30, tzinfo=timezone.utc),
            issuer=self.issuer,
        )

        self.assertEqual("revoked", resolved.key.status)

    def test_revoked_key_is_rejected(self) -> None:
        with self.assertRaises(RevokedKeyError):
            self.resolver.resolve_key(
                key_id="acme-proof-ed25519-2025-03",
                algorithm="EdDSA",
                issued_at=datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc),
                issuer=self.issuer,
            )

    def test_hard_revoked_key_without_external_anchor_is_rejected(self) -> None:
        with self.assertRaises(RevokedKeyError):
            self.resolver.resolve_key(
                key_id="acme-proof-ed25519-hard-revoked",
                algorithm="EdDSA",
                issued_at=datetime(2025, 7, 1, 12, 30, tzinfo=timezone.utc),
                issuer=self.issuer,
                required_use="proof_issuance",
            )

    def test_suspended_key_is_rejected_fail_closed_for_this_pass(self) -> None:
        payload = _discovery_payload()
        payload["keys"][0]["status"] = "suspended"
        resolver = WellKnownKeyResolver(
            issuer_origin="https://trust.acme.example",
            fetch_document=_StubFetcher(payload),
        )

        with self.assertRaises(RevokedKeyError):
            resolver.resolve_key(
                key_id="acme-proof-ed25519-2026-04",
                algorithm="EdDSA",
                issued_at=datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc),
                issuer=self.issuer,
            )

    def test_expired_key_is_rejected(self) -> None:
        with self.assertRaises(ExpiredKeyError):
            self.resolver.resolve_key(
                key_id="acme-proof-ed25519-2025-10",
                algorithm="EdDSA",
                issued_at=datetime(2026, 6, 15, 12, 30, tzinfo=timezone.utc),
                issuer=self.issuer,
            )

    def test_cache_hit_reuses_cached_document(self) -> None:
        self.resolver.resolve_key(
            key_id="acme-proof-ed25519-2026-04",
            algorithm="EdDSA",
            issued_at=datetime(2026, 4, 11, 12, 30, tzinfo=timezone.utc),
            issuer=self.issuer,
        )
        self.resolver.resolve_key(
            key_id="acme-proof-ed25519-2026-04",
            algorithm="EdDSA",
            issued_at=datetime(2026, 4, 11, 12, 31, tzinfo=timezone.utc),
            issuer=self.issuer,
        )

        self.assertEqual(1, self.fetcher.calls)

    def test_default_redirect_handler_rejects_same_origin_redirect(self) -> None:
        request = Request("https://trust.acme.example/.well-known/actenon/keys.json")
        redirect = well_known_module._NoRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://trust.acme.example/.well-known/actenon/keys.json",
        )

        self.assertIsNone(redirect)

    def test_different_origin_redirect_target_is_rejected_by_url_policy(self) -> None:
        with self.assertRaises(KeyDiscoveryFetchError):
            well_known_module._validate_well_known_fetch_url(
                "https://evil.example/.well-known/actenon/keys.json",
                expected_origin="https://trust.acme.example",
                resolve_host=False,
            )

    def test_http_redirect_target_is_rejected_by_url_policy(self) -> None:
        with self.assertRaises(KeyDiscoveryFetchError):
            well_known_module._validate_well_known_fetch_url(
                "http://trust.acme.example/.well-known/actenon/keys.json",
                expected_origin="https://trust.acme.example",
                resolve_host=False,
            )

    def test_loopback_redirect_target_is_rejected_by_url_policy(self) -> None:
        with self.assertRaises(KeyDiscoveryFetchError):
            well_known_module._validate_well_known_fetch_url(
                "https://127.0.0.1/.well-known/actenon/keys.json",
                expected_origin="https://127.0.0.1",
                resolve_host=False,
            )

    def test_metadata_redirect_target_is_rejected_by_url_policy(self) -> None:
        with self.assertRaises(KeyDiscoveryFetchError):
            well_known_module._validate_well_known_fetch_url(
                "https://169.254.169.254/.well-known/actenon/keys.json",
                expected_origin="https://169.254.169.254",
                resolve_host=False,
            )

    def test_direct_private_ip_issuer_origin_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            WellKnownKeyResolver(
                issuer_origin="https://10.0.0.10",
                fetch_document=_StubFetcher(_discovery_payload()),
            )

    def test_default_fetcher_rejects_private_dns_resolution_before_opening_url(self) -> None:
        with (
            patch.object(
                well_known_module.socket,
                "getaddrinfo",
                return_value=[
                    (
                        well_known_module.socket.AF_INET,
                        well_known_module.socket.SOCK_STREAM,
                        6,
                        "",
                        ("10.0.0.10", 443),
                    )
                ],
            ),
            patch.object(well_known_module, "build_opener") as build_opener,
        ):
            with self.assertRaises(KeyDiscoveryFetchError):
                well_known_module._default_fetch_document(
                    "https://trust.acme.example/.well-known/actenon/keys.json",
                    1.0,
                )

        build_opener.assert_not_called()

    def test_non_canonical_well_known_path_is_rejected_before_fetch(self) -> None:
        with self.assertRaises(KeyDiscoveryFetchError):
            well_known_module._validate_well_known_fetch_url(
                "https://trust.acme.example/.well-known/actenon/keys.json/extra",
                expected_origin="https://trust.acme.example",
                resolve_host=False,
            )


if __name__ == "__main__":
    unittest.main()
