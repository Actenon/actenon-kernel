from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from actenon.core.errors import ProofVerificationError
from actenon.models import PartyRef, SignatureSpec
from actenon.proof import PCCBVerifier
from actenon.proof.signers import well_known as well_known_module
from actenon.proof.signers.base import b64url_encode

from .helpers import build_security_context, build_security_intent, mint_security_pccb, mutate_signature_bytes, security_signer

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
except Exception:  # pragma: no cover - exercised in core-only environments
    ed25519 = None
    hashes = None
    padding = None
    rsa = None
    serialization = None


def _assert_signature_invalid(testcase: unittest.TestCase, pccb) -> None:
    with testcase.assertRaisesRegex(ProofVerificationError, "SIGNATURE_INVALID"):
        PCCBVerifier(security_signer()).verify(build_security_intent(), pccb, build_security_context())


def _int_to_b64url(value: int) -> str:
    return b64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _resolved_key(*, algorithm: str, key_id: str, public_key_jwk: dict[str, object]) -> well_known_module.ResolvedVerificationKey:
    return well_known_module.ResolvedVerificationKey(
        issuer=PartyRef(type="service", id="issuer"),
        origin="https://trust.example",
        published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        key=well_known_module.DiscoveredVerificationKey(
            key_id=key_id,
            algorithm=algorithm,
            use=("proof_issuance",),
            status="active",
            public_key_jwk=public_key_jwk,
        ),
    )


class SignatureAttackTests(unittest.TestCase):
    def test_alg_none_is_rejected(self) -> None:
        pccb = mint_security_pccb()
        attacked = replace(pccb, signature=replace(pccb.signature, algorithm="none", value=""))

        _assert_signature_invalid(self, attacked)

    def test_hmac_asymmetric_confusion_is_rejected(self) -> None:
        pccb = mint_security_pccb()
        attacked = replace(pccb, signature=replace(pccb.signature, algorithm="RS256"))

        _assert_signature_invalid(self, attacked)

    def test_wrong_kid_is_rejected(self) -> None:
        pccb = mint_security_pccb()
        attacked = replace(pccb, signature=replace(pccb.signature, key_id="wrong-kid"))

        _assert_signature_invalid(self, attacked)

    def test_signature_truncation_extension_and_single_byte_mutation_are_rejected(self) -> None:
        pccb = mint_security_pccb()

        for mutation in ("truncate", "extend", "single-byte"):
            with self.subTest(mutation=mutation):
                _assert_signature_invalid(self, mutate_signature_bytes(pccb, mutation))

    def test_empty_and_malformed_base64_signatures_are_rejected(self) -> None:
        pccb = mint_security_pccb()

        for raw_value in ("", "!!!!", "@@@", "not_base64!"):
            with self.subTest(value=raw_value):
                attacked = replace(pccb, signature=replace(pccb.signature, value=raw_value))
                _assert_signature_invalid(self, attacked)

    def test_base64url_helper_decodes_unpadded_values_without_requiring_padding(self) -> None:
        from actenon.proof.signers.base import b64url_decode

        self.assertEqual(b"\xfb\xff\x00", b64url_decode("-_8A"))
        self.assertEqual("-_8A", b64url_encode(b"\xfb\xff\x00"))


@unittest.skipIf(ed25519 is None or serialization is None or rsa is None or padding is None or hashes is None, "cryptography is not installed")
class AsymmetricSignatureAttackTests(unittest.TestCase):
    def test_eddsa_key_used_for_rs256_is_rejected(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        signature = SignatureSpec(
            algorithm="RS256",
            key_id="ed-key",
            encoding="base64url",
            value=b64url_encode(b"signature"),
        )
        resolved = _resolved_key(
            algorithm="RS256",
            key_id="ed-key",
            public_key_jwk={
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "ed-key",
                "alg": "RS256",
                "x": b64url_encode(public_bytes),
            },
        )

        with self.assertRaises(well_known_module.KeyDiscoveryFormatError):
            well_known_module._verify_signature_with_resolved_key(
                payload=b"payload",
                signature=signature,
                resolved_key=resolved,
            )

    def test_rsa_key_used_for_eddsa_is_rejected(self) -> None:
        signature = SignatureSpec(
            algorithm="EdDSA",
            key_id="rsa-key",
            encoding="base64url",
            value=b64url_encode(b"x" * 64),
        )
        resolved = _resolved_key(
            algorithm="EdDSA",
            key_id="rsa-key",
            public_key_jwk={
                "kty": "RSA",
                "kid": "rsa-key",
                "alg": "EdDSA",
                "n": _int_to_b64url((1 << 2047) | 65537),
                "e": _int_to_b64url(65537),
            },
        )

        with self.assertRaises(well_known_module.KeyDiscoveryFormatError):
            well_known_module._verify_signature_with_resolved_key(
                payload=b"payload",
                signature=signature,
                resolved_key=resolved,
            )

    def test_wrong_key_purpose_is_rejected(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        payload = {
            "contract": {"name": "key_discovery", "version": "v1"},
            "issuer": {"type": "service", "id": "issuer"},
            "origin": "https://trust.example",
            "published_at": "2026-01-01T00:00:00Z",
            "keys": [
                {
                    "key_id": "ed-key",
                    "algorithm": "EdDSA",
                    "use": "outcome_attestation",
                    "status": "active",
                    "public_key_jwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": "ed-key",
                        "alg": "EdDSA",
                        "x": b64url_encode(public_bytes),
                    },
                }
            ],
        }

        resolver = well_known_module.WellKnownKeyResolver(
            issuer_origin="https://trust.example",
            fetch_document=lambda _url, _timeout: ({}, json.dumps(payload).encode("utf-8")),
        )

        with self.assertRaises(well_known_module.KeyPurposeMismatchError):
            resolver.resolve_key(
                key_id="ed-key",
                algorithm="EdDSA",
                issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                issuer=PartyRef(type="service", id="issuer"),
                required_use="proof_issuance",
            )

    def test_der_wrapped_eddsa_signature_is_rejected_but_valid_raw_signature_is_accepted(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        payload = b"payload"
        raw_signature = private_key.sign(payload)
        resolved = _resolved_key(
            algorithm="EdDSA",
            key_id="ed-key",
            public_key_jwk={
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "ed-key",
                "alg": "EdDSA",
                "x": b64url_encode(public_bytes),
            },
        )

        self.assertTrue(
            well_known_module._verify_signature_with_resolved_key(
                payload=payload,
                signature=SignatureSpec(
                    algorithm="EdDSA",
                    key_id="ed-key",
                    encoding="base64url",
                    value=b64url_encode(raw_signature),
                ),
                resolved_key=resolved,
            )
        )
        self.assertFalse(
            well_known_module._verify_signature_with_resolved_key(
                payload=payload,
                signature=SignatureSpec(
                    algorithm="EdDSA",
                    key_id="ed-key",
                    encoding="base64url",
                    value=b64url_encode(b"\x30\x44" + raw_signature),
                ),
                resolved_key=resolved,
            )
        )

    def test_weak_rsa_key_is_rejected_after_hardening(self) -> None:
        signature = SignatureSpec(
            algorithm="RS256",
            key_id="rsa-weak",
            encoding="base64url",
            value=b64url_encode(b"signature"),
        )
        resolved = _resolved_key(
            algorithm="RS256",
            key_id="rsa-weak",
            public_key_jwk={
                "kty": "RSA",
                "kid": "rsa-weak",
                "alg": "RS256",
                "n": _int_to_b64url((1 << 1023) | 65537),
                "e": _int_to_b64url(65537),
            },
        )

        with self.assertRaisesRegex(well_known_module.KeyDiscoveryFormatError, "modulus size"):
            well_known_module._verify_signature_with_resolved_key(
                payload=b"payload",
                signature=signature,
                resolved_key=resolved,
            )


if __name__ == "__main__":
    unittest.main()
