from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from actenon.models import PartyRef
from actenon.proof.signers import well_known as well_known_module
from actenon.proof.signers.base import b64url_encode


ISSUER = PartyRef(type="service", id="issuer")
ISSUED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _public_jwk(key_id: str = "ed-key") -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": key_id,
        "alg": "EdDSA",
        "x": b64url_encode(b"x" * 32),
    }


def _document(*, keys: list[dict[str, object]], origin: str = "https://trust.example", issuer: PartyRef = ISSUER) -> dict[str, object]:
    return {
        "contract": {"name": "key_discovery", "version": "v1"},
        "issuer": issuer.to_dict(),
        "origin": origin,
        "published_at": "2026-01-01T00:00:00Z",
        "keys": keys,
    }


def _key(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "key_id": "ed-key",
        "algorithm": "EdDSA",
        "use": "proof_issuance",
        "status": "active",
        "public_key_jwk": _public_jwk(),
    }
    payload.update(overrides)
    return payload


def _resolver_with_body(body: bytes):
    return well_known_module.WellKnownKeyResolver(
        issuer_origin="https://trust.example",
        fetch_document=lambda _url, _timeout: ({"cache-control": "max-age=1"}, body),
    )


def _resolver(payload: dict[str, object]):
    return _resolver_with_body(json.dumps(payload).encode("utf-8"))


class WellKnownResolverAttackTests(unittest.TestCase):
    def test_redirect_target_policies_reject_cross_origin_http_local_private_and_metadata(self) -> None:
        cases = [
            ("https://evil.example/.well-known/actenon/keys.json", "https://trust.example"),
            ("http://trust.example/.well-known/actenon/keys.json", "https://trust.example"),
            ("https://127.0.0.1/.well-known/actenon/keys.json", "https://127.0.0.1"),
            ("https://10.0.0.1/.well-known/actenon/keys.json", "https://10.0.0.1"),
            ("https://169.254.169.254/.well-known/actenon/keys.json", "https://169.254.169.254"),
        ]
        for url, expected_origin in cases:
            with self.subTest(url=url):
                with self.assertRaises(well_known_module.KeyDiscoveryFetchError):
                    well_known_module._validate_well_known_fetch_url(
                        url,
                        expected_origin=expected_origin,
                        resolve_host=False,
                    )

    def test_wrong_well_known_path_is_rejected(self) -> None:
        with self.assertRaises(well_known_module.KeyDiscoveryFetchError):
            well_known_module._validate_well_known_fetch_url(
                "https://trust.example/.well-known/actenon/keys.json/extra",
                expected_origin="https://trust.example",
                resolve_host=False,
            )

    def test_origin_mismatch_and_issuer_mismatch_are_rejected(self) -> None:
        with self.assertRaises(well_known_module.KeyDiscoveryFormatError):
            _resolver(_document(keys=[_key()], origin="https://other.example")).resolve_key(
                key_id="ed-key",
                algorithm="EdDSA",
                issued_at=ISSUED_AT,
                issuer=ISSUER,
            )

        with self.assertRaises(well_known_module.IssuerMismatchError):
            _resolver(_document(keys=[_key()])).resolve_key(
                key_id="ed-key",
                algorithm="EdDSA",
                issued_at=ISSUED_AT,
                issuer=PartyRef(type="service", id="other-issuer"),
            )

    def test_duplicate_key_ids_and_duplicate_json_keys_are_rejected(self) -> None:
        duplicate_key_document = _document(keys=[_key(), _key(public_key_jwk=_public_jwk("ed-key"))])
        with self.assertRaises(well_known_module.KeyDiscoveryFormatError):
            _resolver(duplicate_key_document).resolve_key(
                key_id="ed-key",
                algorithm="EdDSA",
                issued_at=ISSUED_AT,
                issuer=ISSUER,
            )

        duplicate_json = b'{"contract":{"name":"key_discovery","name":"shadow","version":"v1"}}'
        with self.assertRaisesRegex(well_known_module.KeyDiscoveryFormatError, "duplicate object keys"):
            _resolver_with_body(duplicate_json).resolve_key(
                key_id="ed-key",
                algorithm="EdDSA",
                issued_at=ISSUED_AT,
                issuer=ISSUER,
            )

    def test_key_lifecycle_boundaries_are_enforced(self) -> None:
        cases = [
            (_key(status="active", expires_at="2026-01-01T11:00:00Z"), well_known_module.ExpiredKeyError),
            (_key(status="active", not_before="2026-01-01T13:00:00Z"), well_known_module.KeyNotYetValidError),
            (_key(status="revoked", revoked_at="2026-01-01T11:00:00Z"), well_known_module.RevokedKeyError),
        ]
        for key_payload, expected_error in cases:
            with self.subTest(expected_error=expected_error.__name__):
                with self.assertRaises(expected_error):
                    _resolver(_document(keys=[key_payload])).resolve_key(
                        key_id="ed-key",
                        algorithm="EdDSA",
                        issued_at=ISSUED_AT,
                        issuer=ISSUER,
                    )

    def test_wrong_purpose_is_rejected_and_retired_historical_key_resolves(self) -> None:
        with self.assertRaises(well_known_module.KeyPurposeMismatchError):
            _resolver(_document(keys=[_key(use="outcome_attestation")])).resolve_key(
                key_id="ed-key",
                algorithm="EdDSA",
                issued_at=ISSUED_AT,
                issuer=ISSUER,
                required_use="proof_issuance",
            )

        resolved = _resolver(_document(keys=[_key(status="retired")])).resolve_key(
            key_id="ed-key",
            algorithm="EdDSA",
            issued_at=ISSUED_AT,
            issuer=ISSUER,
            required_use="proof_issuance",
        )

        self.assertEqual("retired", resolved.key.status)


if __name__ == "__main__":
    unittest.main()
