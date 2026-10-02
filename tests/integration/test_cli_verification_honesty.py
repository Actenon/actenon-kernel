"""The verification CLI must not say "verified" for what it did not verify (E2E F10)."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from actenon.cli import main
from actenon.demo.local_proof import run_local_proof_demo
from actenon.models import SignatureSpec
from actenon.proof.signers.base import b64url_decode, b64url_encode
from tests.security.helpers import NOW, build_security_context, build_security_intent, mint_security_pccb


def _run(argv: list[str]) -> tuple[int, str, str]:
    stdout, stderr = StringIO(), StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class ReceiptVerificationHonestyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        root = Path(self._tmp.name) / "local"
        run_local_proof_demo(root)
        self.allow = root / "scenarios" / "allow"
        self.deny = root / "scenarios" / "deny"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_receipt_alone_is_not_reported_verified(self) -> None:
        code, stdout, stderr = _run(["verify-receipt", "--receipt", str(self.allow / "execution_receipt.json")])
        self.assertEqual(1, code)
        self.assertNotIn("verified.", stdout)
        self.assertIn("NOT verified", stderr)

    def test_structure_only_is_explicit(self) -> None:
        code, stdout, _ = _run(
            ["verify-receipt", "--receipt", str(self.allow / "execution_receipt.json"), "--structure-only"]
        )
        self.assertEqual(0, code)
        self.assertIn("structure only", stdout)
        self.assertIn("NOT verified", stdout)

    def test_tampered_receipt_is_refused_against_its_intent(self) -> None:
        receipt = json.loads((self.allow / "execution_receipt.json").read_text())
        receipt["action"]["parameters"]["amount_minor"] = 999_999
        tampered = Path(self._tmp.name) / "tampered.json"
        tampered.write_text(json.dumps(receipt))
        code, stdout, _ = _run(
            ["verify-receipt", "--receipt", str(tampered), "--intent", str(self.allow / "action_intent.json")]
        )
        self.assertNotEqual(0, code)
        self.assertNotIn("verified", stdout)

    def test_linked_receipt_reports_what_was_and_was_not_verified(self) -> None:
        code, stdout, stderr = _run(
            [
                "verify-receipt",
                "--receipt", str(self.allow / "execution_receipt.json"),
                "--intent", str(self.allow / "action_intent.json"),
                "--pccb", str(self.allow / "pccb.json"),
            ]
        )
        self.assertEqual(0, code, stderr)
        self.assertIn("Receipt links verified.", stdout)
        self.assertIn("PCCB signature: verified", stdout)
        self.assertIn("Not verified: the receipt itself carries no signature", stdout)

    def test_linked_receipt_with_a_forged_pccb_signature_fails(self) -> None:
        pccb = json.loads((self.allow / "pccb.json").read_text())
        pccb["signature"]["value"] = "A" * len(pccb["signature"]["value"])
        forged = Path(self._tmp.name) / "forged_pccb.json"
        forged.write_text(json.dumps(pccb))
        code, stdout, _ = _run(
            [
                "verify-receipt",
                "--receipt", str(self.allow / "execution_receipt.json"),
                "--pccb", str(forged),
            ]
        )
        self.assertNotEqual(0, code)
        self.assertNotIn("links verified", stdout)

    def test_refusal_alone_is_not_reported_verified(self) -> None:
        code, stdout, stderr = _run(["verify-refusal", "--refusal", str(self.deny / "refusal.json")])
        self.assertEqual(1, code)
        self.assertIn("NOT verified", stderr)


class VerifyProofPublicKeyTests(unittest.TestCase):
    def _write(self, directory: Path, key: Ed25519PrivateKey, *, kid: str = "prod-ed25519") -> tuple[Path, Path, Path]:
        class _Signer:
            algorithm = "EdDSA"
            key_id = kid

            def sign(self, payload: bytes) -> SignatureSpec:
                return SignatureSpec("EdDSA", kid, "base64url", b64url_encode(key.sign(payload)))

            def verify(self, payload, signature) -> bool:  # pragma: no cover - minting only
                return False

        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent, context=build_security_context(), signer=_Signer())
        from cryptography.hazmat.primitives import serialization

        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw), "kid": kid, "alg": "EdDSA"}
        paths = (directory / "intent.json", directory / "pccb.json", directory / "jwk.json")
        paths[0].write_text(json.dumps(intent.to_dict()))
        paths[1].write_text(json.dumps(pccb.to_dict()))
        paths[2].write_text(json.dumps(jwk))
        return paths

    def _verify(self, intent: Path, pccb: Path, jwk: Path) -> tuple[int, str, str]:
        return _run(
            [
                "verify-proof", "--intent", str(intent), "--pccb", str(pccb),
                "--audience", "service:payment-release-endpoint",
                "--verification-time", NOW.isoformat().replace("+00:00", "Z"),
                "--public-key-jwk", str(jwk),
            ]
        )

    def test_ed25519_proof_verifies_with_its_public_jwk(self) -> None:
        with TemporaryDirectory() as tempdir:
            intent, pccb, jwk = self._write(Path(tempdir), Ed25519PrivateKey.generate())
            code, stdout, stderr = self._verify(intent, pccb, jwk)
            self.assertEqual(0, code, stdout + stderr)
            self.assertIn("Proof verified.", stdout)

    def test_ed25519_proof_is_refused_with_another_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            intent, pccb, _ = self._write(Path(tempdir), Ed25519PrivateKey.generate())
            other = Path(tempdir) / "other"
            other.mkdir()
            _, _, wrong_jwk = self._write(other, Ed25519PrivateKey.generate())
            code, stdout, _ = self._verify(intent, pccb, wrong_jwk)
            self.assertEqual(1, code)
            self.assertNotIn("Proof verified.", stdout)

    def test_jwk_kid_must_match_the_proof(self) -> None:
        with TemporaryDirectory() as tempdir:
            key = Ed25519PrivateKey.generate()
            intent, pccb, jwk = self._write(Path(tempdir), key)
            document = json.loads(jwk.read_text())
            document["kid"] = "someone-elses-key"
            jwk.write_text(json.dumps(document))
            code, stdout, _ = self._verify(intent, pccb, jwk)
            self.assertEqual(1, code)

    def test_tampered_ed25519_signature_is_refused(self) -> None:
        with TemporaryDirectory() as tempdir:
            intent, pccb, jwk = self._write(Path(tempdir), Ed25519PrivateKey.generate())
            document = json.loads(pccb.read_text())
            raw = bytearray(b64url_decode(document["signature"]["value"]))
            raw[0] ^= 1
            document["signature"]["value"] = b64url_encode(bytes(raw))
            pccb.write_text(json.dumps(document))
            code, _, _ = self._verify(intent, pccb, jwk)
            self.assertEqual(1, code)


if __name__ == "__main__":
    unittest.main()
