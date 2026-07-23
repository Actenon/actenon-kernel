from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main


class KeysPublishCliIntegrationTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_keys_publish_writes_conformant_document(self) -> None:
        with TemporaryDirectory() as tempdir:
            output_path = Path(tempdir) / "keys.json"
            public_jwk = json.dumps(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYLef1YF8TtN4b4x2zZC7FQ5a0jvL7vG64F8S4M",
                }
            )
            code, stdout, stderr = self._run_cli(
                [
                    "keys",
                    "publish",
                    "--issuer-origin",
                    "https://trust.acme.example",
                    "--issuer-id",
                    "acme-proof-issuer",
                    "--issuer-display-name",
                    "Acme Proof Issuer",
                    "--key-id",
                    "acme-proof-ed25519-2026-04",
                    "--algorithm",
                    "EdDSA",
                    "--public-jwk-json",
                    public_jwk,
                    "--not-before",
                    "2026-04-01T00:00:00Z",
                    "--expires-at",
                    "2027-04-01T00:00:00Z",
                    "--output",
                    str(output_path),
                ]
            )

            self.assertEqual(0, code, stderr)
            self.assertEqual("", stderr)
            self.assertIn("Key-discovery document written.", stdout)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual("key_discovery", payload["contract"]["name"])
            self.assertEqual("v1", payload["contract"]["version"])
            self.assertEqual("https://trust.acme.example", payload["origin"])
            self.assertEqual("acme-proof-issuer", payload["issuer"]["id"])
            self.assertEqual("acme-proof-ed25519-2026-04", payload["keys"][0]["key_id"])
            self.assertEqual("EdDSA", payload["keys"][0]["algorithm"])
            self.assertEqual("proof_issuance", payload["keys"][0]["use"])
            self.assertEqual("sig", payload["keys"][0]["public_key_jwk"]["use"])
            self.assertEqual("acme-proof-ed25519-2026-04", payload["keys"][0]["public_key_jwk"]["kid"])

    def test_keys_publish_rejects_mismatched_jwk_kid(self) -> None:
        with TemporaryDirectory() as tempdir:
            output_path = Path(tempdir) / "keys.json"
            public_jwk = json.dumps(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "wrong-key-id",
                    "x": "11qYAYLef1YF8TtN4b4x2zZC7FQ5a0jvL7vG64F8S4M",
                }
            )
            code, stdout, stderr = self._run_cli(
                [
                    "keys",
                    "publish",
                    "--issuer-origin",
                    "https://trust.acme.example",
                    "--issuer-id",
                    "acme-proof-issuer",
                    "--key-id",
                    "acme-proof-ed25519-2026-04",
                    "--algorithm",
                    "EdDSA",
                    "--public-jwk-json",
                    public_jwk,
                    "--output",
                    str(output_path),
                ]
            )

            self.assertEqual(1, code)
            self.assertEqual("", stdout)
            self.assertIn("does not match key_id", stderr)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
