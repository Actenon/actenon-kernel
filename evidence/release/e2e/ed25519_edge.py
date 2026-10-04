"""Integrator-side Ed25519 verifier for the edge (the kernel ships no public
Ed25519 JWK SignatureVerifier class; Permit's Ed25519PublicKeyVerifier is
unreleased). Uses only `cryptography`, a kernel base dependency."""
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519


def _d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Ed25519JwkVerifier:
    algorithm = "EdDSA"

    def __init__(self, jwk: dict):
        self.key_id = jwk["kid"]
        self._pub = ed25519.Ed25519PublicKey.from_public_bytes(_d(jwk["x"]))

    def verify(self, payload: bytes, signature) -> bool:
        if signature.algorithm != "EdDSA" or signature.key_id != self.key_id or signature.encoding != "base64url":
            return False
        try:
            self._pub.verify(_d(signature.value), payload)
            return True
        except Exception:
            return False
