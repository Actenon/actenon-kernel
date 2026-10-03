"""Minimal Ed25519 Signer / SignatureVerifier satisfying the kernel's
`actenon.proof.signers.base.Signer` protocol. Harness-owned so H1 does not
depend on unreleased Permit code. Uses only `cryptography` (a kernel base dep)."""
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from actenon.models.contracts import SignatureSpec

def _e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

class Ed25519Verifier:
    algorithm = "EdDSA"
    def __init__(self, x: str, kid: str):
        self.key_id = kid
        self._pub = ed25519.Ed25519PublicKey.from_public_bytes(_d(x))
    def verify(self, payload: bytes, signature) -> bool:
        if signature.algorithm != "EdDSA" or signature.key_id != self.key_id or signature.encoding != "base64url":
            return False
        try:
            self._pub.verify(_d(signature.value), payload); return True
        except Exception:
            return False

class Ed25519Signer(Ed25519Verifier):
    def __init__(self, kid: str = "prod-ed25519-1"):
        self._priv = ed25519.Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization as s
        raw = self._priv.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        self.x = _e(raw)
        super().__init__(self.x, kid)
    def sign(self, payload: bytes):
        return SignatureSpec(algorithm="EdDSA", key_id=self.key_id, encoding="base64url", value=_e(self._priv.sign(payload)))
