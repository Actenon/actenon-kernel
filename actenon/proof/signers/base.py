from __future__ import annotations

import base64
import binascii
from typing import Protocol

from actenon.models.contracts import SignatureSpec


def b64url_encode(raw: bytes) -> str:
    """Encode bytes using URL-safe base64 without padding."""

    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(raw: str) -> bytes:
    """Decode URL-safe base64 that may omit padding."""

    if not isinstance(raw, str):
        raise TypeError("base64url input must be a string")
    padding = "=" * (-len(raw) % 4)
    try:
        return base64.b64decode((raw + padding).encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64url input") from exc


class SignatureVerifier(Protocol):
    """Protocol for protected-endpoint signature verification.

    Verifier-edge deployments only need a stable way to validate a PCCB
    signature against a canonical payload and a configured trust root.

    The verifier contract intentionally does not require proof minting.
    """

    algorithm: str
    key_id: str

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        """Return `True` when the signature is valid for the given payload."""


class Signer(SignatureVerifier, Protocol):
    """Protocol for proof signers used by PCCB minting and verification.

    The signer contract is intentionally small:

    - `sign` produces a portable `SignatureSpec`
    - `verify` validates that a supplied signature matches a payload

    Local, KMS-backed, and HSM-backed implementations can all conform to this
    interface without exposing product-specific client APIs to the rest of the
    kernel.
    """

    algorithm: str
    key_id: str

    def sign(self, payload: bytes) -> SignatureSpec:
        """Produce a portable signature over a canonical payload."""
