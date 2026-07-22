from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from actenon.models.contracts import SignatureSpec

from .base import b64url_decode, b64url_encode


@dataclass(frozen=True)
class HsmKeyHandle:
    """Portable description of an HSM-resident key used for proof signing."""

    module: str
    key_label: str
    key_id: str
    algorithm: str
    slot: str | None = None


class HsmSigningBackend(Protocol):
    """Abstract backend for HSM-backed proof signing and verification."""

    def sign(self, *, key: HsmKeyHandle, payload: bytes) -> bytes:
        """Return raw signature bytes for the supplied payload."""

    def verify(self, *, key: HsmKeyHandle, payload: bytes, signature: bytes) -> bool:
        """Return `True` when the supplied signature is valid."""


@dataclass(frozen=True)
class HsmSigner:
    """Signer adapter that delegates proof operations to an HSM backend."""

    backend: HsmSigningBackend
    key: HsmKeyHandle

    @property
    def algorithm(self) -> str:
        return self.key.algorithm

    @property
    def key_id(self) -> str:
        return self.key.key_id

    def sign(self, payload: bytes) -> SignatureSpec:
        raw_signature = self.backend.sign(key=self.key, payload=payload)
        return SignatureSpec(
            algorithm=self.algorithm,
            key_id=self.key_id,
            encoding="base64url",
            value=b64url_encode(raw_signature),
        )

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        if signature.algorithm != self.algorithm or signature.key_id != self.key_id or signature.encoding != "base64url":
            return False
        try:
            raw_signature = b64url_decode(signature.value)
        except (TypeError, ValueError):
            return False
        return self.backend.verify(key=self.key, payload=payload, signature=raw_signature)
