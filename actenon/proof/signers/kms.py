from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from actenon.models.contracts import SignatureSpec

from .base import b64url_decode, b64url_encode


@dataclass(frozen=True)
class KmsKeyHandle:
    """Portable description of a remote KMS key used for proof signing."""

    key_uri: str
    key_id: str
    algorithm: str
    provider: str = "generic-kms"
    key_version: str | None = None


class KmsSigningBackend(Protocol):
    """Abstract backend for remote KMS signing and verification.

    Implementations may wrap cloud KMS products, on-prem signing services, or a
    paid control-plane signer gateway. The kernel only depends on this portable
    shape.
    """

    def sign(self, *, key: KmsKeyHandle, payload: bytes) -> bytes:
        """Return raw signature bytes for the supplied payload."""

    def verify(self, *, key: KmsKeyHandle, payload: bytes, signature: bytes) -> bool:
        """Return `True` when the supplied signature is valid."""


@dataclass(frozen=True)
class KmsSigner:
    """Signer adapter that delegates proof operations to a KMS backend."""

    backend: KmsSigningBackend
    key: KmsKeyHandle

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
