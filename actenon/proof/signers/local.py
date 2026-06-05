from __future__ import annotations

import hmac
import os
import warnings
from dataclasses import dataclass
from hashlib import sha256

from actenon.models.contracts import SignatureSpec

from .base import b64url_decode, b64url_encode


LOCAL_PROOF_KEY_ID = "local-proof-v1"
LOCAL_PROOF_SECRET = b"actenon-local-proof-secret-v1"
ACTENON_ALLOW_LOCAL_HMAC_ENV = "ACTENON_ALLOW_LOCAL_HMAC"
ACTENON_ENV_ENV = "ACTENON_ENV"
ACTENON_LOCAL_HMAC_SECRET_ENV = "ACTENON_LOCAL_HMAC_SECRET"
LOCAL_HMAC_WARNING_MESSAGE = (
    "ACTENON LOCAL HMAC SIGNER IS FOR LOCAL/DEV/DEMO ONLY. "
    "The default local proof secret is public; production must use asymmetric "
    "well-known/KMS/HSM signing custody."
)
_PRODUCTION_ENV_VALUES = frozenset({"prod", "production", "staging", "release", "ci", "non-dev", "nondev"})
_LOCAL_ENV_VALUES = frozenset({"dev", "local", "demo", "test", "testing"})
_PRODUCTION_FLAG_ENVS = (
    "ACTENON_PRODUCTION",
    "ACTENON_CI_RELEASE",
    "ACTENON_RELEASE_BUILD",
)


class LocalHmacProductionGuardError(RuntimeError):
    """Raised when the local HMAC signer is created in a production-like environment."""


def _truthy(raw: str | None) -> bool:
    return raw is not None and raw.strip().lower() in {"1", "true", "yes", "on"}


def _normalized_env() -> str:
    return os.environ.get(ACTENON_ENV_ENV, "").strip().lower()


def _local_hmac_explicitly_allowed() -> bool:
    return _truthy(os.environ.get(ACTENON_ALLOW_LOCAL_HMAC_ENV)) or _normalized_env() in _LOCAL_ENV_VALUES


def _production_like_environment() -> bool:
    return _normalized_env() in _PRODUCTION_ENV_VALUES or any(_truthy(os.environ.get(name)) for name in _PRODUCTION_FLAG_ENVS)


def _coerce_secret(secret: bytes | str) -> bytes:
    if isinstance(secret, bytes):
        return secret
    return secret.encode("utf-8")


def _resolve_local_hmac_secret(secret: bytes | str | None) -> bytes:
    if secret is not None:
        return _coerce_secret(secret)
    env_secret = os.environ.get(ACTENON_LOCAL_HMAC_SECRET_ENV)
    if env_secret is not None:
        return env_secret.encode("utf-8")
    return LOCAL_PROOF_SECRET


def _guard_local_hmac_creation() -> None:
    if _production_like_environment() and not _local_hmac_explicitly_allowed():
        raise LocalHmacProductionGuardError(
            "local HMAC proof signing is disabled in production-like environments. "
            "Set ACTENON_ALLOW_LOCAL_HMAC=1 only for local demos/tests, or use asymmetric well-known/KMS/HSM signing custody."
        )


def _warn_local_hmac_creation() -> None:
    warnings.warn(LOCAL_HMAC_WARNING_MESSAGE, RuntimeWarning, stacklevel=5)


@dataclass(frozen=True)
class HmacSha256Signer:
    """Deterministic local signer used by the open kernel reference flows.

    This signer preserves the repository's existing local proof behavior. It is
    suitable for tests, demos, and local proof mode. It is not positioned as a
    production key-management strategy.
    """

    secret: bytes
    key_id: str
    algorithm: str = "HS256"

    def __post_init__(self) -> None:
        _guard_local_hmac_creation()
        _warn_local_hmac_creation()

    def sign(self, payload: bytes) -> SignatureSpec:
        digest = hmac.new(self.secret, payload, sha256).digest()
        return SignatureSpec(
            algorithm=self.algorithm,
            key_id=self.key_id,
            encoding="base64url",
            value=b64url_encode(digest),
        )

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        if signature.algorithm != self.algorithm or signature.key_id != self.key_id or signature.encoding != "base64url":
            return False
        expected = hmac.new(self.secret, payload, sha256).digest()
        try:
            provided = b64url_decode(signature.value)
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, provided)


def build_local_proof_signer(
    secret: bytes | str | None = None,
    *,
    key_id: str = LOCAL_PROOF_KEY_ID,
) -> HmacSha256Signer:
    """Return the canonical deterministic signer for local proof mode."""

    resolved_secret = _resolve_local_hmac_secret(secret)
    return HmacSha256Signer(secret=resolved_secret, key_id=key_id)
