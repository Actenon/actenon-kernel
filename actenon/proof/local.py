"""Compatibility module for the canonical local proof signer."""

from .signers.local import (
    HmacSha256Signer,
    LOCAL_HMAC_WARNING_MESSAGE,
    LOCAL_PROOF_KEY_ID,
    LOCAL_PROOF_SECRET,
    LocalHmacProductionGuardError,
    build_local_proof_signer,
)

__all__ = [
    "HmacSha256Signer",
    "LOCAL_HMAC_WARNING_MESSAGE",
    "LOCAL_PROOF_KEY_ID",
    "LOCAL_PROOF_SECRET",
    "LocalHmacProductionGuardError",
    "build_local_proof_signer",
]
