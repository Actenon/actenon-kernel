"""Compatibility module for legacy signer and verifier imports.

The canonical signer interfaces now live under ``actenon.proof.signers``.
This module remains as a stable import path for existing code.
"""

from .signers.base import SignatureVerifier, Signer
from .signers.local import HmacSha256Signer

__all__ = ["HmacSha256Signer", "SignatureVerifier", "Signer"]
