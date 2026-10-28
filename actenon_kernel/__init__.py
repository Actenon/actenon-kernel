"""Compatibility and convenience entrypoint for actenon-kernel (`actenon_kernel`).

Exports `ActenonGate`, `PCCBVerifier`, `BoundaryVerifier`, and a fail-closed
`verify_pccb` helper used by `actenon-scan fix --mode actenon` code transforms.
"""

from __future__ import annotations

from typing import Any, Mapping

from actenon.api import ActionIntentIntakeService
from actenon.boundary import (
    BoundaryVerificationRequest,
    BoundaryVerificationResult,
    BoundaryVerifier,
)
from actenon.core.errors import ProofVerificationError, RefusalException
from actenon.gate import ActenonGate, GateOutcome
from actenon.models import ActionIntent, DynamicContextInput, PCCB
from actenon.proof import PCCBVerifier, SignatureVerifier


def verify_pccb(
    proof: PCCB | Mapping[str, Any] | None = None,
    intent: ActionIntent | Mapping[str, Any] | None = None,
    *,
    action: str = "",
    verifier: PCCBVerifier | SignatureVerifier | None = None,
    context: DynamicContextInput | None = None,
) -> bool:
    """Fail-closed PCCB verification helper for guarded consequential call sites.

    Raises ``PermissionError`` unless a valid ``proof``, matching ``intent``,
    configured ``verifier``, and explicit trusted ``context`` with non-empty
    ``scope_capabilities`` are supplied and pass cryptographic verification.
    """
    label = action or "<unspecified>"
    if proof is None or intent is None:
        raise PermissionError(
            f"PCCB_REQUIRED: consequential action {label!r} requires a valid PCCB proof and ActionIntent."
        )
    if verifier is None or context is None:
        raise PermissionError(
            f"ISSUER_UNTRUSTED: consequential action {label!r} requires an explicit verifier and trusted DynamicContextInput."
        )
    if not getattr(context, "scope_capabilities", None):
        raise PermissionError(
            f"SCOPE_REQUIRED: consequential action {label!r} requires explicit trusted context.scope_capabilities."
        )

    try:
        intent_obj = (
            intent
            if isinstance(intent, ActionIntent)
            else ActionIntentIntakeService().parse(intent)
        )
        pccb_obj = proof if isinstance(proof, PCCB) else PCCB.from_dict(dict(proof))
    except (RefusalException, ValueError, TypeError) as exc:
        raise PermissionError(f"PROOF_INVALID: malformed proof or intent for {label!r}: {exc}") from exc

    if action and action not in {intent_obj.action.capability, intent_obj.action.name}:
        raise PermissionError(
            f"ACTION_MISMATCH: expected action {action!r}, got capability={intent_obj.action.capability!r} name={intent_obj.action.name!r}."
        )
    if intent_obj.action.capability not in context.scope_capabilities:
        raise PermissionError(
            f"ACTION_MISMATCH: intent capability {intent_obj.action.capability!r} is not in trusted scope_capabilities."
        )

    pccb_verifier = (
        verifier
        if isinstance(verifier, PCCBVerifier)
        else PCCBVerifier(verifier)
    )
    try:
        pccb_verifier.verify(intent_obj, pccb_obj, context)
    except ProofVerificationError as exc:
        raise PermissionError(f"{exc.refusal_code}: {exc.message}") from exc

    return True


__all__ = [
    "ActenonGate",
    "BoundaryVerificationRequest",
    "BoundaryVerificationResult",
    "BoundaryVerifier",
    "GateOutcome",
    "PCCBVerifier",
    "verify_pccb",
]
