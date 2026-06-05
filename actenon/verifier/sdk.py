from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from actenon.api.intake import ActionIntentIntakeService
from actenon.models import ActionIntent, AudienceRef, DynamicContextInput, PCCB
from actenon.proof.service import PCCBVerifier
from actenon.proof.signing import SignatureVerifier


@dataclass(frozen=True)
class VerifiedPortableRequest:
    intent: ActionIntent
    pccb: PCCB
    context: DynamicContextInput


@dataclass
class VerifierSDK:
    """Portable protected-endpoint verifier entry point.

    The SDK consumes any ``SignatureVerifier``-compatible implementation.
    Protected endpoints verify proofs; they do not need proof-minting
    capability in order to use this SDK.
    """

    signer: SignatureVerifier
    clock_skew_tolerance: timedelta = timedelta(0)

    def __post_init__(self) -> None:
        self._intake = ActionIntentIntakeService()
        self._proof_verifier = PCCBVerifier(self.signer, clock_skew_tolerance=self.clock_skew_tolerance)

    def parse_intent(self, payload: Mapping[str, Any]) -> ActionIntent:
        return self._intake.parse(payload)

    def parse_pccb(self, payload: Mapping[str, Any]) -> PCCB:
        return PCCB.from_dict(payload)

    def build_context(
        self,
        *,
        request_id: str,
        audience: AudienceRef,
        now: datetime,
        scope_capabilities: tuple[str, ...],
        parameter_constraints: dict[str, Any] | None = None,
        resource_selectors: tuple[dict[str, Any], ...] = (),
    ) -> DynamicContextInput:
        return DynamicContextInput(
            request_id=request_id,
            audience=audience,
            scope_capabilities=scope_capabilities,
            now=now,
            parameter_constraints=parameter_constraints or {},
            resource_selectors=resource_selectors,
        )

    def verify(
        self,
        *,
        intent: ActionIntent | Mapping[str, Any],
        pccb: PCCB | Mapping[str, Any],
        context: DynamicContextInput,
    ) -> VerifiedPortableRequest:
        resolved_intent = intent if isinstance(intent, ActionIntent) else self.parse_intent(intent)
        resolved_pccb = pccb if isinstance(pccb, PCCB) else self.parse_pccb(pccb)
        self._proof_verifier.verify(resolved_intent, resolved_pccb, context)
        return VerifiedPortableRequest(intent=resolved_intent, pccb=resolved_pccb, context=context)

    def verify_payloads(
        self,
        *,
        intent_payload: Mapping[str, Any],
        pccb_payload: Mapping[str, Any],
        request_id: str,
        audience: AudienceRef,
        now: datetime,
        scope_capabilities: tuple[str, ...],
        parameter_constraints: dict[str, Any] | None = None,
        resource_selectors: tuple[dict[str, Any], ...] = (),
    ) -> VerifiedPortableRequest:
        context = self.build_context(
            request_id=request_id,
            audience=audience,
            now=now,
            scope_capabilities=scope_capabilities,
            parameter_constraints=parameter_constraints,
            resource_selectors=resource_selectors,
        )
        return self.verify(intent=intent_payload, pccb=pccb_payload, context=context)
