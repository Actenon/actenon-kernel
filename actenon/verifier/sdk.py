from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from actenon.api.intake import ActionIntentIntakeService
from actenon.core.errors import ProofVerificationError
from actenon.execution.effects import EffectProtector
from actenon.models import ActionIntent, AudienceRef, DynamicContextInput, PCCB
from actenon.models.runtime import ProtectedExecutionRequest
from actenon.proof.service import (
    DEFAULT_CLOCK_SKEW_TOLERANCE,
    PCCBVerifier,
    RevocationChecker,
    VerifierDisclosureMode,
)
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

    Signed ``extensions.effect`` constraints are mandatory. Without an
    ``effect_protector`` they are refused; with one, verify() recomputes and
    atomically claims ownership after cryptographic/revocation verification.
    It is then a stateful authorization call, not a preview: do not also claim
    the same reservation through another edge API. The resource owns trusted
    execution, settlement and reconciliation. Ordinary proofs still require
    an external single-use replay claim before dispatch. For stateless
    cryptographic inspection only, use PCCBVerifier; its success alone is
    never permission to execute an effect.

    The ``disclosure_mode`` parameter controls how much detail the verifier
    exposes in refusal codes. Defaults to ``trusted_detailed`` for
    backward compatibility with existing conformance vectors. Production
    deployments should use ``public_generic`` to prevent proof-forging
    oracles.
    """

    signer: SignatureVerifier
    clock_skew_tolerance: timedelta = DEFAULT_CLOCK_SKEW_TOLERANCE
    disclosure_mode: VerifierDisclosureMode = VerifierDisclosureMode.TRUSTED_DETAILED
    revocation_checker: RevocationChecker | None = None
    effect_protector: EffectProtector | None = None

    def __post_init__(self) -> None:
        self._intake = ActionIntentIntakeService()
        self._proof_verifier = PCCBVerifier(
            self.signer,
            clock_skew_tolerance=self.clock_skew_tolerance,
            disclosure_mode=self.disclosure_mode,
            revocation_checker=self.revocation_checker,
        )

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
        resolved_intent = (
            intent if isinstance(intent, ActionIntent) else self.parse_intent(intent)
        )
        resolved_pccb = pccb if isinstance(pccb, PCCB) else self.parse_pccb(pccb)
        self._proof_verifier.verify(resolved_intent, resolved_pccb, context)
        if "effect" in resolved_pccb.extensions and self.effect_protector is None:
            raise ProofVerificationError(
                "POLICY_REFUSAL",
                "This proof requires authoritative effect ownership verification at the edge.",
            )
        if self.effect_protector is not None:
            self.effect_protector.claim_request(
                ProtectedExecutionRequest(resolved_intent, resolved_pccb, context)
            )
        return VerifiedPortableRequest(
            intent=resolved_intent, pccb=resolved_pccb, context=context
        )

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
