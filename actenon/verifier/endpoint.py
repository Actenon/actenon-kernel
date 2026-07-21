from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from actenon.escrow import CapabilityEscrow
from actenon.models import (
    ActionIntent,
    AdmissionResult,
    AudienceRef,
    DynamicContextInput,
    ExecutionResult,
    PCCB,
    PolicyDecision,
    ProtectedExecutionRequest,
    Receipt,
    Refusal,
)
from actenon.proof import PCCBVerifier, VerifierDisclosureMode
from actenon.proof.signing import SignatureVerifier
from actenon.receipts import OutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, ReplayStore

from .middleware import Handler, ProtectedEndpointMiddleware
from .sdk import VerifierSDK


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _decision_payload(decision: PolicyDecision | None) -> dict[str, Any] | None:
    if decision is None:
        return None
    return {
        "outcome": decision.outcome,
        "summary": decision.summary,
        "reason_codes": list(decision.reason_codes),
        "required_evidence": list(decision.required_evidence),
        "approver_types": list(decision.approver_types),
        "rule_evaluations": [
            {
                "rule_id": item.rule_id,
                "outcome": item.outcome,
                "reason_code": item.reason_code,
                "summary": item.summary,
                "details": item.details,
                "required_evidence": list(item.required_evidence),
                "approver_types": list(item.approver_types),
            }
            for item in decision.rule_evaluations
        ],
    }


class AdmissionKernel(Protocol):
    def submit_intent(self, payload: Mapping[str, Any], context: DynamicContextInput) -> AdmissionResult:
        ...

    def build_execution_request(self, *, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> ProtectedExecutionRequest:
        ...

    def execute(self, request: ProtectedExecutionRequest, handler: Handler) -> ExecutionResult:
        ...


class LocalAdmissionNormalizer(Protocol):
    def __call__(self, raw_request: Mapping[str, Any], *, request_id: str, now: datetime) -> Mapping[str, Any]:
        ...


class LocalAdmissionContextBuilder(Protocol):
    def __call__(
        self,
        raw_request: Mapping[str, Any],
        *,
        intent_payload: Mapping[str, Any],
        request_id: str,
        now: datetime,
    ) -> DynamicContextInput:
        ...


@dataclass(frozen=True)
class LocalAdmissionOutcome:
    request_id: str
    normalized_intent_payload: dict[str, Any]
    decision: PolicyDecision | None
    admission_receipt: Receipt | None
    execution_receipt: Receipt | None
    refusal: Refusal | None
    pccb: PCCB | None
    escrow_id: str | None
    protected_response: dict[str, Any] | None = None
    mode: str = "proof-absent-local-admission"

    @property
    def final_outcome(self) -> str:
        if self.execution_receipt is not None:
            return self.execution_receipt.outcome
        if self.refusal is not None:
            return "refused"
        if self.decision is not None:
            return self.decision.outcome
        return "invalid"

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "request_id": self.request_id,
            "final_outcome": self.final_outcome,
            "normalized_action_intent": self.normalized_intent_payload,
            "decision": _decision_payload(self.decision),
            "escrow_id": self.escrow_id,
            "pccb": self.pccb.to_dict() if self.pccb is not None else None,
            "admission_receipt": self.admission_receipt.to_dict() if self.admission_receipt is not None else None,
            "execution_receipt": self.execution_receipt.to_dict() if self.execution_receipt is not None else None,
            "refusal": self.refusal.to_dict() if self.refusal is not None else None,
            "protected_response": self.protected_response,
        }


@dataclass(frozen=True)
class PythonProtectedEndpoint:
    """Small Python helper for protecting a real handler with kernel middleware."""

    signer: SignatureVerifier
    escrow: CapabilityEscrow
    replay_store: ReplayStore
    outcome_writer: OutcomeWriter
    receipt_factory: ReceiptFactory = field(default_factory=ReceiptFactory)
    refusal_factory: RefusalFactory = field(default_factory=RefusalFactory)

    def build_context(
        self,
        *,
        intent: ActionIntent,
        request_id: str,
        audience: AudienceRef,
        now: datetime,
        scope_capabilities: tuple[str, ...] | None = None,
    ) -> DynamicContextInput:
        sdk = VerifierSDK(self.signer)
        return sdk.build_context(
            request_id=request_id,
            audience=audience,
            now=now,
            scope_capabilities=scope_capabilities or (intent.action.capability,),
        )

    def build_request(
        self,
        *,
        intent: ActionIntent,
        pccb: PCCB,
        request_id: str,
        audience: AudienceRef,
        now: datetime,
        scope_capabilities: tuple[str, ...] | None = None,
    ) -> ProtectedExecutionRequest:
        context = self.build_context(
            intent=intent,
            request_id=request_id,
            audience=audience,
            now=now,
            scope_capabilities=scope_capabilities,
        )
        return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

    def execute(
        self,
        *,
        request: ProtectedExecutionRequest,
        handler: Handler,
    ) -> ExecutionResult:
        middleware = ProtectedEndpointMiddleware(
            proof_verifier=PCCBVerifier(self.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
            escrow=self.escrow,
            receipt_factory=self.receipt_factory,
            refusal_factory=self.refusal_factory,
            outcome_writer=self.outcome_writer,
            replay_protector=ReplayProtector(self.replay_store),
        )
        return middleware.execute(request, handler)

    def execute_payloads(
        self,
        *,
        intent_payload: Mapping[str, Any],
        pccb_payload: Mapping[str, Any],
        request_id: str,
        audience: AudienceRef,
        now: datetime,
        handler: Handler,
        scope_capabilities: tuple[str, ...] | None = None,
    ) -> ExecutionResult:
        sdk = VerifierSDK(self.signer)
        intent = sdk.parse_intent(intent_payload)
        pccb = sdk.parse_pccb(pccb_payload)
        request = self.build_request(
            intent=intent,
            pccb=pccb,
            request_id=request_id,
            audience=audience,
            now=now,
            scope_capabilities=scope_capabilities,
        )
        return self.execute(request=request, handler=handler)


@dataclass(frozen=True)
class LocalAdmissionProtectedEndpoint:
    """Edge-side helper for adopting Actenon before upstream proof exists."""

    kernel: AdmissionKernel
    normalize_action_intent: LocalAdmissionNormalizer
    build_admission_context: LocalAdmissionContextBuilder
    request_id_factory: Callable[[], str] = field(default=lambda: f"req_local_admission_{uuid4().hex[:12]}")
    clock: Callable[[], datetime] = field(default=_utc_now)

    def admit_and_execute(
        self,
        *,
        raw_request: Mapping[str, Any],
        handler: Handler,
        request_id: str | None = None,
        now: datetime | None = None,
    ) -> LocalAdmissionOutcome:
        resolved_request_id = request_id or self.request_id_factory()
        resolved_now = now or self.clock()
        normalized_intent_payload = dict(
            self.normalize_action_intent(
                raw_request,
                request_id=resolved_request_id,
                now=resolved_now,
            )
        )
        context = self.build_admission_context(
            raw_request,
            intent_payload=normalized_intent_payload,
            request_id=resolved_request_id,
            now=resolved_now,
        )
        admission = self.kernel.submit_intent(normalized_intent_payload, context)
        if admission.intent is None or admission.decision is None or admission.pccb is None or admission.decision.outcome != "allow":
            return LocalAdmissionOutcome(
                request_id=resolved_request_id,
                normalized_intent_payload=normalized_intent_payload,
                decision=admission.decision,
                admission_receipt=admission.receipt,
                execution_receipt=None,
                refusal=admission.refusal,
                pccb=admission.pccb,
                escrow_id=admission.escrow_id,
                protected_response=None,
            )
        execution_request = self.kernel.build_execution_request(intent=admission.intent, pccb=admission.pccb, context=context)
        execution = self.kernel.execute(execution_request, handler)
        return LocalAdmissionOutcome(
            request_id=resolved_request_id,
            normalized_intent_payload=normalized_intent_payload,
            decision=admission.decision,
            admission_receipt=admission.receipt,
            execution_receipt=execution.receipt,
            refusal=execution.refusal,
            pccb=admission.pccb,
            escrow_id=admission.escrow_id,
            protected_response=execution.payload,
        )
