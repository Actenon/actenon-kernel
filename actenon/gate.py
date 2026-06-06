"""High-level proof-gated execution API."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Literal, Mapping
from uuid import uuid4

from actenon.api import ActionIntentIntakeService
from actenon.core import ContractValidationError, ProofVerificationError, RefusalException
from actenon.credentials import BrokeredCredential, CredentialBroker, InMemoryCredentialBroker
from actenon.escrow import CapabilityEscrow
from actenon.execution import ProtectedExecutor
from actenon.models import (
    ActionIntent,
    AudienceRef,
    DynamicContextInput,
    PCCB,
    PartyRef,
    PolicyDecision,
    ProtectedExecutionRequest,
    Receipt,
    Refusal,
    RuleEvaluation,
)
from actenon.models.contracts import utc_now
from actenon.preflight import PolicyPack, PreflightDecision, PreflightEngine
from actenon.proof import PCCBMinter, PCCBVerifier, SignatureVerifier, Signer, build_local_proof_signer
from actenon.receipts import InMemoryOutcomeWriter, OutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector


SideEffect = Callable[..., Any]


@dataclass(frozen=True)
class GateOutcome:
    """One protected execution outcome and its emitted artifacts."""

    receipt: Receipt | None
    refusal: Refusal | None
    payload: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.refusal is None and self.receipt is not None and self.receipt.outcome == "executed"

    @property
    def outcome(self) -> Literal["executed", "refused"]:
        return "executed" if self.ok else "refused"

    @property
    def reason_code(self) -> str | None:
        if self.refusal is not None:
            return self.refusal.refusal_code
        return None

    @property
    def unmet_requirements(self) -> tuple[str, ...]:
        return ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "unmet_requirements": list(self.unmet_requirements),
            "payload": self.payload,
        }
        if self.receipt is not None:
            payload["receipt"] = self.receipt.to_dict()
        if self.refusal is not None:
            payload["refusal"] = self.refusal.to_dict()
        return payload


def _coerce_audience(value: AudienceRef | str) -> AudienceRef:
    if isinstance(value, AudienceRef):
        return value
    audience_type, separator, audience_id = value.partition(":")
    if not separator:
        return AudienceRef(type="service", id=value)
    if not audience_type or not audience_id:
        raise ValueError("audience must be an AudienceRef or a non-empty 'type:id' string")
    return AudienceRef(type=audience_type, id=audience_id)


def _coerce_party(value: PartyRef | str) -> PartyRef:
    if isinstance(value, PartyRef):
        return value
    party_type, separator, party_id = value.partition(":")
    if not separator:
        return PartyRef(type="service", id=value)
    if not party_type or not party_id:
        raise ValueError("issuer must be a PartyRef or a non-empty 'type:id' string")
    return PartyRef(type=party_type, id=party_id)


def _policy_from_preflight(decision: PreflightDecision) -> PolicyDecision:
    outcome = {
        "allow": "allow",
        "deny": "deny",
        "approval_required": "approval-required",
        "needs_evidence": "needs-evidence",
    }[decision.outcome]
    evaluations = tuple(
        RuleEvaluation(
            rule_id=rule_id,
            outcome=outcome,
            reason_code=decision.reason_code,
            summary=decision.summary,
            required_evidence=decision.required_evidence,
            approver_types=decision.required_approvals,
        )
        for rule_id in (decision.matched_rules or ("actenon.gate.preflight",))
    )
    return PolicyDecision(
        outcome=outcome,
        summary=decision.summary,
        rule_evaluations=evaluations,
        reason_codes=(decision.reason_code,),
        required_evidence=decision.required_evidence,
        approver_types=decision.required_approvals,
    )


class ActenonGate:
    """Protect consequential side effects behind exact-action proof verification.

    Production deployments should pass a verifier rooted in their asymmetric
    trust configuration. Pass a separate signer only when this process is also
    authorized to mint proofs, such as a KMS/HSM-backed issuer. Verifier-only
    protected endpoints can omit ``signer`` and still call :meth:`protect`.
    """

    def __init__(
        self,
        *,
        verifier: SignatureVerifier,
        audience: AudienceRef | str,
        issuer: PartyRef | str,
        signer: Signer | None = None,
        policy_pack: PolicyPack | None = None,
        replay_protector: ReplayProtector | None = None,
        replay_protection: Literal["default", "disabled"] = "default",
        escrow: CapabilityEscrow | None = None,
        credential_broker: CredentialBroker | None = None,
        receipt_factory: ReceiptFactory | None = None,
        refusal_factory: RefusalFactory | None = None,
        outcome_writer: OutcomeWriter | None = None,
        clock: Callable[[], datetime] = utc_now,
        request_id_factory: Callable[[], str] | None = None,
        escrow_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.audience = _coerce_audience(audience)
        self.issuer = _coerce_party(issuer)
        self.signer = signer
        self.policy_pack = policy_pack
        self.escrow = escrow
        self.clock = clock
        self.request_id_factory = request_id_factory or (lambda: f"req_gate_{uuid4().hex}")
        self.escrow_id_factory = escrow_id_factory or (lambda: f"esc_{uuid4().hex}")
        self.receipt_factory = receipt_factory or ReceiptFactory()
        self.refusal_factory = refusal_factory or RefusalFactory()
        self.outcome_writer = outcome_writer or InMemoryOutcomeWriter()
        self._intake = ActionIntentIntakeService()
        self._minter = PCCBMinter(signer=signer, issuer=self.issuer) if signer is not None else None
        self._executor = ProtectedExecutor(
            proof_verifier=PCCBVerifier(verifier),
            credential_broker=credential_broker or InMemoryCredentialBroker(),
            replay_protector=replay_protector,
            replay_protection=replay_protection,
            escrow=escrow,
            receipt_factory=self.receipt_factory,
            refusal_factory=self.refusal_factory,
            outcome_writer=self.outcome_writer,
        )

    @classmethod
    def local_dev(
        cls,
        *,
        audience: AudienceRef | str,
        issuer: PartyRef | str = "service:actenon-local-dev",
        policy_pack: PolicyPack | None = None,
        replay_protector: ReplayProtector | None = None,
        replay_protection: Literal["default", "disabled"] = "default",
        escrow: CapabilityEscrow | None = None,
        credential_broker: CredentialBroker | None = None,
        receipt_factory: ReceiptFactory | None = None,
        refusal_factory: RefusalFactory | None = None,
        outcome_writer: OutcomeWriter | None = None,
        clock: Callable[[], datetime] = utc_now,
        request_id_factory: Callable[[], str] | None = None,
        escrow_id_factory: Callable[[], str] | None = None,
    ) -> "ActenonGate":
        """Build a local-only HMAC gate for demos and development.

        The local signer uses public development material and is not a
        production trust root.
        """

        signer = build_local_proof_signer()
        return cls(
            verifier=signer,
            signer=signer,
            audience=audience,
            issuer=issuer,
            policy_pack=policy_pack,
            replay_protector=replay_protector,
            replay_protection=replay_protection,
            escrow=escrow,
            credential_broker=credential_broker,
            receipt_factory=receipt_factory,
            refusal_factory=refusal_factory,
            outcome_writer=outcome_writer,
            clock=clock,
            request_id_factory=request_id_factory,
            escrow_id_factory=escrow_id_factory,
        )

    def mint_proof(
        self,
        action: dict[str, Any] | ActionIntent,
        *,
        decision: str = "allow",
    ) -> PCCB:
        """Mint a single-use proof for an exact Action Intent."""

        if self._minter is None:
            raise RuntimeError("this gate is verifier-only; configure a signer to mint proofs")
        if decision != "allow":
            raise ValueError("PCCB minting requires decision='allow'")
        intent = self._coerce_action(action)
        context = self._build_context(intent, audience=self.audience)
        policy_decision = PolicyDecision(
            outcome="allow",
            summary="The configured issuer allowed proof minting for this exact action.",
            rule_evaluations=(),
            reason_codes=("GATE_PROOF_MINTED",),
        )
        escrow_id = self.escrow_id_factory() if self.escrow is not None else None
        pccb = self._minter.mint(intent, policy_decision, context, escrow_id=escrow_id)
        if self.escrow is not None and escrow_id is not None:
            self.escrow.issue(
                escrow_id=escrow_id,
                pccb_id=pccb.pccb_id,
                capability=intent.action.capability,
                expires_at=pccb.expires_at,
                metadata={"intent_id": intent.intent_id, "issuer": self.issuer.to_dict()},
            )
        return pccb

    def protect(
        self,
        action: dict[str, Any] | ActionIntent,
        proof: dict[str, Any] | PCCB | None,
        side_effect: SideEffect,
        *,
        audience: AudienceRef | str | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> GateOutcome:
        """Verify, enforce single-use and policy, then execute or refuse."""

        intent = self._coerce_action(action)
        context = self._build_context(
            intent,
            audience=_coerce_audience(audience) if audience is not None else self.audience,
            evidence=evidence,
        )
        policy_decision = None
        if self.policy_pack is not None:
            preflight = PreflightEngine(self.policy_pack).check(intent, evidence_context=evidence)
            policy_decision = _policy_from_preflight(preflight)

        if proof is None:
            return self._refuse(
                intent,
                context,
                ProofVerificationError("PCCB_REQUIRED", "The protected action did not include a proof credential block."),
            )
        try:
            pccb = proof if isinstance(proof, PCCB) else PCCB.from_dict(proof)
        except ValueError as exc:
            return self._refuse(
                intent,
                context,
                ContractValidationError(f"PCCB contract validation failed: {exc}"),
            )

        request = ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)
        result = self._executor.execute(
            request,
            lambda protected_request, credential: self._invoke_side_effect(
                side_effect,
                protected_request,
                credential,
            ),
            policy_decision=policy_decision,
        )
        return GateOutcome(receipt=result.receipt, refusal=result.refusal, payload=result.payload)

    def protect_action(
        self,
        action: dict[str, Any] | ActionIntent,
        proof: dict[str, Any] | PCCB | None,
        *,
        audience: AudienceRef | str | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> Callable[[SideEffect], SideEffect]:
        """Decorate a function so its body runs only after gate verification."""

        def decorator(side_effect: SideEffect) -> SideEffect:
            @wraps(side_effect)
            def protected(*args: Any, **kwargs: Any) -> GateOutcome:
                return self.protect(
                    action,
                    proof,
                    lambda: side_effect(*args, **kwargs),
                    audience=audience,
                    evidence=evidence,
                )

            return protected

        return decorator

    def _coerce_action(self, action: dict[str, Any] | ActionIntent) -> ActionIntent:
        if isinstance(action, ActionIntent):
            return action
        return self._intake.parse(action)

    def _build_context(
        self,
        intent: ActionIntent,
        *,
        audience: AudienceRef,
        evidence: Mapping[str, Any] | None = None,
    ) -> DynamicContextInput:
        selectors = intent.target.selectors or {"resource_id": intent.target.resource_id}
        parameter_constraints = intent.action.constraints or intent.action.parameters
        return DynamicContextInput(
            request_id=self.request_id_factory(),
            audience=audience,
            scope_capabilities=(intent.action.capability,),
            now=self.clock(),
            facts=dict(evidence or {}),
            parameter_constraints=dict(parameter_constraints),
            resource_selectors=(dict(selectors),),
        )

    def _refuse(
        self,
        intent: ActionIntent,
        context: DynamicContextInput,
        exc: RefusalException,
    ) -> GateOutcome:
        refusal = self.refusal_factory.create_from_exception(
            exc,
            occurred_at=context.now,
            intent=intent,
            context=context,
        )
        receipt = self.receipt_factory.create_refused_receipt(intent, context, refusal)
        self.outcome_writer.write_refusal(refusal)
        self.outcome_writer.write_receipt(receipt)
        return GateOutcome(receipt=receipt, refusal=refusal, payload=None)

    @staticmethod
    def _invoke_side_effect(
        side_effect: SideEffect,
        request: ProtectedExecutionRequest,
        credential: BrokeredCredential,
    ) -> dict[str, Any]:
        try:
            signature = inspect.signature(side_effect)
        except (TypeError, ValueError):
            result = side_effect()
        else:
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind in {parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD}
            ]
            accepts_varargs = any(
                parameter.kind == parameter.VAR_POSITIONAL
                for parameter in signature.parameters.values()
            )
            if accepts_varargs or len(positional) >= 2:
                result = side_effect(request, credential)
            elif len(positional) == 1:
                result = side_effect(request.intent)
            else:
                result = side_effect()

        if result is None:
            return {}
        if isinstance(result, Mapping):
            return dict(result)
        return {"result": result}
