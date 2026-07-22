from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from uuid import uuid4

from actenon.api.intake import ActionIntentIntakeService
from actenon.core.errors import PolicyDecisionError, RefusalException
from actenon.evidence.stores import ActionIntentStore, PCCBStore
from actenon.escrow.base import CapabilityEscrow
from actenon.models.contracts import PCCB
from actenon.models.runtime import AdmissionResult, DynamicContextInput, ExecutionResult, ProtectedExecutionRequest
from actenon.policy.engine import PolicyEngine
from actenon.proof.service import PCCBMinter
from actenon.proof.signers import ProofSealClient, ProofSealError
from actenon.receipts.factory import ReceiptFactory, RefusalFactory
from actenon.receipts.writers import OutcomeWriter
from actenon.verifier.middleware import Handler, ProtectedEndpointMiddleware


@dataclass
class ProtectedExecutionKernel:
    intake: ActionIntentIntakeService
    policy_engine: PolicyEngine
    pccb_minter: PCCBMinter
    escrow: CapabilityEscrow
    middleware: ProtectedEndpointMiddleware
    receipt_factory: ReceiptFactory
    refusal_factory: RefusalFactory
    outcome_writer: OutcomeWriter
    intent_store: ActionIntentStore | None = None
    pccb_store: PCCBStore | None = None
    escrow_id_factory: Callable[[], str] = field(default=lambda: f"esc_{uuid4().hex}")
    proof_seal_client: ProofSealClient | None = None
    require_proof_seal: bool = False

    def _validated_execution_pccb(
        self,
        *,
        local_pccb: PCCB,
        sealed_pccb: PCCB,
    ) -> PCCB:
        """Accept only seal substitutions that preserve active v1 proof bindings."""

        required_matches = (
            ("intent_id", local_pccb.intent_id, sealed_pccb.intent_id),
            ("issued_at", local_pccb.issued_at, sealed_pccb.issued_at),
            ("not_before", local_pccb.not_before, sealed_pccb.not_before),
            ("expires_at", local_pccb.expires_at, sealed_pccb.expires_at),
            ("subject", local_pccb.subject, sealed_pccb.subject),
            ("tenant", local_pccb.tenant, sealed_pccb.tenant),
            ("audience", local_pccb.audience, sealed_pccb.audience),
            ("action", local_pccb.action, sealed_pccb.action),
            ("target", local_pccb.target, sealed_pccb.target),
            ("scope", local_pccb.scope, sealed_pccb.scope),
            ("escrow_id", local_pccb.escrow_id, sealed_pccb.escrow_id),
            ("action_hash", local_pccb.action_hash, sealed_pccb.action_hash),
        )
        for field_name, expected, actual in required_matches:
            if actual != expected:
                raise ProofSealError(
                    "PROOF_SEAL_INVALID",
                    f"proof seal substitution changed the PCCB {field_name}.",
                    details={"field": field_name},
                )
        return sealed_pccb

    def _resolve_execution_pccb(
        self,
        *,
        intent,
        decision,
        context: DynamicContextInput,
        local_pccb: PCCB,
    ) -> PCCB:
        if self.proof_seal_client is None:
            return local_pccb
        try:
            sealed_pccb = self.proof_seal_client.seal(
                intent=intent,
                decision=decision,
                context=context,
                pccb=local_pccb,
            )
        except ProofSealError:
            raise
        except Exception as exc:
            raise ProofSealError("PROOF_SEAL_FAILED", "proof seal substitution failed.") from exc
        return self._validated_execution_pccb(local_pccb=local_pccb, sealed_pccb=sealed_pccb)

    def submit_intent(self, payload: Mapping[str, Any], context: DynamicContextInput) -> AdmissionResult:
        try:
            intent = self.intake.parse(payload)
        except RefusalException as exc:
            refusal = self.refusal_factory.create_from_exception(
                exc,
                occurred_at=context.now,
                intent=None,
                context=context,
            )
            self.outcome_writer.write_refusal(refusal)
            return AdmissionResult(intent=None, decision=None, receipt=None, refusal=refusal)

        if self.intent_store is not None:
            put_intent = getattr(self.intent_store, "put_intent", None)
            if callable(put_intent):
                put_intent(intent)

        decision = self.policy_engine.evaluate(intent, context)

        if decision.outcome == "deny":
            decision_receipt = self.receipt_factory.create_decision_receipt(intent, decision, context)
            self.outcome_writer.write_receipt(decision_receipt)
            refusal_code = decision.reason_codes[0] if decision.reason_codes else "POLICY_DENIED"
            refusal = self.refusal_factory.create_from_exception(
                PolicyDecisionError(
                    refusal_code,
                    decision.summary,
                    rule_refs=tuple(item.rule_id for item in decision.rule_evaluations if item.outcome == "deny"),
                    details={"reason_codes": list(decision.reason_codes)},
                ),
                occurred_at=context.now,
                intent=intent,
                context=context,
            )
            self.outcome_writer.write_refusal(refusal)
            return AdmissionResult(intent=intent, decision=decision, receipt=decision_receipt, refusal=refusal)

        if decision.outcome in {"approval-required", "needs-evidence"}:
            decision_receipt = self.receipt_factory.create_decision_receipt(intent, decision, context)
            self.outcome_writer.write_receipt(decision_receipt)
            return AdmissionResult(intent=intent, decision=decision, receipt=decision_receipt, refusal=None)

        escrow_id = self.escrow_id_factory()
        local_pccb = self.pccb_minter.mint(intent, decision, context, escrow_id=escrow_id)
        try:
            # Proof sealing is optional, but when enabled synchronously it is a
            # critical admit-path substitution rather than a fire-and-forget
            # publication step. Escrow, storage, and receipts must all use the
            # final PCCB that subsequent execution will verify.
            pccb = self._resolve_execution_pccb(
                intent=intent,
                decision=decision,
                context=context,
                local_pccb=local_pccb,
            )
        except ProofSealError as exc:
            if not self.require_proof_seal:
                pccb = local_pccb
            else:
                refusal = self.refusal_factory.create_from_exception(
                    exc,
                    occurred_at=context.now,
                    intent=intent,
                    context=context,
                    pccb_id=local_pccb.pccb_id,
                    escrow_id=escrow_id,
                    action_hash=local_pccb.action_hash,
                )
                self.outcome_writer.write_refusal(refusal)
                return AdmissionResult(intent=intent, decision=decision, receipt=None, refusal=refusal)
        self.escrow.issue(
            escrow_id=escrow_id,
            pccb_id=pccb.pccb_id,
            capability=intent.action.capability,
            expires_at=pccb.expires_at,
            metadata={"intent_id": intent.intent_id},
        )
        allow_receipt = self.receipt_factory.create_decision_receipt(
            intent,
            decision,
            context,
            pccb_id=pccb.pccb_id,
            escrow_id=escrow_id,
            action_hash=pccb.action_hash,
        )
        if self.pccb_store is not None:
            put_pccb = getattr(self.pccb_store, "put_pccb", None)
            if callable(put_pccb):
                put_pccb(pccb)
        self.outcome_writer.write_receipt(allow_receipt)
        return AdmissionResult(
            intent=intent,
            decision=decision,
            receipt=allow_receipt,
            refusal=None,
            pccb=pccb,
            escrow_id=escrow_id,
        )

    def build_execution_request(self, *, intent, pccb, context: DynamicContextInput) -> ProtectedExecutionRequest:
        return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

    def execute(self, request: ProtectedExecutionRequest, handler: Handler) -> ExecutionResult:
        return self.middleware.execute(request, handler)
