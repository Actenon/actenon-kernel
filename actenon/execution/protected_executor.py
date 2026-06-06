from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from actenon.core.errors import RefusalException
from actenon.core.redaction import (
    SAFE_HANDLER_EXCEPTION_CODE,
    SAFE_HANDLER_EXCEPTION_MESSAGE,
    redacted_handler_exception_details,
)
from actenon.credentials import BrokeredCredential, CredentialBroker
from actenon.escrow import CapabilityEscrow
from actenon.models.runtime import ExecutionResult, PolicyDecision, ProtectedExecutionRequest
from actenon.proof import PCCBVerifier
from actenon.receipts import InMemoryOutcomeWriter, OutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, build_default_replay_store


BrokeredHandler = Callable[[ProtectedExecutionRequest, BrokeredCredential], dict[str, Any]]
REPLAY_PROTECTION_DISABLED_WARNING = (
    "Actenon: replay/single-use protection DISABLED — the same proof can execute more than once. "
    "This is unsafe for consequential actions."
)


def _policy_refusal(decision: PolicyDecision) -> RefusalException:
    reason_code = decision.reason_codes[0] if decision.reason_codes else "POLICY_REFUSED"
    return RefusalException(
        category="policy",
        refusal_code=reason_code,
        message=decision.summary,
        retryable=decision.outcome in {"approval-required", "needs-evidence"},
        rule_refs=tuple(item.rule_id for item in decision.rule_evaluations),
        details={
            "policy_outcome": decision.outcome,
            "reason_codes": list(decision.reason_codes),
            "required_evidence": list(decision.required_evidence),
            "approver_types": list(decision.approver_types),
            "unmet_requirements": [
                {
                    "reason_code": evaluation.reason_code,
                    "summary": evaluation.summary,
                    "required_evidence": list(evaluation.required_evidence),
                    "required_approvals": list(evaluation.approver_types),
                    "evidence_keys": list(evaluation.details.get("evidence_keys", [])),
                }
                for evaluation in decision.rule_evaluations
                if evaluation.outcome != "allow"
            ],
        },
    )


@dataclass
class ProtectedExecutor:
    """Execute a protected action through proof, replay, escrow, and brokering.

    The executor is the local OSS credential-broker deployment path. It verifies
    a PCCB before acquiring brokered execution authority, passes only the
    brokered credential reference into the handler, and emits kernel Receipt or
    Refusal artifacts for the outcome.
    """

    proof_verifier: PCCBVerifier
    credential_broker: CredentialBroker
    replay_protector: ReplayProtector | None = None
    escrow: CapabilityEscrow | None = None
    receipt_factory: ReceiptFactory = field(default_factory=ReceiptFactory)
    refusal_factory: RefusalFactory = field(default_factory=RefusalFactory)
    outcome_writer: OutcomeWriter = field(default_factory=InMemoryOutcomeWriter)
    replay_protection: Literal["default", "disabled"] = "default"

    def __post_init__(self) -> None:
        if self.replay_protection not in {"default", "disabled"}:
            raise ValueError("replay_protection must be 'default' or 'disabled'")
        if self.replay_protection == "disabled":
            if self.replay_protector is not None:
                raise ValueError("replay_protector cannot be supplied when replay_protection is 'disabled'")
            logging.warning(REPLAY_PROTECTION_DISABLED_WARNING)
            return
        if self.replay_protector is None:
            self.replay_protector = ReplayProtector(build_default_replay_store())

    def execute(
        self,
        request: ProtectedExecutionRequest,
        handler: BrokeredHandler,
        *,
        policy_decision: PolicyDecision | None = None,
    ) -> ExecutionResult:
        replay_state = None
        brokered_credential: BrokeredCredential | None = None
        escrow_id = request.pccb.escrow_id
        try:
            self.proof_verifier.verify(request.intent, request.pccb, request.context)
            if policy_decision is not None and not policy_decision.allowed:
                raise _policy_refusal(policy_decision)
            if self.replay_protector is not None:
                replay_state = self.replay_protector.claim_request(request)
            if self.escrow is not None:
                if escrow_id is None:
                    raise RefusalException(
                        category="escrow",
                        refusal_code="ESCROW_REFERENCE_MISSING",
                        message="The proof does not include an escrow reference.",
                    )
                self.escrow.consume(
                    escrow_id=escrow_id,
                    pccb_id=request.pccb.pccb_id,
                    capability=request.intent.action.capability,
                    now=request.context.now,
                )
            brokered_credential = self.credential_broker.acquire(request.intent, request.pccb, request.context)
            payload = handler(request, brokered_credential)
            broker_payload = {
                "brokered_credential": brokered_credential.to_public_dict(),
                "credential_broker": {
                    "mode": "protected_endpoint",
                    "credential_material_exposed": False,
                },
            }
            receipt_payload = {**(payload or {}), **broker_payload}
            if self.replay_protector is not None and replay_state is not None:
                self.replay_protector.mark_consumed(replay_state.replay_key, now=request.context.now)
            self.credential_broker.release(brokered_credential, {"outcome": "executed", "payload": payload})
            receipt = self.receipt_factory.create_execution_receipt(
                request.intent,
                request.context,
                pccb_id=request.pccb.pccb_id,
                escrow_id=escrow_id,
                payload=receipt_payload,
                action_hash=request.pccb.action_hash,
            )
            self.outcome_writer.write_receipt(receipt)
            return ExecutionResult(receipt=receipt, refusal=None, payload=payload)
        except RefusalException as exc:
            if replay_state is not None and self.replay_protector is not None:
                self.replay_protector.release_claim(replay_state.replay_key, now=request.context.now, reason=exc.refusal_code)
            refusal = self.refusal_factory.create_from_exception(
                exc,
                occurred_at=request.context.now,
                intent=request.intent,
                context=request.context,
                pccb_id=request.pccb.pccb_id,
                escrow_id=escrow_id,
                action_hash=request.pccb.action_hash,
            )
            receipt = self.receipt_factory.create_refused_receipt(request.intent, request.context, refusal)
            self.outcome_writer.write_refusal(refusal)
            self.outcome_writer.write_receipt(receipt)
            return ExecutionResult(receipt=receipt, refusal=refusal, payload=None)
        except Exception as exc:  # pragma: no cover - defensive conversion for protected handlers
            redacted_details = redacted_handler_exception_details(exc, request_id=request.context.request_id)
            if brokered_credential is not None:
                self.credential_broker.release(
                    brokered_credential,
                    {
                        "outcome": "failed",
                        "safe_error_code": SAFE_HANDLER_EXCEPTION_CODE,
                        **redacted_details,
                    },
                )
            if replay_state is not None and self.replay_protector is not None:
                self.replay_protector.mark_consumed(replay_state.replay_key, now=request.context.now)
            # TODO: allow deployments to attach a secure diagnostics sink; public artifacts stay redacted.
            refusal = self.refusal_factory.create_from_exception(
                RefusalException(
                    category="execution",
                    refusal_code="EXECUTION_FAILED",
                    message=SAFE_HANDLER_EXCEPTION_MESSAGE,
                    details=redacted_details,
                ),
                occurred_at=request.context.now,
                intent=request.intent,
                context=request.context,
                pccb_id=request.pccb.pccb_id,
                escrow_id=escrow_id,
                action_hash=request.pccb.action_hash,
            )
            receipt = self.receipt_factory.create_refused_receipt(request.intent, request.context, refusal)
            self.outcome_writer.write_refusal(refusal)
            self.outcome_writer.write_receipt(receipt)
            return ExecutionResult(receipt=receipt, refusal=refusal, payload=None)
