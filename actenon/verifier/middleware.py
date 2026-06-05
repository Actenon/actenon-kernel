from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from actenon.core.errors import RefusalException
from actenon.core.redaction import SAFE_HANDLER_EXCEPTION_MESSAGE, redacted_handler_exception_details
from actenon.escrow.base import CapabilityEscrow
from actenon.models.runtime import ExecutionResult, ProtectedExecutionRequest
from actenon.proof.service import PCCBVerifier
from actenon.replay.service import ReplayProtector, build_default_replay_store
from actenon.receipts.factory import ReceiptFactory, RefusalFactory
from actenon.receipts.writers import OutcomeWriter


Handler = Callable[[ProtectedExecutionRequest], dict[str, Any]]


@dataclass
class ProtectedEndpointMiddleware:
    proof_verifier: PCCBVerifier
    escrow: CapabilityEscrow
    receipt_factory: ReceiptFactory
    refusal_factory: RefusalFactory
    outcome_writer: OutcomeWriter
    replay_protector: ReplayProtector = field(default_factory=lambda: ReplayProtector(build_default_replay_store()))

    def execute(self, request: ProtectedExecutionRequest, handler: Handler) -> ExecutionResult:
        escrow_id = request.pccb.escrow_id
        replay_state = None
        try:
            self.proof_verifier.verify(request.intent, request.pccb, request.context)
            if escrow_id is None:
                raise RefusalException(
                    category="escrow",
                    refusal_code="ESCROW_REFERENCE_MISSING",
                    message="The proof does not include an escrow reference.",
                )
            replay_state = self.replay_protector.claim_request(request)
            self.escrow.consume(
                escrow_id=escrow_id,
                pccb_id=request.pccb.pccb_id,
                capability=request.intent.action.capability,
                now=request.context.now,
            )
            payload = handler(request)
            self.replay_protector.mark_consumed(replay_state.replay_key, now=request.context.now)
            receipt = self.receipt_factory.create_execution_receipt(
                request.intent,
                request.context,
                pccb_id=request.pccb.pccb_id,
                escrow_id=escrow_id,
                payload=payload,
                action_hash=request.pccb.action_hash,
            )
            self.outcome_writer.write_receipt(receipt)
            return ExecutionResult(receipt=receipt, refusal=None, payload=payload)
        except RefusalException as exc:
            if replay_state is not None and exc.category in {"escrow", "authorization", "proof"}:
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
        except Exception as exc:  # pragma: no cover - converts unexpected handler failures
            redacted_details = redacted_handler_exception_details(exc, request_id=request.context.request_id)
            if replay_state is not None:
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
