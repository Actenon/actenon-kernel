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
REPLAY_STORE_FAIL_OPEN_WARNING = (
    "Actenon: replay store failures configured FAIL-OPEN — an action may execute when single-use "
    "cannot be enforced. This is unsafe for consequential actions."
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
    replay_store_failure: Literal["fail_closed", "fail_open"] = "fail_closed"

    def __post_init__(self) -> None:
        if self.replay_protection not in {"default", "disabled"}:
            raise ValueError("replay_protection must be 'default' or 'disabled'")
        if self.replay_store_failure not in {"fail_closed", "fail_open"}:
            raise ValueError("replay_store_failure must be 'fail_closed' or 'fail_open'")
        if self.replay_protection == "disabled":
            if self.replay_protector is not None:
                raise ValueError("replay_protector cannot be supplied when replay_protection is 'disabled'")
            if self.replay_store_failure != "fail_closed":
                raise ValueError("replay_store_failure cannot be 'fail_open' when replay_protection is 'disabled'")
            logging.warning(REPLAY_PROTECTION_DISABLED_WARNING)
            return
        if self.replay_store_failure == "fail_open":
            logging.warning(REPLAY_STORE_FAIL_OPEN_WARNING)
        if self.replay_protector is None:
            self.replay_protector = ReplayProtector(build_default_replay_store())

    def _claim_replay(self, request: ProtectedExecutionRequest):
        if self.replay_protector is None:
            return None
        try:
            return self.replay_protector.claim_request(request)
        except RefusalException:
            raise
        except Exception as exc:
            if self.replay_store_failure == "fail_open":
                return None
            raise RefusalException(
                category="replay",
                refusal_code="REPLAY_STORE_UNAVAILABLE",
                message="Replay/single-use state could not be established. Execution was refused.",
                retryable=True,
                details={"operation": "claim"},
            ) from exc

    def _mark_replay_consumed(self, replay_state, *, request: ProtectedExecutionRequest) -> bool:
        if self.replay_protector is None or replay_state is None:
            return False
        try:
            self.replay_protector.mark_consumed(replay_state.replay_key, now=request.context.now)
            return True
        except RefusalException:
            raise
        except Exception as exc:
            if self.replay_store_failure == "fail_open":
                return False
            raise RefusalException(
                category="replay",
                refusal_code="REPLAY_STORE_UNAVAILABLE",
                message="Replay/single-use consumption could not be recorded. Execution was refused.",
                retryable=True,
                details={"operation": "consume"},
            ) from exc

    def _release_replay_claim(self, replay_state, *, request: ProtectedExecutionRequest, reason: str) -> None:
        if self.replay_protector is None or replay_state is None:
            return
        try:
            self.replay_protector.release_claim(
                replay_state.replay_key,
                now=request.context.now,
                reason=reason,
            )
        except Exception:
            logging.error(
                "Actenon: replay claim cleanup failed; the claim remains fail-closed.",
            )

    def _release_credential(
        self,
        credential: BrokeredCredential | None,
        outcome: dict[str, Any],
    ) -> None:
        if credential is None:
            return
        try:
            self.credential_broker.release(credential, outcome)
        except Exception:
            logging.error("Actenon: brokered credential cleanup failed.")

    def execute(
        self,
        request: ProtectedExecutionRequest,
        handler: BrokeredHandler,
        *,
        policy_decision: PolicyDecision | None = None,
    ) -> ExecutionResult:
        replay_state = None
        replay_consumed = False
        brokered_credential: BrokeredCredential | None = None
        escrow_id = request.pccb.escrow_id
        try:
            self.proof_verifier.verify(request.intent, request.pccb, request.context)
            if policy_decision is not None and not policy_decision.allowed:
                raise _policy_refusal(policy_decision)
            replay_state = self._claim_replay(request)
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
            replay_consumed = self._mark_replay_consumed(replay_state, request=request)
            payload = handler(request, brokered_credential)
            broker_payload = {
                "brokered_credential": brokered_credential.to_public_dict(),
                "credential_broker": {
                    "mode": "protected_endpoint",
                    "credential_material_exposed": False,
                },
            }
            receipt_payload = {**(payload or {}), **broker_payload}
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
            self._release_credential(
                brokered_credential,
                {"outcome": "refused", "reason_code": exc.refusal_code},
            )
            if not replay_consumed:
                self._release_replay_claim(replay_state, request=request, reason=exc.refusal_code)
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
            self._release_credential(
                brokered_credential,
                {
                    "outcome": "failed",
                    "safe_error_code": SAFE_HANDLER_EXCEPTION_CODE,
                    **redacted_details,
                },
            )
            if not replay_consumed and replay_state is not None:
                try:
                    replay_consumed = self._mark_replay_consumed(replay_state, request=request)
                except RefusalException:
                    logging.error(
                        "Actenon: replay consumption could not be confirmed after execution ambiguity; "
                        "the existing claim remains fail-closed."
                    )
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
