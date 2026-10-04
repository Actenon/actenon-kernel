from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Literal

from actenon.core.errors import RefusalException
from actenon.core.redaction import (
    SAFE_HANDLER_EXCEPTION_CODE,
    SAFE_HANDLER_EXCEPTION_MESSAGE,
    redacted_handler_exception_details,
)
from actenon.credentials import BrokeredCredential, CredentialBroker
from actenon.escrow import CapabilityEscrow
from .effects import EffectProtector
from actenon_protocol.effects import validate_effect_outcome
from actenon.proof.canonical import sha256_hex
from actenon.idempotency import IdempotencyStore
from actenon.models.runtime import (
    ExecutionResult,
    PolicyDecision,
    ProtectedExecutionRequest,
)
from actenon.proof import PCCBVerifier
from actenon.receipts import (
    InMemoryOutcomeWriter,
    OutcomeWriter,
    ReceiptFactory,
    RefusalFactory,
)
from actenon.replay import ReplayProtector
from actenon.replay.service import (
    default_replay_db_path,
    default_replay_store_downgrades,
)
from actenon.replay.sqlite import SqliteReplayStore
from actenon.security_posture import (
    DOWNGRADE_REPLAY_PROTECTION_DISABLED,
    DOWNGRADE_REPLAY_STORE_FAIL_OPEN,
    UNSAFE_ALLOW_REPLAY_DISABLED_ENV,
    UNSAFE_ALLOW_REPLAY_FAIL_OPEN_ENV,
    permit_downgrade,
)


BrokeredHandler = Callable[
    [ProtectedExecutionRequest, BrokeredCredential], dict[str, Any]
]
REPLAY_PROTECTION_DISABLED_WARNING = (
    "Actenon: replay/single-use protection DISABLED — the same proof can execute more than once. "
    "This is unsafe for consequential actions."
)
REPLAY_STORE_FAIL_OPEN_WARNING = (
    "Actenon: replay store failures configured FAIL-OPEN — an action may execute when single-use "
    "cannot be enforced. This is unsafe for consequential actions."
)


def _policy_refusal(decision: PolicyDecision) -> RefusalException:
    reason_code = (
        decision.reason_codes[0] if decision.reason_codes else "POLICY_REFUSED"
    )
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

    Idempotency:
      If the intent's metadata contains an `operation_id`, the executor checks
      the idempotency store AFTER the proof verifies, any policy decision
      allows, and the proof's single-use replay claim succeeds. A replayed
      proof is therefore DUPLICATE_REPLAY; a NEW proof for the same
      operation_id + action_hash is spent and, if a prior result exists
      for the same operation_id + same action_hash, the prior result is
      returned without re-executing the handler (idempotent replay). If the
      same operation_id has a different action_hash, IDEMPOTENCY_CONFLICT is
      raised.

    Outcome states:
      The executor tracks outcome states per the 8-state reconciliation model
      (see actenon.idempotency.OutcomeState).
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
    idempotency_store: IdempotencyStore | None = None
    effect_protector: EffectProtector | None = None
    # Weakened guarantees this executor was built with (empty in a correctly
    # configured production deployment). See actenon.security_posture.
    security_downgrades: tuple[str, ...] = field(default=(), init=False)

    def __post_init__(self) -> None:
        if self.replay_protection not in {"default", "disabled"}:
            raise ValueError("replay_protection must be 'default' or 'disabled'")
        if self.replay_store_failure not in {"fail_closed", "fail_open"}:
            raise ValueError(
                "replay_store_failure must be 'fail_closed' or 'fail_open'"
            )
        if self.replay_protection == "disabled":
            if self.replay_protector is not None:
                raise ValueError(
                    "replay_protector cannot be supplied when replay_protection is 'disabled'"
                )
            if self.replay_store_failure != "fail_closed":
                raise ValueError(
                    "replay_store_failure cannot be 'fail_open' when replay_protection is 'disabled'"
                )
            downgrade = permit_downgrade(
                DOWNGRADE_REPLAY_PROTECTION_DISABLED,
                override_env=UNSAFE_ALLOW_REPLAY_DISABLED_ENV,
                what='replay_protection="disabled" (the same proof can execute more than once)',
                fix="Keep replay protection on and configure a durable replay store.",
            )
            logging.warning(REPLAY_PROTECTION_DISABLED_WARNING)
            self.security_downgrades = (downgrade,)
            return
        downgrades: list[str] = []
        if self.replay_store_failure == "fail_open":
            downgrades.append(
                permit_downgrade(
                    DOWNGRADE_REPLAY_STORE_FAIL_OPEN,
                    override_env=UNSAFE_ALLOW_REPLAY_FAIL_OPEN_ENV,
                    what='replay_store_failure="fail_open" (an action may execute when single use cannot be enforced)',
                    fix='Use replay_store_failure="fail_closed" (the default).',
                )
            )
            logging.warning(REPLAY_STORE_FAIL_OPEN_WARNING)
        if self.replay_protector is None:
            downgrades.extend(default_replay_store_downgrades())
            self.replay_protector = ReplayProtector(
                SqliteReplayStore(default_replay_db_path())
            )
        self.security_downgrades = tuple(downgrades)

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

    def _mark_replay_consumed(
        self, replay_state, *, request: ProtectedExecutionRequest
    ) -> bool:
        if self.replay_protector is None or replay_state is None:
            return False
        try:
            self.replay_protector.mark_consumed(
                replay_state.replay_key, now=request.context.now
            )
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

    def _release_replay_claim(
        self, replay_state, *, request: ProtectedExecutionRequest, reason: str
    ) -> None:
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
        operation_id = request.intent.metadata.get("operation_id")
        action_hash_value = request.pccb.action_hash.value

        replay_state = None
        replay_consumed = False
        brokered_credential: BrokeredCredential | None = None
        escrow_id = request.pccb.escrow_id
        handler_started = False
        effect_reference = None
        effect_evidence = None
        try:
            self.proof_verifier.verify(request.intent, request.pccb, request.context)
            if policy_decision is not None and not policy_decision.allowed:
                raise _policy_refusal(policy_decision)
            # A signed effect extension is a mandatory ownership constraint,
            # never an optional hint an older edge can silently ignore.
            if "effect" in request.pccb.extensions and self.effect_protector is None:
                raise RefusalException(
                    category="policy",
                    refusal_code="POLICY_REFUSAL",
                    message="This proof requires authoritative effect ownership verification at the edge.",
                )
            replay_state = self._claim_replay(request)
            # ── Idempotency check (after verification AND the replay claim) ──
            # A retry of the same operation_id + action_hash with a NEW
            # proof returns the prior result without re-executing. It runs
            # only after the presented proof has verified and its single-use
            # claim succeeded: an idempotency key is never a substitute for
            # proof, a replayed proof is DUPLICATE_REPLAY like any other, and
            # neither the prior result nor the prior action_hash is disclosed
            # to an unverified caller.
            if (
                operation_id is not None
                and self.idempotency_store is not None
                and self.effect_protector is None
            ):
                prior = self.idempotency_store.lookup(operation_id)
                if prior is not None:
                    if prior["action_hash"] != action_hash_value:
                        raise RefusalException(
                            category="idempotency",
                            refusal_code="IDEMPOTENCY_CONFLICT",
                            message=(
                                f"Operation {operation_id!r} was already executed "
                                f"with a different action_hash."
                            ),
                            retryable=False,
                            details={
                                "operation_id": operation_id,
                                "expected_action_hash": prior["action_hash"],
                                "actual_action_hash": action_hash_value,
                            },
                        )
                    # Same operation_id + same action_hash → idempotent retry.
                    # The new proof is spent; the prior result is returned.
                    replay_consumed = self._mark_replay_consumed(
                        replay_state, request=request
                    )
                    prior_result = prior["result"]
                    receipt = self.receipt_factory.create_execution_receipt(
                        request.intent,
                        request.context,
                        pccb_id=request.pccb.pccb_id,
                        escrow_id=request.pccb.escrow_id,
                        payload=prior_result,
                        action_hash=request.pccb.action_hash,
                    )
                    self.outcome_writer.write_receipt(receipt)
                    return ExecutionResult(
                        receipt=receipt, refusal=None, payload=prior_result
                    )
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
            if self.effect_protector is not None:
                effect_reference = self.effect_protector.claim_request(request)
            brokered_credential = self.credential_broker.acquire(
                request.intent, request.pccb, request.context
            )
            replay_consumed = self._mark_replay_consumed(replay_state, request=request)
            handler_started = True
            payload = handler(request, brokered_credential)
            if effect_reference is not None:
                # This is returned by the trusted protected boundary, never
                # inferred from transport success or an agent's report.
                raw_evidence = (payload or {}).get("effect_evidence")
                try:
                    if not isinstance(raw_evidence, dict) or set(raw_evidence) != {
                        *effect_reference.to_dict(),
                        "outcome",
                        "execution_occurred",
                        "evidence_hash",
                    }:
                        raise ValueError("missing boundary consequence evidence")
                    if any(
                        raw_evidence.get(k) != v
                        for k, v in effect_reference.to_dict().items()
                    ):
                        raise ValueError("boundary evidence refers to another effect")
                    validate_effect_outcome(
                        raw_evidence["outcome"],
                        raw_evidence["execution_occurred"],
                        raw_evidence["evidence_hash"],
                    )
                    effect_evidence = dict(raw_evidence)
                    if effect_evidence["outcome"] != "COMMITTED":
                        raise RefusalException(
                            category="execution",
                            refusal_code="OUTCOME_UNKNOWN"
                            if effect_evidence["outcome"] == "AMBIGUOUS"
                            else "PROVIDER_REFUSAL",
                            message="The protected boundary did not confirm a committed consequence.",
                        )
                except RefusalException:
                    raise
                except Exception as exc:
                    raise RefusalException(
                        category="execution",
                        refusal_code="OUTCOME_UNKNOWN",
                        message="The protected boundary did not provide valid consequence evidence; the effect remains held.",
                    ) from exc
            broker_payload = {
                "brokered_credential": brokered_credential.to_public_dict(),
                "credential_broker": {
                    "mode": "protected_endpoint",
                    "credential_material_exposed": False,
                },
            }
            receipt_payload = {**(payload or {}), **broker_payload}
            self.credential_broker.release(
                brokered_credential, {"outcome": "executed", "payload": payload}
            )
            receipt = self.receipt_factory.create_execution_receipt(
                request.intent,
                request.context,
                pccb_id=request.pccb.pccb_id,
                escrow_id=escrow_id,
                payload=receipt_payload,
                action_hash=request.pccb.action_hash,
            )
            if effect_evidence is not None:
                receipt = replace(
                    receipt,
                    extensions={**receipt.extensions, "effect": effect_evidence},
                )
            self.outcome_writer.write_receipt(receipt)
            # ── Record in idempotency store ──────────────────────────
            if (
                operation_id is not None
                and self.idempotency_store is not None
                and self.effect_protector is None
            ):
                self.idempotency_store.record(operation_id, action_hash_value, payload)
            return ExecutionResult(receipt=receipt, refusal=None, payload=payload)
        except RefusalException as caught_refusal:
            exc = caught_refusal
            if (
                effect_reference is not None
                and handler_started
                and effect_evidence is None
            ):
                exc = RefusalException(
                    category="execution",
                    refusal_code="OUTCOME_UNKNOWN",
                    message="Execution may have crossed the protected boundary; the effect remains held for reconciliation.",
                )
            self._release_credential(
                brokered_credential,
                {
                    "outcome": "ambiguous"
                    if exc.refusal_code == "OUTCOME_UNKNOWN"
                    else "refused",
                    "reason_code": exc.refusal_code,
                },
            )
            if not replay_consumed:
                self._release_replay_claim(
                    replay_state, request=request, reason=exc.refusal_code
                )
            refusal = self.refusal_factory.create_from_exception(
                exc,
                occurred_at=request.context.now,
                intent=request.intent,
                context=request.context,
                pccb_id=request.pccb.pccb_id,
                escrow_id=escrow_id,
                action_hash=request.pccb.action_hash,
            )
            receipt = self.receipt_factory.create_refused_receipt(
                request.intent, request.context, refusal
            )
            if effect_reference is not None:
                receipt = self._effect_refusal_receipt(
                    receipt, effect_reference, handler_started, effect_evidence
                )
            self.outcome_writer.write_refusal(refusal)
            self.outcome_writer.write_receipt(receipt)
            return ExecutionResult(receipt=receipt, refusal=refusal, payload=None)
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive conversion for protected handlers
            redacted_details = redacted_handler_exception_details(
                exc, request_id=request.context.request_id
            )
            self._release_credential(
                brokered_credential,
                {
                    "outcome": "ambiguous"
                    if effect_reference is not None and handler_started
                    else "failed",
                    "safe_error_code": SAFE_HANDLER_EXCEPTION_CODE,
                    **redacted_details,
                },
            )
            if not replay_consumed and replay_state is not None:
                try:
                    replay_consumed = self._mark_replay_consumed(
                        replay_state, request=request
                    )
                except RefusalException:
                    logging.error(
                        "Actenon: replay consumption could not be confirmed after execution ambiguity; "
                        "the existing claim remains fail-closed."
                    )
            # TODO: allow deployments to attach a secure diagnostics sink; public artifacts stay redacted.
            refusal = self.refusal_factory.create_from_exception(
                RefusalException(
                    category="execution",
                    refusal_code="OUTCOME_UNKNOWN"
                    if effect_reference is not None and handler_started
                    else "EXECUTION_FAILED",
                    message="The execution outcome is unknown; the effect remains held for reconciliation."
                    if effect_reference is not None and handler_started
                    else SAFE_HANDLER_EXCEPTION_MESSAGE,
                    details=redacted_details,
                ),
                occurred_at=request.context.now,
                intent=request.intent,
                context=request.context,
                pccb_id=request.pccb.pccb_id,
                escrow_id=escrow_id,
                action_hash=request.pccb.action_hash,
            )
            receipt = self.receipt_factory.create_refused_receipt(
                request.intent, request.context, refusal
            )
            if effect_reference is not None:
                receipt = self._effect_refusal_receipt(
                    receipt, effect_reference, handler_started, effect_evidence
                )
            self.outcome_writer.write_refusal(refusal)
            self.outcome_writer.write_receipt(receipt)
            return ExecutionResult(receipt=receipt, refusal=refusal, payload=None)

    @staticmethod
    def _effect_refusal_receipt(receipt, reference, handler_started, evidence):
        if evidence is None:
            outcome = "AMBIGUOUS" if handler_started else "NOT_EXECUTED"
            occurred = None if handler_started else False
            evidence = {
                **reference.to_dict(),
                "outcome": outcome,
                "execution_occurred": occurred,
                "evidence_hash": sha256_hex(
                    {
                        "reference": reference.to_dict(),
                        "handler_started": handler_started,
                        "reason": list(receipt.reason_codes),
                    }
                ),
            }
        ambiguous = evidence["outcome"] == "AMBIGUOUS"
        return replace(
            receipt,
            summary="Execution outcome is unknown; blind retry is refused until reconciliation."
            if ambiguous
            else receipt.summary,
            side_effects={"state": "unknown" if ambiguous else "none"},
            extensions={**receipt.extensions, "effect": evidence},
        )
