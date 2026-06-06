from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from secrets import token_urlsafe
from typing import Any, Callable
from uuid import uuid4

from actenon.core.errors import ProofVerificationError
from actenon.models.contracts import (
    ActionHashSpec,
    ActionIntent,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
)
from actenon.models.runtime import DynamicContextInput, PolicyDecision
from .audit import AuditLogSink, PCCBMintAuditRecord
from .canonical import canonicalize_bytes, sha256_hex
from .refusal_messages import public_proof_refusal_message
from .signing import SignatureVerifier, Signer


DEFAULT_CLOCK_SKEW_TOLERANCE = timedelta(0)


def build_action_hash_input(intent: ActionIntent) -> dict[str, Any]:
    return {
        "intent_id": intent.intent_id,
        "tenant": intent.tenant.to_dict(),
        "requester": intent.requester.to_dict(),
        "action": intent.action.to_dict(),
        "target": intent.target.to_dict(),
        "issued_at": intent.to_dict()["issued_at"],
        "expires_at": intent.to_dict()["expires_at"],
    }


@dataclass
class PCCBMinter:
    signer: Signer
    issuer: PartyRef
    pccb_id_factory: Callable[[], str] = field(default=lambda: f"pccb_{uuid4().hex}")
    nonce_factory: Callable[[], str] = field(default=lambda: token_urlsafe(24))
    audit_sink: AuditLogSink | None = None

    def mint(self, intent: ActionIntent, decision: PolicyDecision, context: DynamicContextInput, *, escrow_id: str | None = None) -> PCCB:
        if not decision.allowed:
            raise ValueError("PCCB minting requires an allow decision")

        issued_at = context.now
        scope = ScopeSpec(
            mode="exact",
            capabilities=tuple(sorted(set(context.scope_capabilities or (intent.action.capability,)))),
            single_use=True,
            resource_selectors=context.resource_selectors,
            parameter_constraints=context.parameter_constraints,
        )
        action_hash = ActionHashSpec(
            algorithm="sha-256",
            canonicalization="RFC8785-JCS",
            value=sha256_hex(build_action_hash_input(intent)),
        )
        unsigned = PCCB(
            pccb_id=self.pccb_id_factory(),
            intent_id=intent.intent_id,
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=intent.expires_at,
            issuer=self.issuer,
            subject=intent.requester,
            tenant=intent.tenant,
            audience=context.audience,
            action=intent.action,
            target=intent.target,
            scope=scope,
            nonce=self.nonce_factory(),
            action_hash=action_hash,
            escrow_id=escrow_id,
            signature=SignatureSpec(algorithm=self.signer.algorithm, key_id=self.signer.key_id, encoding="base64url", value="pending"),
        )
        signature = self.signer.sign(canonicalize_bytes(unsigned.unsigned_payload()))
        pccb = PCCB(
            pccb_id=unsigned.pccb_id,
            intent_id=unsigned.intent_id,
            issued_at=unsigned.issued_at,
            not_before=unsigned.not_before,
            expires_at=unsigned.expires_at,
            issuer=unsigned.issuer,
            subject=unsigned.subject,
            tenant=unsigned.tenant,
            audience=unsigned.audience,
            action=unsigned.action,
            target=unsigned.target,
            scope=unsigned.scope,
            nonce=unsigned.nonce,
            action_hash=unsigned.action_hash,
            escrow_id=unsigned.escrow_id,
            signature=signature,
            extensions=unsigned.extensions,
        )
        if self.audit_sink is not None:
            self.audit_sink.record_pccb_mint(PCCBMintAuditRecord(pccb))
        return pccb


@dataclass
class PCCBVerifier:
    signer: SignatureVerifier
    clock_skew_tolerance: timedelta = DEFAULT_CLOCK_SKEW_TOLERANCE

    def __post_init__(self) -> None:
        if self.clock_skew_tolerance < timedelta(0):
            raise ValueError("clock_skew_tolerance must be non-negative")

    def verify(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> None:
        if context.now + self.clock_skew_tolerance < pccb.not_before:
            raise ProofVerificationError(
                "PROOF_NOT_YET_VALID",
                public_proof_refusal_message("PROOF_NOT_YET_VALID"),
            )
        if context.now - self.clock_skew_tolerance > pccb.expires_at:
            raise ProofVerificationError(
                "PROOF_EXPIRED",
                public_proof_refusal_message("PROOF_EXPIRED"),
            )
        if pccb.audience != context.audience:
            raise ProofVerificationError(
                "AUDIENCE_MISMATCH",
                public_proof_refusal_message("AUDIENCE_MISMATCH"),
            )
        if pccb.scope.mode != "exact":
            raise ProofVerificationError(
                "SCOPE_MODE_INVALID",
                public_proof_refusal_message("SCOPE_MODE_INVALID"),
            )
        if intent.action.capability not in pccb.scope.capabilities:
            raise ProofVerificationError(
                "SCOPE_CAPABILITY_MISMATCH",
                public_proof_refusal_message("SCOPE_CAPABILITY_MISMATCH"),
            )
        if pccb.intent_id and pccb.intent_id != intent.intent_id:
            raise ProofVerificationError(
                "INTENT_MISMATCH",
                public_proof_refusal_message("INTENT_MISMATCH"),
            )
        if pccb.tenant != intent.tenant:
            raise ProofVerificationError(
                "TENANT_MISMATCH",
                public_proof_refusal_message("TENANT_MISMATCH"),
            )
        if pccb.subject != intent.requester:
            raise ProofVerificationError(
                "SUBJECT_MISMATCH",
                public_proof_refusal_message("SUBJECT_MISMATCH"),
            )
        if pccb.action != intent.action:
            raise ProofVerificationError(
                "ACTION_MISMATCH",
                public_proof_refusal_message("ACTION_MISMATCH"),
            )
        if pccb.target != intent.target:
            raise ProofVerificationError(
                "TARGET_MISMATCH",
                public_proof_refusal_message("TARGET_MISMATCH"),
            )

        try:
            expected_hash = sha256_hex(build_action_hash_input(intent))
        except (TypeError, ValueError, RecursionError) as exc:
            raise ProofVerificationError(
                "ACTION_HASH_INVALID",
                public_proof_refusal_message("ACTION_HASH_INVALID"),
            ) from exc
        if pccb.action_hash.algorithm != "sha-256" or pccb.action_hash.canonicalization != "RFC8785-JCS":
            raise ProofVerificationError(
                "ACTION_HASH_ALGORITHM_INVALID",
                public_proof_refusal_message("ACTION_HASH_ALGORITHM_INVALID"),
            )
        if pccb.action_hash.value != expected_hash:
            raise ProofVerificationError(
                "ACTION_HASH_MISMATCH",
                public_proof_refusal_message("ACTION_HASH_MISMATCH"),
            )

        try:
            unsigned_payload = canonicalize_bytes(pccb.unsigned_payload())
        except (TypeError, ValueError, RecursionError) as exc:
            raise ProofVerificationError(
                "PROOF_PAYLOAD_INVALID",
                public_proof_refusal_message("PROOF_PAYLOAD_INVALID"),
            ) from exc
        verify_with_metadata = getattr(self.signer, "verify_with_metadata", None)
        if callable(verify_with_metadata):
            is_valid = verify_with_metadata(
                unsigned_payload,
                pccb.signature,
                issuer=pccb.issuer,
                issued_at=pccb.issued_at,
            )
        else:
            is_valid = self.signer.verify(unsigned_payload, pccb.signature)
        if not is_valid:
            raise ProofVerificationError(
                "SIGNATURE_INVALID",
                public_proof_refusal_message("SIGNATURE_INVALID"),
            )
