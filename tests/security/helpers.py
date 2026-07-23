from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from actenon.models import (
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
)
from actenon.proof import PCCBMinter, build_action_hash_input, sha256_hex
from actenon.proof.canonical import canonicalize_bytes
from actenon.proof.signers import HmacSha256Signer
from actenon.proof.signers.base import b64url_decode, b64url_encode


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def security_signer() -> HmacSha256Signer:
    return HmacSha256Signer(secret=b"actenon-security-test-secret", key_id="security-hs256")


def build_security_intent(
    *,
    intent_id: str = "intent_security_001",
    tenant_id: str = "tenant_security",
    requester_id: str = "agent_security",
    amount_minor: int = 1000,
    capability: str = "payment.release",
    target_id: str = "payment_001",
    issued_at: datetime = NOW,
    expires_at: datetime | None = None,
) -> ActionIntent:
    return ActionIntent(
        intent_id=intent_id,
        issued_at=issued_at,
        expires_at=expires_at or issued_at + timedelta(minutes=5),
        tenant=TenantRef(tenant_id=tenant_id),
        requester=PartyRef(type="agent", id=requester_id),
        action=ActionSpec(
            name=capability,
            capability=capability,
            parameters={"amount_minor": amount_minor, "currency": "USD", "payment_id": target_id},
            constraints={"exact_amount_minor": amount_minor, "exact_currency": "USD"},
        ),
        target=TargetRef(resource_type="payment", resource_id=target_id),
        justification="Adversarial security test action.",
    )


def build_security_context(
    *,
    request_id: str = "req_security_001",
    audience_id: str = "payment-release-endpoint",
    now: datetime = NOW,
    scope_capabilities: tuple[str, ...] = ("payment.release",),
) -> DynamicContextInput:
    return DynamicContextInput(
        request_id=request_id,
        audience=AudienceRef(type="service", id=audience_id),
        scope_capabilities=scope_capabilities,
        now=now,
        parameter_constraints={"exact_amount_minor": 1000, "exact_currency": "USD"},
    )


def mint_security_pccb(
    *,
    intent: ActionIntent | None = None,
    context: DynamicContextInput | None = None,
    signer: HmacSha256Signer | None = None,
    pccb_id: str = "pccb_security_001",
    nonce: str = "nonce-security-001",
    escrow_id: str | None = "esc_security_001",
    capabilities: tuple[str, ...] | None = None,
) -> PCCB:
    signer = signer or security_signer()
    intent = intent or build_security_intent()
    context = context or build_security_context(scope_capabilities=capabilities or (intent.action.capability,))
    pccb = PCCBMinter(
        signer=signer,
        issuer=PartyRef(type="service", id="actenon-security-issuer"),
        pccb_id_factory=lambda: pccb_id,
        nonce_factory=lambda: nonce,
    ).mint(
        intent,
        decision=_allow_decision(),
        context=replace(context, scope_capabilities=capabilities or context.scope_capabilities),
        escrow_id=escrow_id,
    )
    return pccb


def _allow_decision():
    from actenon.models import PolicyDecision

    return PolicyDecision(
        outcome="allow",
        summary="Security test allow.",
        rule_evaluations=(),
        reason_codes=("SECURITY_TEST_ALLOW",),
    )


def resign_pccb(pccb: PCCB, *, signer: HmacSha256Signer | None = None) -> PCCB:
    signer = signer or security_signer()
    pending = replace(
        pccb,
        signature=SignatureSpec(
            algorithm=signer.algorithm,
            key_id=signer.key_id,
            encoding="base64url",
            value="pending",
        ),
    )
    return replace(pending, signature=signer.sign(canonicalize_bytes(pending.unsigned_payload())))


def mutate_signature_bytes(pccb: PCCB, mutation: str) -> PCCB:
    raw = bytearray(b64url_decode(pccb.signature.value))
    if mutation == "truncate":
        raw = raw[:-1]
    elif mutation == "extend":
        raw.extend(b"\x00")
    elif mutation == "single-byte":
        raw[0] ^= 0x01
    else:  # pragma: no cover - defensive helper guard
        raise ValueError(f"unsupported signature mutation {mutation!r}")
    return replace(pccb, signature=replace(pccb.signature, value=b64url_encode(bytes(raw))))


def unsigned_pccb_with_action_hash(intent: ActionIntent, context: DynamicContextInput, *, signer: HmacSha256Signer | None = None) -> PCCB:
    signer = signer or security_signer()
    return PCCB(
        pccb_id="pccb_security_unsigned",
        intent_id=intent.intent_id,
        issued_at=context.now,
        not_before=context.now,
        expires_at=intent.expires_at,
        issuer=PartyRef(type="service", id="actenon-security-issuer"),
        subject=intent.requester,
        tenant=intent.tenant,
        audience=context.audience,
        action=intent.action,
        target=intent.target,
        scope=ScopeSpec(mode="exact", capabilities=(intent.action.capability,), single_use=True),
        nonce="nonce-security-unsigned",
        action_hash=ActionHashSpec(
            algorithm="sha-256",
            canonicalization="RFC8785-JCS",
            value=sha256_hex(build_action_hash_input(intent)),
        ),
        escrow_id="esc_security_001",
        signature=SignatureSpec(algorithm=signer.algorithm, key_id=signer.key_id, encoding="base64url", value="pending"),
    )
