"""Shared helpers for the packaged conformance suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from os import PathLike

from actenon.api import ActionIntentIntakeService
from actenon.core import ProtectedExecutionKernel
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.models import AudienceRef, DynamicContextInput, PartyRef, PolicyDecision
from actenon.policy import (
    CapabilityScopeHardRule,
    HardRuleEngine,
    IntentChronologyHardRule,
    IntentTtlHardRule,
    PolicyEngine,
    TenantWorkflowRule,
    TenantWorkflowRuleLayer,
)
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.verifier import ProtectedEndpointMiddleware, VerifierSDK
from actenon.demo.portable_local_proof import FIXED_BASE_TIME, build_hello_world_action_intent_payload


def build_verified_materials():
    """Return a valid portable proof-verification tuple for conformance tests."""

    signer = build_local_proof_signer()
    sdk = VerifierSDK(signer)
    intake = ActionIntentIntakeService()
    payload = build_hello_world_action_intent_payload()
    intent = intake.parse(payload)
    context = sdk.build_context(
        request_id="req_conformance_001",
        audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
        now=FIXED_BASE_TIME,
        scope_capabilities=("protected_resource.read",),
        parameter_constraints={"exact_message": "portable hello world"},
        resource_selectors=({"resource_id": "hello_resource_demo_001"},),
    )
    pccb = PCCBMinter(
        signer=signer,
        issuer=intent.requester,
        pccb_id_factory=lambda: "pccb_conformance_001",
        nonce_factory=lambda: "nonce-conformance-00000001",
    ).mint(
        intent,
        decision=PolicyDecision(
            outcome="allow",
            summary="Conformance test allow.",
            rule_evaluations=(),
            reason_codes=("LOCAL_PROOF_ALLOW",),
        ),
        context=context,
    )
    return signer, sdk, intake, payload, pccb.to_dict(), context


def build_replay_kernel(tempdir: str | PathLike[str]):
    """Create a replay-enabled kernel harness for conformance tests."""

    replay_db = Path(tempdir) / "conformance-replay.sqlite3"
    now = datetime.now(timezone.utc)
    payload = {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": "intent_conformance_replay_001",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "tenant": {"tenant_id": "tenant_alpha"},
        "requester": {"type": "service", "id": "actor_123"},
        "action": {
            "name": "refund.create",
            "capability": "refund.execute",
            "parameters": {"amount_minor": 1000, "currency": "USD"},
        },
        "target": {"resource_type": "payment", "resource_id": "pay_001"},
    }
    context = DynamicContextInput(
        request_id="req_conformance_replay_001",
        audience=AudienceRef(type="service", id="protected-endpoint"),
        scope_capabilities=("refund.execute",),
        now=now,
        facts={"risk_level": "normal"},
    )
    signer = HmacSha256Signer(secret=b"conformance-secret", key_id="local-conformance")
    writer = InMemoryOutcomeWriter()
    receipt_factory = ReceiptFactory(receipt_id_factory=lambda: "rcpt_conformance")
    refusal_factory = RefusalFactory(refusal_id_factory=lambda: "rfsl_conformance")
    escrow = InMemoryCapabilityEscrow()
    replay_protector = ReplayProtector(SqliteReplayStore(replay_db))
    policy = PolicyEngine(
        hard_rules=HardRuleEngine((IntentChronologyHardRule(), IntentTtlHardRule(), CapabilityScopeHardRule())),
        tenant_workflow_rules=TenantWorkflowRuleLayer(
            tenant_rules={
                "tenant_alpha": (
                    TenantWorkflowRule(
                        rule_id="tenant_alpha.refund.allow",
                        outcome="allow",
                        summary="The tenant workflow authorizes this action.",
                        reason_code="WORKFLOW_ALLOW",
                        capabilities=("refund.execute",),
                        required_fact_values={"risk_level": "normal"},
                    ),
                )
            }
        ),
    )
    middleware = ProtectedEndpointMiddleware(
        proof_verifier=PCCBVerifier(signer),
        escrow=escrow,
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=writer,
        replay_protector=replay_protector,
    )
    kernel = ProtectedExecutionKernel(
        intake=ActionIntentIntakeService(),
        policy_engine=policy,
        pccb_minter=PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="kernel"),
            pccb_id_factory=lambda: "pccb_conformance_replay_001",
            nonce_factory=lambda: "nonce-conformance-replay-0001",
        ),
        escrow=escrow,
        middleware=middleware,
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=writer,
        escrow_id_factory=lambda: "esc_conformance_replay_001",
    )
    return kernel, writer, payload, context
