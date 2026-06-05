from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.execution import ProtectedExecutor
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PartyRef,
    PolicyDecision,
    ProtectedExecutionRequest,
    TargetRef,
    TenantRef,
)
from actenon.proof import PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.receipts import InMemoryOutcomeWriter


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
AUDIENCE = AudienceRef(type="service", id="infra-delete-brokered-endpoint")

RESOURCES: dict[str, dict[str, Any]] = {
    "prod-db-primary": {"environment": "production", "resource_type": "database", "deleted": False},
    "sandbox-temp-volume": {"environment": "sandbox", "resource_type": "volume", "deleted": False},
}


def _intent(resource_id: str) -> ActionIntent:
    resource = RESOURCES[resource_id]
    return ActionIntent(
        intent_id=f"intent_delete_{resource_id}",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_demo"),
        requester=PartyRef(type="agent", id="infra-agent"),
        action=ActionSpec(
            name=f"{resource['resource_type']}.delete",
            capability="infrastructure.delete",
            parameters={"resource_id": resource_id, "environment": resource["environment"]},
        ),
        target=TargetRef(resource_type=resource["resource_type"], resource_id=resource_id),
        justification=f"Delete {resource_id}.",
    )


def _context(resource_id: str) -> DynamicContextInput:
    return DynamicContextInput(
        request_id=f"req_delete_{resource_id}",
        audience=AUDIENCE,
        scope_capabilities=("infrastructure.delete",),
        now=NOW,
        facts={"environment": RESOURCES[resource_id]["environment"]},
    )


def _decision(resource_id: str) -> PolicyDecision:
    if RESOURCES[resource_id]["environment"] == "production":
        return PolicyDecision(
            outcome="deny",
            summary="Production destructive infrastructure delete is refused by the protected endpoint.",
            rule_evaluations=(),
            reason_codes=("INFRA_DELETE_PRODUCTION_DENIED",),
        )
    return PolicyDecision(
        outcome="allow",
        summary="Sandbox infrastructure delete is allowed.",
        rule_evaluations=(),
        reason_codes=("INFRA_DELETE_ALLOWED_SANDBOX",),
    )


def _build_request(resource_id: str, escrow: InMemoryCapabilityEscrow) -> ProtectedExecutionRequest:
    intent = _intent(resource_id)
    context = _context(resource_id)
    signer = build_local_proof_signer()
    escrow_id = f"escrow_{resource_id}"
    pccb = PCCBMinter(
        signer=signer,
        issuer=PartyRef(type="service", id="actenon-local-demo"),
        pccb_id_factory=lambda: f"pccb_delete_{resource_id}",
        nonce_factory=lambda: f"nonce-delete-{resource_id}",
    ).mint(
        intent,
        decision=PolicyDecision(
            outcome="allow",
            summary="Demo proof minted for endpoint verification.",
            rule_evaluations=(),
            reason_codes=("DEMO_PROOF_MINTED",),
        ),
        context=context,
        escrow_id=escrow_id,
    )
    escrow.issue(
        escrow_id=escrow_id,
        pccb_id=pccb.pccb_id,
        capability=intent.action.capability,
        expires_at=pccb.expires_at,
        metadata={"intent_id": intent.intent_id},
    )
    return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)


def agent_direct_delete(resource_id: str, credential: BrokeredCredential | None = None) -> dict[str, Any]:
    if credential is None:
        raise PermissionError("agent has no standing production credential")
    return _delete_with_brokered_credential(resource_id, credential)


def _delete_with_brokered_credential(resource_id: str, credential: BrokeredCredential) -> dict[str, Any]:
    resource = RESOURCES[resource_id]
    resource["deleted"] = True
    return {
        "external_reference": f"delete:{resource_id}",
        "resource_id": resource_id,
        "deleted": True,
        "credential_reference": credential.secret_reference,
    }


def run_demo() -> dict[str, Any]:
    signer = build_local_proof_signer()
    escrow = InMemoryCapabilityEscrow()
    writer = InMemoryOutcomeWriter()
    executor = ProtectedExecutor(
        proof_verifier=PCCBVerifier(signer),
        credential_broker=InMemoryCredentialBroker(
            ttl=timedelta(seconds=60),
            credential_id_factory=lambda: "cred_infra_delete_demo",
        ),
        escrow=escrow,
        outcome_writer=writer,
    )

    try:
        agent_direct_delete("prod-db-primary")
    except PermissionError as exc:
        direct_attempt = {"outcome": "blocked", "reason": str(exc)}
    else:  # pragma: no cover - direct execution should not be possible in the demo
        direct_attempt = {"outcome": "unexpectedly_executed"}

    prod_request = _build_request("prod-db-primary", escrow)
    prod_result = executor.execute(
        prod_request,
        lambda request, credential: _delete_with_brokered_credential(request.intent.target.resource_id, credential),
        policy_decision=_decision("prod-db-primary"),
    )

    sandbox_request = _build_request("sandbox-temp-volume", escrow)
    sandbox_result = executor.execute(
        sandbox_request,
        lambda request, credential: _delete_with_brokered_credential(request.intent.target.resource_id, credential),
        policy_decision=_decision("sandbox-temp-volume"),
    )

    return {
        "direct_agent_attempt": direct_attempt,
        "production_delete_refusal": prod_result.refusal.to_dict() if prod_result.refusal else None,
        "sandbox_delete_receipt": sandbox_result.receipt.to_dict() if sandbox_result.receipt else None,
        "resources": RESOURCES,
        "credential_material_written": False,
    }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
