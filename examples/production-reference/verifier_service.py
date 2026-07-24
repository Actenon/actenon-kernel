"""Reference verifier service — a FastAPI endpoint that requires a valid PCCB.

This is the resource-owned placement (Placement B): the verifier runs
inside the resource boundary, not inside the agent framework.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.models.runtime import PolicyDecision
from actenon.proof import PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.proof.service import DynamicContextInput

app = FastAPI(title="Actenon Reference Verifier")

# In a real deployment, use a KMS-backed signer (see PRODUCTION_INTEGRATION.md §1.3).
signer = build_local_proof_signer()
minter = PCCBMinter(
    signer=signer,
    issuer=PartyRef(type="service", id="issuer:reference"),
)
verifier = PCCBVerifier(signer=signer)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/mint-proof")
async def mint_proof(request: Request):
    """Mint a PCCB for testing. In production, the issuer is a separate service."""
    body = await request.json()
    now = datetime.now(UTC)
    intent = ActionIntent(
        intent_id=body.get("intent_id", f"intent_{uuid4().hex[:8]}"),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        tenant=TenantRef(tenant_id=body.get("tenant_id", "tenant:reference")),
        requester=PartyRef(type="agent", id=body.get("agent_id", "agent:reference")),
        action=ActionSpec(
            name=body["action"],
            capability=body["action"],
            parameters=body.get("parameters", {}),
        ),
        target=TargetRef(
            resource_type=body.get("target_type", "payment_intent"),
            resource_id=body["target_id"],
        ),
    )
    context = DynamicContextInput(
        request_id=f"req_{uuid4().hex[:8]}",
        audience=AudienceRef(type="service", id="service:payments"),
        scope_capabilities=(body["action"],),
        now=now,
    )
    decision = PolicyDecision(
        outcome="allow",
        summary="Reference deployment allow.",
        rule_evaluations=(),
        reason_codes=("REFERENCE_ALLOW",),
    )
    pccb = minter.mint(intent, decision, context)
    return {
        "intent": intent.to_dict(),
        "pccb": pccb.to_dict(),
    }


@app.post("/refunds")
async def refund(request: Request):
    """Protected endpoint — requires a valid PCCB in the X-Actenon-Proof header."""
    proof_header = request.headers.get("X-Actenon-Proof")
    if not proof_header:
        raise HTTPException(status_code=403, detail="PROOF_MISSING: no proof header")

    body = await request.json()
    intent = ActionIntent.from_dict(body["intent"])
    pccb_dict = body["pccb"]

    # In a real deployment, decode the PCCB from the proof header.
    # For the reference, we accept the PCCB in the body.
    from actenon.models.contracts import PCCB
    pccb = PCCB.from_dict(pccb_dict)

    context = DynamicContextInput(
        request_id=f"req_{uuid4().hex[:8]}",
        audience=AudienceRef(type="service", id="service:payments"),
        scope_capabilities=("payment.refund",),
        now=datetime.now(UTC),
    )

    try:
        verifier.verify(intent, pccb, context)
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"PROOF_INVALID: {e}")

    # If we reach here, the proof verified. Execute the action.
    receipt_id = f"rcpt_{uuid4().hex[:8]}"
    return {
        "outcome": "executed",
        "receipt_id": receipt_id,
        "action": intent.action.name,
        "target": intent.target.resource_id,
        "verified_at": datetime.now(UTC).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
