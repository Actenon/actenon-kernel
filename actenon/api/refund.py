from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


def build_refund_action_intent_payload(
    *,
    intent_id: str,
    tenant_id: str,
    requester_id: str,
    payment_id: str,
    amount_minor: int,
    currency: str,
    issued_at: datetime,
    ttl_seconds: int = 300,
    justification: str | None = None,
    metadata: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    evidence_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    payload: dict[str, Any] = {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": intent_id,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "tenant": {"tenant_id": tenant_id},
        "requester": {"type": "service", "id": requester_id},
        "action": {
            "name": "refund.create",
            "capability": "refund.execute",
            "parameters": {
                "amount_minor": amount_minor,
                "currency": currency,
            },
            "constraints": {
                "exact_amount_minor": amount_minor,
                "exact_currency": currency,
            },
            "scope": {
                "target_resource_type": "payment",
                "single_use": True,
            },
        },
        "target": {
            "resource_type": "payment",
            "resource_id": payment_id,
        },
        "metadata": metadata or {},
        "context": context or {},
    }
    if justification is not None:
        payload["justification"] = justification
    if evidence_refs:
        payload["evidence_refs"] = evidence_refs
    return payload
