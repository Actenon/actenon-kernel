from __future__ import annotations

from datetime import timedelta
from typing import Any, Callable, Mapping

from actenon import ActenonGate
from actenon.adapters.edge import ProtectedEdge
from actenon.credentials import BrokeredCredential
from actenon.models import (
    ActionIntent,
    ActionSpec,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.models.contracts import parse_timestamp
from actenon.proof import sha256_hex


def build_intent(
    request: Mapping[str, Any],
    *,
    action_name: str,
    capability: str,
    target_type: str,
    target_key: str,
) -> ActionIntent:
    requested_at = parse_timestamp(request["requested_at"], "requested_at")
    return ActionIntent(
        intent_id=f"intent_edge_{sha256_hex(dict(request))[:20]}",
        issued_at=requested_at,
        expires_at=requested_at + timedelta(minutes=5),
        tenant=TenantRef(tenant_id=str(request["tenant_id"])),
        requester=PartyRef(type="agent", id=str(request["agent_id"])),
        action=ActionSpec(
            name=action_name,
            capability=capability,
            parameters=dict(request),
        ),
        target=TargetRef(
            resource_type=target_type,
            resource_id=str(request[target_key]),
        ),
    )


def protected_edge(
    gate: ActenonGate,
    backend: Callable[[ActionIntent, BrokeredCredential], Any],
    *,
    action_name: str,
    capability: str,
    target_type: str,
    target_key: str,
) -> ProtectedEdge:
    return ProtectedEdge(
        gate,
        intent_builder=lambda request: build_intent(
            request,
            action_name=action_name,
            capability=capability,
            target_type=target_type,
            target_key=target_key,
        ),
        backend=backend,
    )
