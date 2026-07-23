from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from actenon import ActenonGate
from actenon.adapters import EdgeConfigurationError, ProtectedEdge
from actenon.credentials import BrokeredCredential
from actenon.models import (
    ActionIntent,
    ActionSpec,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.replay import ReplayProtector, SqliteReplayStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
BOUNDARIES = (
    ("database", "database.delete_table", "database.delete", "table", "customers"),
    ("payments", "payment.release", "payment.release", "destination", "bank:approved"),
    ("cloud", "cloud.terminate_instance", "cloud.instance.terminate", "instance_id", "i-001"),
    ("iam", "iam.grant_role", "iam.role.grant", "principal_id", "user-001"),
    ("storage", "storage.delete_object", "storage.object.delete", "object_key", "exports/a.csv"),
    ("ci-cd", "deployment.promote", "deployment.promote", "environment", "production"),
    ("communications", "communications.send", "communications.send", "recipient", "ops@example.test"),
    ("physical-ot", "ot.set_actuator", "ot.actuator.set", "actuator_id", "valve-001"),
)


class BrokeredSyntheticResource:
    def __init__(self, capability: str) -> None:
        self.capability = capability
        self.state: list[dict[str, Any]] = []

    def execute(
        self,
        intent: ActionIntent,
        credential: BrokeredCredential | None,
    ) -> dict[str, str]:
        if not isinstance(credential, BrokeredCredential):
            raise PermissionError("backend requires a brokered credential")
        if self.capability not in credential.scope:
            raise PermissionError("brokered credential is not scoped to this action")
        self.state.append(dict(intent.action.parameters))
        return {"status": "synthetic-side-effect-recorded"}


def _request(target_key: str, target_value: str, *, variant: str) -> dict[str, Any]:
    return {
        "request_id": f"request-{variant}",
        "requested_at": "2026-01-01T12:00:00Z",
        "tenant_id": "tenant-edge-tests",
        "agent_id": "edge-test-agent",
        target_key: target_value,
        "operation_variant": variant,
    }


def _intent_builder(
    boundary: str,
    action_name: str,
    capability: str,
    target_key: str,
):
    def build(request: Mapping[str, Any]) -> ActionIntent:
        requested_at = datetime.fromisoformat(
            str(request["requested_at"]).replace("Z", "+00:00")
        )
        return ActionIntent(
            intent_id=f"intent-{boundary}-{request['request_id']}",
            issued_at=requested_at,
            expires_at=requested_at + timedelta(minutes=10),
            tenant=TenantRef(tenant_id=str(request["tenant_id"])),
            requester=PartyRef(type="agent", id=str(request["agent_id"])),
            action=ActionSpec(
                name=action_name,
                capability=capability,
                parameters=dict(request),
            ),
            target=TargetRef(
                resource_type=boundary,
                resource_id=str(request[target_key]),
            ),
        )

    return build


@pytest.mark.parametrize(
    ("boundary", "action_name", "capability", "target_key", "target_value"),
    BOUNDARIES,
)
def test_eight_resource_boundaries_refuse_rogue_and_laundered_requests(
    tmp_path: Path,
    boundary: str,
    action_name: str,
    capability: str,
    target_key: str,
    target_value: str,
) -> None:
    gate = ActenonGate.local_dev(
        audience=f"service:{boundary}-edge",
        replay_protector=ReplayProtector(
            SqliteReplayStore(tmp_path / f"{boundary}-replay.sqlite3")
        ),
        clock=lambda: NOW,
    )
    resource = BrokeredSyntheticResource(capability)
    edge = ProtectedEdge(
        gate,
        intent_builder=_intent_builder(
            boundary,
            action_name,
            capability,
            target_key,
        ),
        backend=resource.execute,
    )
    authorized = _request(target_key, target_value, variant="authorized")
    laundering_source = _request(
        target_key,
        f"{target_value}-harmless",
        variant="laundering-source",
    )
    laundering_target = _request(
        target_key,
        f"{target_value}-harmful",
        variant="laundering-target",
    )

    rogue = edge.execute(authorized, None)
    assert rogue.reason_code == "NO_PROOF"
    assert resource.state == []

    authorized_proof = gate.mint_proof(edge.intent_for(authorized))
    executed = edge.execute(authorized, authorized_proof)
    assert executed.ok
    assert resource.state == [authorized]

    laundering_proof = gate.mint_proof(edge.intent_for(laundering_source))
    laundered = edge.execute(laundering_target, laundering_proof)
    assert laundered.reason_code in ("INTENT_MISMATCH", "TARGET_MISMATCH", "ACTION_MISMATCH")
    assert resource.state == [authorized]

    replayed = edge.execute(authorized, authorized_proof)
    assert replayed.reason_code == "DUPLICATE_REPLAY"
    assert resource.state == [authorized]

    with pytest.raises(PermissionError, match="brokered credential"):
        resource.execute(edge.intent_for(authorized), None)


def test_edge_public_api_cannot_select_a_proof_derived_action(tmp_path: Path) -> None:
    gate = ActenonGate.local_dev(
        audience="service:edge-api-shape",
        replay_protector=ReplayProtector(
            SqliteReplayStore(tmp_path / "api-shape-replay.sqlite3")
        ),
        clock=lambda: NOW,
    )
    resource = BrokeredSyntheticResource("database.delete")
    builder = _intent_builder(
        "database",
        "database.delete_table",
        "database.delete",
        "table",
    )

    constructor_parameters = inspect.signature(ProtectedEdge).parameters
    execute_parameters = inspect.signature(ProtectedEdge.execute).parameters
    assert "proof_action_builder" not in constructor_parameters
    assert "trusted_action" not in execute_parameters
    assert "proof_action" not in execute_parameters

    with pytest.raises(TypeError):
        ProtectedEdge(
            gate,
            intent_builder=builder,
            backend=resource.execute,
            proof_action_builder=lambda proof: proof.action,
        )


def test_edge_rejects_an_intent_builder_that_omits_requested_fields(
    tmp_path: Path,
) -> None:
    gate = ActenonGate.local_dev(
        audience="service:edge-incomplete-binding",
        replay_protector=ReplayProtector(
            SqliteReplayStore(tmp_path / "incomplete-replay.sqlite3")
        ),
        clock=lambda: NOW,
    )
    resource = BrokeredSyntheticResource("database.delete")
    complete_builder = _intent_builder(
        "database",
        "database.delete_table",
        "database.delete",
        "table",
    )

    def incomplete_builder(request: Mapping[str, Any]) -> ActionIntent:
        intent = complete_builder(request)
        return ActionIntent(
            intent_id=intent.intent_id,
            issued_at=intent.issued_at,
            expires_at=intent.expires_at,
            tenant=intent.tenant,
            requester=intent.requester,
            action=ActionSpec(
                name=intent.action.name,
                capability=intent.action.capability,
                parameters={"table": request["table"]},
            ),
            target=intent.target,
        )

    edge = ProtectedEdge(
        gate,
        intent_builder=incomplete_builder,
        backend=resource.execute,
    )

    with pytest.raises(EdgeConfigurationError, match="complete raw requested action"):
        edge.intent_for(_request("table", "customers", variant="incomplete"))
    assert resource.state == []
