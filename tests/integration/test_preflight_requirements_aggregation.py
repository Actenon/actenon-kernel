from __future__ import annotations

import warnings
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon import ActenonGate
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.preflight import (
    PreflightEngine,
    PreflightEvidence,
    build_destructive_actions_policy_pack,
)
from actenon.replay import ReplayProtector, SqliteReplayStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _intent(
    *,
    intent_id: str,
    capability: str,
    parameters: dict[str, object],
    resource_type: str,
    resource_id: str,
) -> ActionIntent:
    return ActionIntent(
        intent_id=intent_id,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_preflight"),
        requester=PartyRef(type="agent", id="policy-agent"),
        action=ActionSpec(
            name=capability,
            capability=capability,
            parameters={"environment": "production", **parameters},
        ),
        target=TargetRef(
            resource_type=resource_type,
            resource_id=resource_id,
            selectors={"environment": "production"},
        ),
    )


def _requirements_by_code(decision: object) -> dict[str, object]:
    return {
        requirement.reason_code: requirement
        for requirement in decision.unmet_requirements
    }


def test_admin_grant_reports_all_requirements_and_documented_evidence_allows() -> None:
    intent = _intent(
        intent_id="intent_admin_grant",
        capability="iam.permission.grant",
        parameters={"role": "admin", "principal": "user:operator"},
        resource_type="iam_principal",
        resource_id="user:operator",
    )
    engine = PreflightEngine()

    refused = engine.check(intent)
    requirements = _requirements_by_code(refused)

    assert refused.outcome == "approval_required"
    assert refused.reason_code == "PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED"
    assert {
        "PREFLIGHT_CHANGE_TICKET_REQUIRED",
        "PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED",
    }.issubset(requirements)
    change_ticket = requirements["PREFLIGHT_CHANGE_TICKET_REQUIRED"]
    assert change_ticket.evidence_keys[0].key == "change_ticket"
    assert change_ticket.evidence_keys[0].value_type == "string"
    assert change_ticket.evidence_keys[0].example == "CHG-2026-0042"
    admin_approval = requirements["PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED"]
    assert {item.key for item in admin_approval.evidence_keys} == {
        "approval_artifacts",
        "approval_present",
        "approval_trusted_keys",
        "approver_types",
    }
    assert admin_approval.required_approvals == ("security_admin",)

    allowed = engine.check(
        intent,
        evidence_context=PreflightEvidence(
            change_ticket="CHG-2026-0042",
            approval_present=True,
            approver_types=("security_admin",),
        ),
    )

    assert allowed.outcome == "allow"
    assert allowed.reason_code == "PREFLIGHT_REQUIREMENTS_SATISFIED"
    assert allowed.unmet_requirements == ()


def test_sensitive_export_reports_both_requirements_and_allows_in_one_pass() -> None:
    intent = _intent(
        intent_id="intent_sensitive_export",
        capability="data.export",
        parameters={
            "row_count": 25_000,
            "destination": "external",
            "sensitive_data": True,
        },
        resource_type="dataset",
        resource_id="customer-records",
    )
    engine = PreflightEngine()

    refused = engine.check(intent)
    requirements = _requirements_by_code(refused)

    assert refused.reason_code == "PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED"
    assert {
        "PREFLIGHT_CHANGE_TICKET_REQUIRED",
        "PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED",
    }.issubset(requirements)

    allowed = engine.check(
        intent,
        evidence_context={
            "change_ticket": "CHG-2026-0043",
            "approval_present": True,
            "approver_types": ["data_owner", "privacy_reviewer"],
        },
    )

    assert allowed.outcome == "allow"
    assert allowed.unmet_requirements == ()


def test_gate_outcome_and_refusal_artifact_surface_all_unmet_requirements() -> None:
    intent = _intent(
        intent_id="intent_gate_admin_grant",
        capability="iam.permission.grant",
        parameters={"role": "admin", "principal": "user:operator"},
        resource_type="iam_principal",
        resource_id="user:operator",
    )
    side_effects: list[str] = []

    with TemporaryDirectory() as tempdir, warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        gate = ActenonGate.local_dev(
            audience="service:iam-protected-endpoint",
            policy_pack=build_destructive_actions_policy_pack(),
            replay_protector=ReplayProtector(
                SqliteReplayStore(Path(tempdir) / "replay.sqlite3")
            ),
            clock=lambda: NOW,
        )
        proof = gate.mint_proof(intent)

        refused = gate.protect(
            intent,
            proof,
            lambda: side_effects.append("unexpected"),
        )
        allowed = gate.protect(
            replace(intent),
            proof,
            lambda: side_effects.append("executed"),
            evidence=PreflightEvidence(
                change_ticket="CHG-2026-0042",
                approval_present=True,
                approver_types=("security_admin",),
            ),
        )

    assert refused.outcome == "refused"
    assert refused.reason_code == "PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED"
    assert {
        requirement.reason_code for requirement in refused.unmet_requirements
    } == {
        "PREFLIGHT_CHANGE_TICKET_REQUIRED",
        "PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED",
    }
    assert refused.refusal is not None
    refusal_requirements = refused.refusal.details["unmet_requirements"]
    assert len(refusal_requirements) == 2
    assert refused.to_dict()["unmet_requirements"][0]["evidence_keys"]
    assert allowed.ok
    assert allowed.unmet_requirements == ()
    assert side_effects == ["executed"]
