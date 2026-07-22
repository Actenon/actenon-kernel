from __future__ import annotations

import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon import ActenonGate
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.preflight import (
    PreflightEngine,
    PreflightEvidence,
    build_access_governance_policy_pack,
    build_clinical_policy_pack,
    build_clinical_policy_pack_template,
    build_data_privacy_policy_pack,
    build_payments_policy_pack,
)
from actenon.replay import ReplayProtector, SqliteReplayStore


NOW = datetime(2026, 6, 6, 12, 0, tzinfo=timezone.utc)


def _intent(
    *,
    intent_id: str,
    capability: str,
    parameters: dict[str, object],
    resource_type: str,
    resource_id: str,
    requester_id: str = "domain-policy-agent",
) -> ActionIntent:
    return ActionIntent(
        intent_id=intent_id,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_domain_policy"),
        requester=PartyRef(type="agent", id=requester_id),
        action=ActionSpec(
            name=capability,
            capability=capability,
            parameters=parameters,
        ),
        target=TargetRef(
            resource_type=resource_type,
            resource_id=resource_id,
        ),
    )


def _requirement_codes(decision: object) -> set[str]:
    return {
        requirement.reason_code
        for requirement in decision.unmet_requirements
    }


def test_data_privacy_pack_governs_broad_sensitive_external_exports() -> None:
    engine = PreflightEngine(build_data_privacy_policy_pack())
    small_internal = _intent(
        intent_id="intent_privacy_small_internal",
        capability="data.export",
        parameters={
            "row_count": 250,
            "sensitivity_classification": "internal",
            "destination": "internal://analytics",
            "destination_classification": "internal",
            "source_residency": "gb",
            "destination_residency": "gb",
        },
        resource_type="dataset",
        resource_id="customer-sample",
    )
    broad_external = _intent(
        intent_id="intent_privacy_broad_external",
        capability="data.export",
        parameters={
            "row_count": 5_000_000,
            "sensitivity_classification": "restricted",
            "destination": "https://approved-vendor.example/upload",
            "destination_classification": "external",
            "source_residency": "gb",
            "destination_residency": "us",
        },
        resource_type="dataset",
        resource_id="customer-records",
    )

    allowed = engine.check(small_internal)
    refused = engine.check(broad_external)

    assert allowed.outcome == "allow"
    assert refused.outcome == "approval_required"
    assert refused.reason_code == "PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED"
    assert "PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED" in _requirement_codes(
        refused
    )
    assert "PREFLIGHT_CHANGE_TICKET_REQUIRED" not in _requirement_codes(refused)
    assert {
        "PREFLIGHT_EXTERNAL_EGRESS_EVIDENCE_REQUIRED",
        "PREFLIGHT_RESIDENCY_EVIDENCE_REQUIRED",
    }.issubset(_requirement_codes(refused))

    approved = engine.check(
        broad_external,
        evidence_context=PreflightEvidence(
            approval_present=True,
            approver_types=("data_owner", "privacy_reviewer"),
            destination_allowlisted=True,
            residency_allowed=True,
        ),
    )

    assert approved.outcome == "allow"
    assert approved.unmet_requirements == ()


def test_actenon_gate_uses_explicit_domain_policy_pack() -> None:
    intent = _intent(
        intent_id="intent_gate_privacy_external",
        capability="data.export",
        parameters={
            "row_count": 5_000_000,
            "sensitivity_classification": "restricted",
            "destination": "https://vendor.example/upload",
            "destination_classification": "external",
        },
        resource_type="dataset",
        resource_id="customer-records",
    )
    side_effects: list[str] = []

    with TemporaryDirectory() as tempdir, warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        gate = ActenonGate.local_dev(
            audience="service:privacy-export",
            policy_pack=build_data_privacy_policy_pack(),
            replay_protector=ReplayProtector(
                SqliteReplayStore(Path(tempdir) / "replay.sqlite3")
            ),
            clock=lambda: NOW,
        )
        proof = gate.mint_proof(intent)
        outcome = gate.protect(
            intent,
            proof,
            lambda: side_effects.append("unexpected"),
        )

    assert outcome.outcome == "refused"
    assert outcome.reason_code == "PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED"
    assert side_effects == []


def test_access_governance_pack_allows_jit_reader_and_governs_admin_access() -> None:
    engine = PreflightEngine(build_access_governance_policy_pack())
    reader = _intent(
        intent_id="intent_access_reader",
        capability="iam.role.assign",
        parameters={
            "role": "viewer",
            "role_tier": "standard",
            "access_mode": "jit",
        },
        resource_type="workspace_role",
        resource_id="workspace:analytics",
    )
    admin = _intent(
        intent_id="intent_access_admin",
        capability="iam.permission.grant",
        parameters={
            "role": "admin",
            "role_tier": "privileged",
            "access_mode": "standing",
        },
        resource_type="iam_principal",
        resource_id="user:operator",
    )

    assert engine.check(reader).outcome == "allow"
    refused = engine.check(admin)
    assert refused.outcome == "approval_required"
    assert refused.reason_code == "PREFLIGHT_PRIVILEGED_ACCESS_APPROVAL_REQUIRED"

    approved = engine.check(
        admin,
        evidence_context=PreflightEvidence(
            approval_present=True,
            approver_types=("security_admin", "resource_owner"),
            approver_ids=("security-reviewer", "workspace-owner"),
        ),
    )
    assert approved.outcome == "allow"

    sod_violation = engine.check(
        admin,
        evidence_context=PreflightEvidence(
            approval_present=True,
            approver_types=("security_admin", "resource_owner"),
            approver_ids=("domain-policy-agent", "workspace-owner"),
        ),
    )
    assert sod_violation.outcome == "deny"
    assert (
        sod_violation.reason_code
        == "PREFLIGHT_SEPARATION_OF_DUTIES_VIOLATION"
    )


def test_payments_pack_allows_low_notional_and_requires_high_value_approval() -> None:
    engine = PreflightEngine(
        build_payments_policy_pack(approval_threshold_minor=100_000)
    )
    low_value = _intent(
        intent_id="intent_payment_low",
        capability="payment.release",
        parameters={
            "amount_minor": 5_000,
            "new_payee": False,
            "destination_changed": False,
        },
        resource_type="payment",
        resource_id="payment:low",
    )
    high_value = _intent(
        intent_id="intent_payment_high",
        capability="payment.transfer",
        parameters={
            "amount_minor": 500_000,
            "new_payee": False,
            "destination_changed": False,
        },
        resource_type="payment",
        resource_id="payment:high",
    )

    assert engine.check(low_value).outcome == "allow"
    refused = engine.check(high_value)
    assert refused.outcome == "approval_required"
    assert refused.reason_code == "PREFLIGHT_PAYMENT_APPROVAL_REQUIRED"

    approved = engine.check(
        high_value,
        evidence_context=PreflightEvidence(
            approval_present=True,
            approver_types=("finance_approver",),
        ),
    )
    assert approved.outcome == "allow"


def test_payments_pack_aggregates_new_payee_verification_with_approval() -> None:
    engine = PreflightEngine(build_payments_policy_pack())
    new_payee = _intent(
        intent_id="intent_payment_new_payee",
        capability="payout.release",
        parameters={
            "amount_minor": 10_000,
            "new_payee": True,
            "destination_changed": True,
        },
        resource_type="payout",
        resource_id="payout:new-payee",
    )

    refused = engine.check(new_payee)

    assert refused.reason_code == "PREFLIGHT_PAYMENT_APPROVAL_REQUIRED"
    assert {
        "PREFLIGHT_PAYMENT_APPROVAL_REQUIRED",
        "PREFLIGHT_PAYEE_DESTINATION_VERIFICATION_REQUIRED",
    }.issubset(_requirement_codes(refused))

    approved = engine.check(
        new_payee,
        evidence_context=PreflightEvidence(
            approval_present=True,
            approver_types=("finance_approver",),
            payee_verified=True,
            destination_verified=True,
        ),
    )
    assert approved.outcome == "allow"


def test_clinical_pack_is_marked_template_and_requires_review_for_orders() -> None:
    pack = build_clinical_policy_pack_template()
    engine = PreflightEngine(pack)
    draft = _intent(
        intent_id="intent_clinical_draft",
        capability="clinical.note.draft",
        parameters={"clinical_risk": "low"},
        resource_type="clinical_note",
        resource_id="note:synthetic",
    )
    medication_order = _intent(
        intent_id="intent_clinical_medication",
        capability="medication.order",
        parameters={"clinical_risk": "high"},
        resource_type="medication_order",
        resource_id="order:synthetic",
    )

    assert pack.is_template is True
    assert build_clinical_policy_pack().is_template is True
    assert "not certified clinical guidance" in (pack.disclaimer or "")
    assert engine.check(draft).outcome == "allow"

    refused = engine.check(medication_order)
    assert refused.outcome == "approval_required"
    assert refused.reason_code == "PREFLIGHT_CLINICAL_REVIEW_REQUIRED"
    assert refused.metadata["policy_pack"]["is_template"] is True

    approved = engine.check(
        medication_order,
        evidence_context=PreflightEvidence(
            approval_present=True,
            approver_types=("licensed_clinician",),
        ),
    )
    assert approved.outcome == "allow"
