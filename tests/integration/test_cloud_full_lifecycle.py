from __future__ import annotations

import unittest
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from itertools import count
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from actenon.api import ActionIntentIntakeService
from actenon.core import ProtectedExecutionKernel
from actenon.escrow import SqliteCapabilityEscrow
from actenon.evidence.stores import InMemoryActionIntentStore, InMemoryPCCBStore
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    EvidenceRef,
    PartyRef,
    PCCB,
    PolicyDecision,
    ProtectedExecutionRequest,
    Receipt,
    Refusal,
    RuleEvaluation,
    TargetRef,
    TenantRef,
)
from actenon.policy import CapabilityScopeHardRule, HardRuleEngine, IntentChronologyHardRule, IntentTtlHardRule, PolicyEngine, TenantWorkflowRuleLayer
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier, VerifierDisclosureMode
from actenon.receipts import InMemoryOutcomeWriter, OutcomeAttestationService, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore, build_replay_key
from actenon.verifier import ProtectedEndpointMiddleware


NOW = datetime(2026, 6, 4, 12, 0, tzinfo=timezone.utc)
AUDIENCE = AudienceRef(type="service", id="cloud-lifecycle-protected-endpoint")


@dataclass
class _LifecycleAuditLog:
    events: list[dict[str, Any]] = field(default_factory=list)

    def record(self, event: str, **fields: Any) -> None:
        self.events.append({"event": event, **fields})

    def names(self) -> list[str]:
        return [event["event"] for event in self.events]

    def by_name(self, name: str) -> list[dict[str, Any]]:
        return [event for event in self.events if event["event"] == name]


@dataclass
class _LifecycleUsageMeter:
    billable_receipt_ids: list[str] = field(default_factory=list)

    @property
    def billable_action_count(self) -> int:
        return len(self.billable_receipt_ids)

    def record_receipt(self, receipt: Receipt) -> None:
        if receipt.phase == "execution" and receipt.outcome == "executed":
            self.billable_receipt_ids.append(receipt.receipt_id)


class _LifecycleOutcomeWriter(InMemoryOutcomeWriter):
    def __init__(self, *, audit_log: _LifecycleAuditLog, usage_meter: _LifecycleUsageMeter, pccb_store: InMemoryPCCBStore) -> None:
        super().__init__(pccb_store=pccb_store)
        self.audit_log = audit_log
        self.usage_meter = usage_meter

    def write_receipt(self, receipt: Receipt) -> None:
        super().write_receipt(receipt)
        self.usage_meter.record_receipt(receipt)
        self.audit_log.record(
            "receipt_emitted",
            receipt_id=receipt.receipt_id,
            outcome=receipt.outcome,
            phase=receipt.phase,
            pccb_id=receipt.correlation.pccb_id if receipt.correlation else None,
        )

    def write_refusal(self, refusal: Refusal) -> None:
        super().write_refusal(refusal)
        self.audit_log.record(
            "refusal_emitted",
            refusal_id=refusal.refusal_id,
            refusal_code=refusal.reason_code,
            category=refusal.category,
            pccb_id=refusal.correlation.pccb_id if refusal.correlation else None,
        )


@dataclass(frozen=True)
class _ApprovalEvidenceAllowRule:
    rule_id: str = "tenant.lifecycle.data_export.approval_and_evidence"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        if intent.tenant.tenant_id != "tenant_cloud_lifecycle":
            return None
        if intent.action.capability != "data.export":
            return None
        evidence_values = tuple(item.value for item in intent.evidence_refs)
        if context.facts.get("approval_status") != "approved":
            return None
        if "change_ticket:CHG-2026-0604" not in evidence_values:
            return None
        return RuleEvaluation(
            rule_id=self.rule_id,
            outcome="allow",
            reason_code="APPROVED_EVIDENCE_ALLOW",
            summary="Approved data export evidence is present.",
            details={
                "approver_id": context.facts.get("approver_id"),
                "evidence_refs": list(evidence_values),
            },
        )


class _InProcessCloudLifecycleHarness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.audit_log = _LifecycleAuditLog()
        self.usage_meter = _LifecycleUsageMeter()
        self.intent_store = InMemoryActionIntentStore()
        self.pccb_store = InMemoryPCCBStore()
        self.signer = HmacSha256Signer(secret=b"cloud-lifecycle-local-test-secret", key_id="cloud-lifecycle-hs256")
        self.replay_store = SqliteReplayStore(root / "replay.sqlite3")
        self.escrow = SqliteCapabilityEscrow(root / "escrow.sqlite3")
        self._receipt_counter = count(1)
        self._refusal_counter = count(1)
        self._pccb_counter = count(1)
        self._nonce_counter = count(1)
        self.writer = _LifecycleOutcomeWriter(
            audit_log=self.audit_log,
            usage_meter=self.usage_meter,
            pccb_store=self.pccb_store,
        )
        self.receipt_factory = ReceiptFactory(receipt_id_factory=self._next_receipt_id)
        self.refusal_factory = RefusalFactory(refusal_id_factory=self._next_refusal_id)
        self.policy_engine: PolicyEngine | None = None
        self.kernel: ProtectedExecutionKernel | None = None

    def _next_receipt_id(self) -> str:
        return f"rcpt_cloud_lifecycle_{next(self._receipt_counter):03d}"

    def _next_refusal_id(self) -> str:
        return f"rfsl_cloud_lifecycle_{next(self._refusal_counter):03d}"

    def _next_pccb_id(self) -> str:
        return f"pccb_cloud_lifecycle_{next(self._pccb_counter):03d}"

    def _next_nonce(self) -> str:
        return f"nonce-cloud-lifecycle-{next(self._nonce_counter):04d}"

    def create_tenant(self) -> TenantRef:
        tenant = TenantRef(tenant_id="tenant_cloud_lifecycle", attributes={"mode": "sqlite-in-process"})
        self.audit_log.record("tenant_created", tenant_id=tenant.tenant_id)
        return tenant

    def create_policy(self) -> PolicyEngine:
        policy = PolicyEngine(
            hard_rules=HardRuleEngine((IntentChronologyHardRule(), IntentTtlHardRule(), CapabilityScopeHardRule())),
            tenant_workflow_rules=TenantWorkflowRuleLayer(
                tenant_rules={
                    "tenant_cloud_lifecycle": (_ApprovalEvidenceAllowRule(),),
                }
            ),
        )
        self.policy_engine = policy
        self.audit_log.record("policy_created", rule_id=_ApprovalEvidenceAllowRule.rule_id)
        self.kernel = self._build_kernel(policy)
        return policy

    def _build_kernel(self, policy: PolicyEngine) -> ProtectedExecutionKernel:
        middleware = ProtectedEndpointMiddleware(
            proof_verifier=PCCBVerifier(self.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
            escrow=self.escrow,
            receipt_factory=self.receipt_factory,
            refusal_factory=self.refusal_factory,
            outcome_writer=self.writer,
            replay_protector=ReplayProtector(self.replay_store),
        )
        return ProtectedExecutionKernel(
            intake=ActionIntentIntakeService(),
            policy_engine=policy,
            pccb_minter=PCCBMinter(
                signer=self.signer,
                issuer=PartyRef(type="service", id="cloud-control-plane-local"),
                pccb_id_factory=self._next_pccb_id,
                nonce_factory=self._next_nonce,
            ),
            escrow=self.escrow,
            middleware=middleware,
            receipt_factory=self.receipt_factory,
            refusal_factory=self.refusal_factory,
            outcome_writer=self.writer,
            intent_store=self.intent_store,
            pccb_store=self.pccb_store,
            escrow_id_factory=lambda: "esc_cloud_lifecycle_001",
        )

    def submit_intent(self, payload: dict[str, Any], context: DynamicContextInput):
        assert self.kernel is not None
        result = self.kernel.submit_intent(payload, context)
        if result.intent is None:
            self.audit_log.record("action_intent_rejected", refusal_code=result.refusal.reason_code if result.refusal else None)
            return result
        self.audit_log.record("action_intent_accepted", intent_id=result.intent.intent_id, tenant_id=result.intent.tenant.tenant_id)
        assert result.decision is not None
        self.audit_log.record(
            "policy_evaluated",
            outcome=result.decision.outcome,
            reason_codes=list(result.decision.reason_codes),
            approver_id=context.facts.get("approver_id"),
            evidence_refs=[item.value for item in result.intent.evidence_refs],
        )
        if result.pccb is not None:
            self.audit_log.record(
                "proof_issued",
                pccb_id=result.pccb.pccb_id,
                action_hash=result.pccb.action_hash.value,
                escrow_id=result.escrow_id,
            )
            self.audit_log.record("escrow_created", escrow_id=result.escrow_id, pccb_id=result.pccb.pccb_id)
        return result

    def execute(self, request: ProtectedExecutionRequest):
        assert self.kernel is not None
        self.audit_log.record(
            "protected_execution_requested",
            request_id=request.context.request_id,
            pccb_id=request.pccb.pccb_id,
            escrow_id=request.pccb.escrow_id,
        )
        result = self.kernel.execute(request, self._handler)
        if request.pccb.escrow_id is not None:
            escrow_record = self.escrow.inspect(request.pccb.escrow_id)
            if escrow_record is not None and escrow_record.state == "consumed":
                self.audit_log.record(
                    "escrow_consumed",
                    escrow_id=escrow_record.escrow_id,
                    pccb_id=escrow_record.pccb_id,
                )
        return result

    def build_request(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> ProtectedExecutionRequest:
        assert self.kernel is not None
        return self.kernel.build_execution_request(intent=intent, pccb=pccb, context=context)

    def attest_receipt(self, receipt: Receipt):
        return OutcomeAttestationService(
            signer=self.signer,
            issuer=PartyRef(type="service", id="cloud-control-plane-local"),
            attestation_id_factory=lambda: f"att_{receipt.receipt_id}",
        ).attest_receipt(receipt, issued_at=NOW + timedelta(seconds=5))

    def attest_refusal(self, refusal: Refusal):
        return OutcomeAttestationService(
            signer=self.signer,
            issuer=PartyRef(type="service", id="cloud-control-plane-local"),
            attestation_id_factory=lambda: f"att_{refusal.refusal_id}",
        ).attest_refusal(refusal, issued_at=NOW + timedelta(seconds=5))

    def verify_receipt_attestation(self, attestation):
        return OutcomeAttestationService(
            signer=self.signer,
            issuer=PartyRef(type="service", id="cloud-control-plane-local"),
        ).verify_receipt_attestation(attestation)

    def verify_refusal_attestation(self, attestation):
        return OutcomeAttestationService(
            signer=self.signer,
            issuer=PartyRef(type="service", id="cloud-control-plane-local"),
        ).verify_refusal_attestation(attestation)

    def mint_unescrowed_pccb(self, intent: ActionIntent, context: DynamicContextInput) -> PCCB:
        return PCCBMinter(
            signer=self.signer,
            issuer=PartyRef(type="service", id="cloud-control-plane-local"),
            pccb_id_factory=lambda: "pccb_cloud_lifecycle_missing_escrow",
            nonce_factory=lambda: "nonce-cloud-lifecycle-missing-escrow",
        ).mint(
            intent,
            PolicyDecision(
                outcome="allow",
                summary="Test-only allow for missing escrow negative path.",
                rule_evaluations=(),
                reason_codes=("TEST_ALLOW",),
            ),
            context,
            escrow_id=None,
        )

    def _handler(self, request: ProtectedExecutionRequest) -> dict[str, Any]:
        return {
            "external_reference": f"export:{request.intent.target.resource_id}",
            "provider_reference": "provider-export-001",
            "resource_version": "dataset-v2",
            "rows_exported": request.intent.action.parameters["row_count"],
        }


class CloudFullLifecycleIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.harness = _InProcessCloudLifecycleHarness(Path(self.tempdir.name))
        self.tenant = self.harness.create_tenant()
        self.harness.create_policy()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _context(self, *, now: datetime = NOW, audience: AudienceRef = AUDIENCE, approved: bool = True) -> DynamicContextInput:
        facts = {
            "approval_status": "approved" if approved else "missing",
            "approver_id": "user:approver_001" if approved else None,
        }
        return DynamicContextInput(
            request_id="req_cloud_lifecycle_001",
            audience=audience,
            scope_capabilities=("data.export",),
            now=now,
            facts=facts,
            parameter_constraints={"dataset_id": "dataset_001", "destination": "s3://approved-export-bucket/dataset_001.csv"},
            resource_selectors=({"resource_type": "dataset", "resource_id": "dataset_001"},),
        )

    def _payload(
        self,
        *,
        intent_id: str = "intent_cloud_lifecycle_001",
        issued_at: datetime = NOW,
        expires_at: datetime = NOW + timedelta(minutes=5),
    ) -> dict[str, Any]:
        return ActionIntent(
            intent_id=intent_id,
            issued_at=issued_at,
            expires_at=expires_at,
            tenant=self.tenant,
            requester=PartyRef(type="agent", id="agent_data_exporter"),
            action=ActionSpec(
                name="data.export",
                capability="data.export",
                parameters={
                    "dataset_id": "dataset_001",
                    "destination": "s3://approved-export-bucket/dataset_001.csv",
                    "row_count": 42,
                    "classification": "internal",
                },
            ),
            target=TargetRef(resource_type="dataset", resource_id="dataset_001"),
            justification="Approved lifecycle test export.",
            evidence_refs=(
                EvidenceRef(type="change_ticket", value="change_ticket:CHG-2026-0604"),
                EvidenceRef(type="approval_record", value="approval:APP-2026-0604"),
            ),
            metadata={"approval_id": "approval:APP-2026-0604"},
        ).to_dict()

    def _allowed_admission(self, *, intent_id: str = "intent_cloud_lifecycle_001", context: DynamicContextInput | None = None):
        return self.harness.submit_intent(self._payload(intent_id=intent_id), context or self._context())

    def test_action_intent_to_verified_receipt_lifecycle_executes_once(self) -> None:
        context = self._context()
        admission = self._allowed_admission(context=context)

        self.assertIsNone(admission.refusal)
        self.assertEqual("allow", admission.decision.outcome)
        self.assertIsNotNone(admission.pccb)
        self.assertIsNotNone(admission.escrow_id)
        assert admission.intent is not None
        assert admission.pccb is not None
        request = self.harness.build_request(admission.intent, admission.pccb, context)

        PCCBVerifier(self.harness.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG).verify(admission.intent, admission.pccb, context)
        result = self.harness.execute(request)

        self.assertIsNone(result.refusal)
        self.assertIsNotNone(result.receipt)
        assert result.receipt is not None
        self.assertEqual("executed", result.receipt.outcome)
        self.assertEqual(1, self.harness.usage_meter.billable_action_count)

        escrow_record = self.harness.escrow.inspect(admission.escrow_id)
        self.assertIsNotNone(escrow_record)
        assert escrow_record is not None
        self.assertEqual("consumed", escrow_record.state)
        replay_state = self.harness.replay_store.inspect(build_replay_key(admission.intent, admission.pccb, context), now=context.now)
        self.assertIsNotNone(replay_state)
        assert replay_state is not None
        self.assertEqual("consumed", replay_state.status)

        attestation = self.harness.attest_receipt(result.receipt)
        verified_receipt = self.harness.verify_receipt_attestation(attestation)
        self.assertEqual(result.receipt.receipt_id, verified_receipt.receipt_id)
        self.assertEqual(admission.pccb.pccb_id, attestation.proof_binding["pccb_id"])
        self.assertEqual(admission.pccb.action_hash.value, attestation.proof_binding["action_hash"])

        event_names = self.harness.audit_log.names()
        for expected in (
            "tenant_created",
            "policy_created",
            "action_intent_accepted",
            "policy_evaluated",
            "proof_issued",
            "escrow_created",
            "protected_execution_requested",
            "escrow_consumed",
            "receipt_emitted",
        ):
            with self.subTest(event=expected):
                self.assertIn(expected, event_names)
        policy_event = self.harness.audit_log.by_name("policy_evaluated")[0]
        self.assertEqual("user:approver_001", policy_event["approver_id"])
        self.assertIn("approval:APP-2026-0604", policy_event["evidence_refs"])

    def test_policy_denied_intent_emits_refusal_and_is_not_billed(self) -> None:
        result = self.harness.submit_intent(self._payload(intent_id="intent_cloud_lifecycle_denied"), self._context(approved=False))

        self.assertIsNotNone(result.refusal)
        self.assertIsNone(result.pccb)
        self.assertEqual("NO_WORKFLOW_RULE_MATCH", result.refusal.reason_code)
        self.assertEqual(0, self.harness.usage_meter.billable_action_count)
        self.assertIn("refusal_emitted", self.harness.audit_log.names())

    def test_tampered_action_wrong_audience_expired_and_missing_escrow_fail_closed(self) -> None:
        cases = (
            ("tampered_action", self._tampered_action_request, "ACTION_MISMATCH"),
            ("wrong_audience", self._wrong_audience_request, "AUDIENCE_MISMATCH"),
            ("expired_proof", self._expired_proof_request, "PROOF_EXPIRED"),
            ("missing_escrow", self._missing_escrow_request, "ESCROW_REFERENCE_MISSING"),
        )
        for name, builder, expected_code in cases:
            with self.subTest(name=name):
                harness = _InProcessCloudLifecycleHarness(Path(self.tempdir.name) / name)
                harness.create_tenant()
                harness.create_policy()
                request = builder(harness)

                result = harness.execute(request)

                self.assertIsNotNone(result.refusal)
                assert result.refusal is not None
                self.assertEqual(expected_code, result.refusal.reason_code)
                self.assertEqual(0, harness.usage_meter.billable_action_count)
                attestation = harness.attest_refusal(result.refusal)
                verified_refusal = harness.verify_refusal_attestation(attestation)
                self.assertEqual(result.refusal.refusal_id, verified_refusal.refusal_id)
                self.assertEqual(request.pccb.pccb_id, attestation.proof_binding["pccb_id"])
                self.assertEqual(request.pccb.action_hash.value, attestation.proof_binding["action_hash"])

    def test_replay_rejected_after_first_execution_and_not_billed_again(self) -> None:
        context = self._context()
        admission = self._allowed_admission(intent_id="intent_cloud_lifecycle_replay", context=context)
        assert admission.intent is not None
        assert admission.pccb is not None
        request = self.harness.build_request(admission.intent, admission.pccb, context)

        first = self.harness.execute(request)
        second = self.harness.execute(request)

        self.assertIsNone(first.refusal)
        self.assertIsNotNone(second.refusal)
        assert second.refusal is not None
        self.assertEqual("DUPLICATE_REPLAY", second.refusal.reason_code)
        self.assertEqual(1, self.harness.usage_meter.billable_action_count)
        attestation = self.harness.attest_refusal(second.refusal)
        verified_refusal = self.harness.verify_refusal_attestation(attestation)
        self.assertEqual(second.refusal.refusal_id, verified_refusal.refusal_id)

    def test_malformed_intent_is_structurally_non_executable_and_not_billed(self) -> None:
        malformed = {
            "contract": {"name": "action_intent", "version": "v1"},
            "intent_id": "intent_cloud_lifecycle_malformed",
            "issued_at": NOW.isoformat().replace("+00:00", "Z"),
            "expires_at": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "tenant": self.tenant.to_dict(),
            "requester": {"type": "agent", "id": "agent_data_exporter"},
            "target": {"resource_type": "dataset", "resource_id": "dataset_001"},
        }

        result = self.harness.submit_intent(malformed, self._context())

        self.assertIsNone(result.intent)
        self.assertIsNotNone(result.refusal)
        self.assertEqual("SCHEMA_INVALID", result.refusal.reason_code)
        self.assertIsNone(result.pccb)
        self.assertEqual(0, self.harness.usage_meter.billable_action_count)
        self.assertIn("action_intent_rejected", self.harness.audit_log.names())

    def _tampered_action_request(self, harness: _InProcessCloudLifecycleHarness) -> ProtectedExecutionRequest:
        context = self._context()
        admission = harness.submit_intent(self._payload(intent_id="intent_cloud_lifecycle_tampered"), context)
        assert admission.intent is not None
        assert admission.pccb is not None
        mutated_intent = replace(
            admission.intent,
            action=replace(
                admission.intent.action,
                parameters={**admission.intent.action.parameters, "row_count": 1000},
            ),
        )
        return harness.build_request(mutated_intent, admission.pccb, context)

    def _wrong_audience_request(self, harness: _InProcessCloudLifecycleHarness) -> ProtectedExecutionRequest:
        context = self._context()
        admission = harness.submit_intent(self._payload(intent_id="intent_cloud_lifecycle_wrong_audience"), context)
        assert admission.intent is not None
        assert admission.pccb is not None
        wrong_context = self._context(audience=AudienceRef(type="service", id="wrong-endpoint"))
        return harness.build_request(admission.intent, admission.pccb, wrong_context)

    def _expired_proof_request(self, harness: _InProcessCloudLifecycleHarness) -> ProtectedExecutionRequest:
        context = self._context()
        payload = self._payload(
            intent_id="intent_cloud_lifecycle_expired",
            expires_at=NOW + timedelta(seconds=30),
        )
        admission = harness.submit_intent(payload, context)
        assert admission.intent is not None
        assert admission.pccb is not None
        expired_context = self._context(now=NOW + timedelta(minutes=1))
        return harness.build_request(admission.intent, admission.pccb, expired_context)

    def _missing_escrow_request(self, harness: _InProcessCloudLifecycleHarness) -> ProtectedExecutionRequest:
        context = self._context()
        admission = harness.submit_intent(self._payload(intent_id="intent_cloud_lifecycle_missing_escrow"), context)
        assert admission.intent is not None
        pccb = harness.mint_unescrowed_pccb(admission.intent, context)
        return harness.build_request(admission.intent, pccb, context)


if __name__ == "__main__":
    unittest.main()
