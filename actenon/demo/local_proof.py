from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from actenon.api import (
    ActionIntentIntakeService,
    build_invoice_payment_action_intent_payload,
    build_refund_action_intent_payload,
    compute_invoice_payment_batch_hash,
)
from actenon.core import ProtectedExecutionKernel
from actenon.escrow import SqliteCapabilityEscrow
from actenon.models import AudienceRef, DynamicContextInput, PartyRef
from actenon.policy import build_invoice_payment_policy_engine, build_refund_policy_engine
from actenon.proof import PCCBMinter, PCCBVerifier, VerifierDisclosureMode, build_local_proof_signer
from actenon.receipts import (
    CompositeOutcomeWriter,
    InMemoryOutcomeWriter,
    JsonArtifactOutcomeWriter,
    ReceiptFactory,
    RefusalFactory,
)
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.verifier import ProtectedEndpointMiddleware
from examples.invoice_payment_guard_local.protected_endpoint import LocalProtectedInvoicePaymentEndpoint
from examples.refund_guard_local.protected_endpoint import LocalProtectedRefundEndpoint


FIXED_BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class DeterministicSequence:
    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)

    def next(self, prefix: str) -> str:
        self._counters[prefix] += 1
        return f"{prefix}_{self._counters[prefix]:04d}"

    def next_nonce(self) -> str:
        self._counters["nonce"] += 1
        return f"nonce-local-{self._counters['nonce']:08d}"


@dataclass(frozen=True)
class RefundScenarioDefinition:
    name: str
    description: str
    amount_minor: int
    risk_level: str
    expected_outcome: str
    expected_decision_outcome: str
    include_evidence: bool = False


@dataclass(frozen=True)
class InvoicePaymentScenarioDefinition:
    name: str
    description: str
    payer_entity_id: str
    supplier_id: str
    bank_account_reference: str
    invoice_ids: tuple[str, ...]
    amount_minor: int
    currency: str
    payment_date: str
    payment_batch_id: str
    expected_outcome: str
    expected_decision_outcome: str
    required_approval_chain: tuple[str, ...] = ()
    provided_approval_chain: tuple[str, ...] = ()
    required_approver_types: tuple[str, ...] = ()
    required_evidence_types: tuple[str, ...] = ()
    evidence_refs: tuple[dict[str, Any], ...] = ()
    risk_level: str = "normal"
    batch_hash_override: str | None = None
    context_overrides: dict[str, Any] = field(default_factory=dict)


def _write_json(target: Path, payload: Any) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_kernel(artifact_root: Path, *, policy_engine) -> tuple[ProtectedExecutionKernel, InMemoryOutcomeWriter]:
    sequence = DeterministicSequence()
    signer = build_local_proof_signer()
    in_memory_writer = InMemoryOutcomeWriter()
    outcome_writer = CompositeOutcomeWriter(
        in_memory_writer,
        JsonArtifactOutcomeWriter(artifact_root / "outcomes"),
    )
    receipt_factory = ReceiptFactory(receipt_id_factory=lambda: sequence.next("rcpt"))
    refusal_factory = RefusalFactory(refusal_id_factory=lambda: sequence.next("rfsl"))
    replay_store = SqliteReplayStore(artifact_root / "state" / "replay.sqlite3")
    escrow = SqliteCapabilityEscrow(artifact_root / "state" / "escrow.sqlite3")
    middleware = ProtectedEndpointMiddleware(
        proof_verifier=PCCBVerifier(signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
        escrow=escrow,
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=outcome_writer,
        replay_protector=ReplayProtector(replay_store),
    )
    kernel = ProtectedExecutionKernel(
        intake=ActionIntentIntakeService(),
        policy_engine=policy_engine,
        pccb_minter=PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="local_kernel", display_name="Local Kernel"),
            pccb_id_factory=lambda: sequence.next("pccb"),
            nonce_factory=sequence.next_nonce,
        ),
        escrow=middleware.escrow,
        middleware=middleware,
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=outcome_writer,
        escrow_id_factory=lambda: sequence.next("esc"),
    )
    return kernel, in_memory_writer


def _build_refund_payload(scenario: RefundScenarioDefinition, issued_at: datetime) -> dict[str, Any]:
    evidence_refs = None
    if scenario.include_evidence:
        evidence_refs = [{"type": "external_id", "value": "manager-note-001"}]
    payload = build_refund_action_intent_payload(
        intent_id=f"intent_{scenario.name}",
        tenant_id="tenant_demo",
        requester_id="demo_actor",
        payment_id="payment_demo_001",
        amount_minor=scenario.amount_minor,
        currency="USD",
        issued_at=issued_at,
        justification=scenario.description,
        metadata={"scenario": scenario.name, "wedge": "refund"},
        context={"demo_scenario": scenario.name, "demo_wedge": "refund"},
        evidence_refs=evidence_refs,
    )
    payload["requester"]["display_name"] = "Local Proof Demo"
    return payload


def _build_refund_context(scenario: RefundScenarioDefinition, issued_at: datetime) -> DynamicContextInput:
    return DynamicContextInput(
        request_id=f"req_{scenario.name}",
        audience=AudienceRef(type="service", id="local-refund-endpoint"),
        scope_capabilities=("refund.execute",),
        now=issued_at,
        facts={
            "risk_level": scenario.risk_level,
            "scenario": scenario.name,
            "payment_id": "payment_demo_001",
            "payment_currency": "USD",
            "remaining_refundable_minor": 5000,
        },
        parameter_constraints={
            "exact_amount_minor": scenario.amount_minor,
            "exact_currency": "USD",
            "target_resource_id": "payment_demo_001",
        },
        resource_selectors=({"resource_id": "payment_demo_001"},),
        required_evidence_types=("external_id",),
        approver_types=("finance-operator",),
    )


def run_local_proof_demo(artifact_root: Path) -> dict[str, Any]:
    artifact_root = artifact_root.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    endpoint = LocalProtectedRefundEndpoint(artifact_root / "state" / "protected_endpoint_state.json")
    kernel, in_memory_writer = _build_kernel(artifact_root, policy_engine=build_refund_policy_engine())

    scenarios = (
        RefundScenarioDefinition(
            name="allow",
            description="Allow case that executes a protected refund once.",
            amount_minor=1500,
            risk_level="normal",
            expected_outcome="executed",
            expected_decision_outcome="allow",
        ),
        RefundScenarioDefinition(
            name="deny",
            description="Deny case blocked by the tenant workflow layer.",
            amount_minor=1500,
            risk_level="blocked",
            expected_outcome="deny",
            expected_decision_outcome="deny",
        ),
        RefundScenarioDefinition(
            name="approval_required",
            description="Approval-required case that stops pending finance operator approval.",
            amount_minor=2200,
            risk_level="approval",
            expected_outcome="approval-required",
            expected_decision_outcome="approval-required",
        ),
        RefundScenarioDefinition(
            name="needs_evidence",
            description="Needs-evidence case that stops before proof minting.",
            amount_minor=1500,
            risk_level="review",
            expected_outcome="needs-evidence",
            expected_decision_outcome="needs-evidence",
        ),
    )

    manifest: dict[str, Any] = {
        "wedge": "refund",
        "artifact_root": str(artifact_root),
        "protected_endpoint_state": str(endpoint.state_path),
        "escrow_db": str(artifact_root / "state" / "escrow.sqlite3"),
        "scenarios": [],
    }

    for index, scenario in enumerate(scenarios):
        scenario_time = FIXED_BASE_TIME + timedelta(minutes=index)
        scenario_dir = artifact_root / "scenarios" / scenario.name
        payload = _build_refund_payload(scenario, scenario_time)
        context = _build_refund_context(scenario, scenario_time)
        receipt_count_before = len(in_memory_writer.receipts)
        refusal_count_before = len(in_memory_writer.refusals)
        admission = kernel.submit_intent(payload, context)

        result_summary: dict[str, Any] = {
            "wedge": "refund",
            "scenario": scenario.name,
            "description": scenario.description,
            "expected_outcome": scenario.expected_outcome,
            "expected_decision_outcome": scenario.expected_decision_outcome,
            "request_id": context.request_id,
        }
        _write_json(scenario_dir / "action_intent.json", payload)

        if admission.decision is not None:
            result_summary["decision_outcome"] = admission.decision.outcome
            if admission.decision.outcome != scenario.expected_decision_outcome:
                raise RuntimeError(
                    f"Scenario {scenario.name} expected decision {scenario.expected_decision_outcome} "
                    f"but got {admission.decision.outcome}"
                )
        if admission.receipt is not None:
            _write_json(scenario_dir / "decision_receipt.json", admission.receipt.to_dict())
            result_summary["decision_receipt_id"] = admission.receipt.receipt_id
        if admission.refusal is not None:
            _write_json(scenario_dir / "refusal.json", admission.refusal.to_dict())
            result_summary["reason_code"] = admission.refusal.reason_code

        if scenario.name == "allow":
            if admission.intent is None or admission.pccb is None:
                raise RuntimeError("Allow scenario did not produce a proof-carrying admission result.")
            _write_json(scenario_dir / "pccb.json", admission.pccb.to_dict())
            request = kernel.build_execution_request(intent=admission.intent, pccb=admission.pccb, context=context)
            execution = kernel.execute(request, endpoint.handle)
            if execution.receipt is not None:
                _write_json(scenario_dir / "execution_receipt.json", execution.receipt.to_dict())
                result_summary["execution_receipt_id"] = execution.receipt.receipt_id
            if execution.refusal is not None:
                _write_json(scenario_dir / "execution_refusal.json", execution.refusal.to_dict())
                result_summary["execution_reason_code"] = execution.refusal.reason_code
            result_summary["final_outcome"] = execution.receipt.outcome if execution.receipt is not None else "unknown"
            if execution.payload is not None:
                _write_json(scenario_dir / "execution_payload.json", execution.payload)
        else:
            result_summary["final_outcome"] = admission.decision.outcome if admission.decision is not None else "unknown"
            if result_summary["final_outcome"] != scenario.expected_outcome:
                raise RuntimeError(
                    f"Scenario {scenario.name} expected final outcome {scenario.expected_outcome} "
                    f"but got {result_summary['final_outcome']}"
                )

        new_receipts = in_memory_writer.receipts[receipt_count_before:]
        new_refusals = in_memory_writer.refusals[refusal_count_before:]
        result_summary["receipt_ids"] = [item.receipt_id for item in new_receipts]
        result_summary["refusal_ids"] = [item.refusal_id for item in new_refusals]
        _write_json(scenario_dir / "summary.json", result_summary)
        manifest["scenarios"].append(result_summary)

    _write_json(artifact_root / "manifest.json", manifest)

    summary_lines = [
        "Local proof mode completed successfully.",
        f"Artifact root: {artifact_root}",
        f"Protected endpoint state: {endpoint.state_path}",
        "Refund scenarios:",
    ]
    for item in manifest["scenarios"]:
        summary_lines.append(
            f" - {item['scenario']}: {item['final_outcome']} "
            f"(receipts={','.join(item['receipt_ids']) or 'none'}; refusals={','.join(item['refusal_ids']) or 'none'})"
        )
    (artifact_root / "SUMMARY.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return manifest


def _build_invoice_payment_payload(scenario: InvoicePaymentScenarioDefinition, issued_at: datetime) -> dict[str, Any]:
    payload = build_invoice_payment_action_intent_payload(
        intent_id=f"intent_invoice_payment_{scenario.name}",
        tenant_id="tenant_demo",
        requester_id="demo_actor",
        payer_entity_id=scenario.payer_entity_id,
        supplier_id=scenario.supplier_id,
        bank_account_reference=scenario.bank_account_reference,
        invoice_ids=scenario.invoice_ids,
        amount_minor=scenario.amount_minor,
        currency=scenario.currency,
        payment_date=scenario.payment_date,
        payment_batch_id=scenario.payment_batch_id,
        issued_at=issued_at,
        proposer_id="demo_actor",
        justification=scenario.description,
        evidence_refs=list(scenario.evidence_refs) or None,
        context={"demo_scenario": scenario.name, "demo_wedge": "invoice_payment"},
        metadata={"scenario": scenario.name, "wedge": "invoice_payment"},
        batch_hash=scenario.batch_hash_override,
    )
    payload["requester"]["display_name"] = "Local Proof Demo"
    return payload


def _build_invoice_payment_context(scenario: InvoicePaymentScenarioDefinition, issued_at: datetime) -> DynamicContextInput:
    expected_batch_hash = compute_invoice_payment_batch_hash(
        payer_entity_id="entity_demo_ap" if scenario.name == "wrong_entity" else scenario.payer_entity_id,
        supplier_id=scenario.supplier_id,
        bank_account_reference="bank_demo_main" if scenario.name == "bank_mismatch" else scenario.bank_account_reference,
        invoice_ids=scenario.invoice_ids,
        amount_minor=scenario.amount_minor,
        currency=scenario.currency,
        payment_date=scenario.payment_date,
        payment_batch_id=scenario.payment_batch_id,
    )
    facts: dict[str, Any] = {
        "risk_level": scenario.risk_level,
        "scenario": scenario.name,
        "expected_payer_entity_id": "entity_demo_ap" if scenario.name == "wrong_entity" else scenario.payer_entity_id,
        "expected_supplier_id": scenario.supplier_id,
        "expected_bank_account_reference": "bank_demo_main" if scenario.name == "bank_mismatch" else scenario.bank_account_reference,
        "expected_invoice_ids": list(scenario.invoice_ids),
        "expected_amount_minor": scenario.amount_minor,
        "expected_currency": scenario.currency,
        "expected_payment_date": scenario.payment_date,
        "expected_batch_hash": expected_batch_hash,
        "required_approval_chain": list(scenario.required_approval_chain),
        "provided_approval_chain": list(scenario.provided_approval_chain),
        "required_approver_types": list(scenario.required_approver_types),
        "required_evidence_types": list(scenario.required_evidence_types),
    }
    facts.update(scenario.context_overrides)
    return DynamicContextInput(
        request_id=f"req_invoice_payment_{scenario.name}",
        audience=AudienceRef(type="service", id="local-invoice-payment-endpoint"),
        scope_capabilities=("invoice_payment.execute",),
        now=issued_at,
        facts=facts,
        parameter_constraints={
            "exact_payer_entity_id": scenario.payer_entity_id,
            "exact_supplier_id": scenario.supplier_id,
            "exact_bank_account_reference": scenario.bank_account_reference,
            "exact_invoice_ids": list(scenario.invoice_ids),
            "exact_amount_minor": scenario.amount_minor,
            "exact_currency": scenario.currency,
            "exact_payment_date": scenario.payment_date,
            "exact_payment_batch_id": scenario.payment_batch_id,
            "exact_batch_hash": scenario.batch_hash_override or compute_invoice_payment_batch_hash(
                payer_entity_id=scenario.payer_entity_id,
                supplier_id=scenario.supplier_id,
                bank_account_reference=scenario.bank_account_reference,
                invoice_ids=scenario.invoice_ids,
                amount_minor=scenario.amount_minor,
                currency=scenario.currency,
                payment_date=scenario.payment_date,
                payment_batch_id=scenario.payment_batch_id,
            ),
        },
        resource_selectors=({"resource_id": scenario.payment_batch_id},),
        required_evidence_types=scenario.required_evidence_types,
        approver_types=scenario.required_approver_types,
    )


def run_invoice_payment_local_proof_demo(artifact_root: Path) -> dict[str, Any]:
    artifact_root = artifact_root.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    endpoint = LocalProtectedInvoicePaymentEndpoint(artifact_root / "state" / "protected_endpoint_state.json")
    kernel, in_memory_writer = _build_kernel(artifact_root, policy_engine=build_invoice_payment_policy_engine())

    scenarios = (
        InvoicePaymentScenarioDefinition(
            name="allow",
            description="Allow case that executes a protected invoice payment once.",
            payer_entity_id="entity_demo_ap",
            supplier_id="supplier_demo_001",
            bank_account_reference="bank_demo_main",
            invoice_ids=("inv_allow_001", "inv_allow_002"),
            amount_minor=6500,
            currency="USD",
            payment_date="2026-01-15",
            payment_batch_id="batch_allow_001",
            expected_outcome="executed",
            expected_decision_outcome="allow",
            required_approval_chain=("approver_manager", "approver_controller"),
            provided_approval_chain=("approver_manager", "approver_controller"),
            required_approver_types=("finance-controller", "treasury-operator"),
        ),
        InvoicePaymentScenarioDefinition(
            name="duplicate_invoice_payment",
            description="Deny case for an invoice that has already been paid or scheduled.",
            payer_entity_id="entity_demo_ap",
            supplier_id="supplier_demo_001",
            bank_account_reference="bank_demo_main",
            invoice_ids=("inv_dup_001",),
            amount_minor=1200,
            currency="USD",
            payment_date="2026-01-15",
            payment_batch_id="batch_duplicate_001",
            expected_outcome="deny",
            expected_decision_outcome="deny",
            context_overrides={"duplicate_invoice_ids": ["inv_dup_001"]},
        ),
        InvoicePaymentScenarioDefinition(
            name="wrong_entity",
            description="Deny case for a payer entity that does not match the protected payment context.",
            payer_entity_id="entity_other_ap",
            supplier_id="supplier_demo_001",
            bank_account_reference="bank_demo_main",
            invoice_ids=("inv_entity_001",),
            amount_minor=1600,
            currency="USD",
            payment_date="2026-01-18",
            payment_batch_id="batch_entity_001",
            expected_outcome="deny",
            expected_decision_outcome="deny",
        ),
        InvoicePaymentScenarioDefinition(
            name="bank_mismatch",
            description="Deny case for bank details that do not match the validated payee reference.",
            payer_entity_id="entity_demo_ap",
            supplier_id="supplier_demo_001",
            bank_account_reference="bank_demo_wrong",
            invoice_ids=("inv_bank_001",),
            amount_minor=1900,
            currency="USD",
            payment_date="2026-01-19",
            payment_batch_id="batch_bank_001",
            expected_outcome="deny",
            expected_decision_outcome="deny",
        ),
        InvoicePaymentScenarioDefinition(
            name="approval_missing",
            description="Approval-required case that stops until the full approval chain is complete.",
            payer_entity_id="entity_demo_ap",
            supplier_id="supplier_demo_001",
            bank_account_reference="bank_demo_main",
            invoice_ids=("inv_approval_001",),
            amount_minor=2200,
            currency="USD",
            payment_date="2026-01-16",
            payment_batch_id="batch_approval_001",
            expected_outcome="approval-required",
            expected_decision_outcome="approval-required",
            required_approval_chain=("approver_manager", "approver_controller"),
            provided_approval_chain=("approver_manager",),
            required_approver_types=("finance-controller", "treasury-operator"),
        ),
        InvoicePaymentScenarioDefinition(
            name="evidence_missing",
            description="Needs-evidence case that stops until documentary evidence is attached.",
            payer_entity_id="entity_demo_ap",
            supplier_id="supplier_demo_001",
            bank_account_reference="bank_demo_main",
            invoice_ids=("inv_evidence_001",),
            amount_minor=1800,
            currency="USD",
            payment_date="2026-01-17",
            payment_batch_id="batch_evidence_001",
            expected_outcome="needs-evidence",
            expected_decision_outcome="needs-evidence",
            required_evidence_types=("invoice_pdf", "supplier_statement"),
        ),
        InvoicePaymentScenarioDefinition(
            name="batch_hash_mismatch",
            description="Deny case for a batch hash that does not match the declared invoice payment set.",
            payer_entity_id="entity_demo_ap",
            supplier_id="supplier_demo_001",
            bank_account_reference="bank_demo_main",
            invoice_ids=("inv_hash_001",),
            amount_minor=2100,
            currency="USD",
            payment_date="2026-01-20",
            payment_batch_id="batch_hash_001",
            expected_outcome="deny",
            expected_decision_outcome="deny",
            batch_hash_override="batch_tampered_0001",
        ),
    )

    manifest: dict[str, Any] = {
        "wedge": "invoice_payment",
        "artifact_root": str(artifact_root),
        "protected_endpoint_state": str(endpoint.state_path),
        "escrow_db": str(artifact_root / "state" / "escrow.sqlite3"),
        "scenarios": [],
    }

    for index, scenario in enumerate(scenarios):
        scenario_time = FIXED_BASE_TIME + timedelta(minutes=10 + index)
        scenario_dir = artifact_root / "scenarios" / scenario.name
        payload = _build_invoice_payment_payload(scenario, scenario_time)
        context = _build_invoice_payment_context(scenario, scenario_time)
        receipt_count_before = len(in_memory_writer.receipts)
        refusal_count_before = len(in_memory_writer.refusals)
        admission = kernel.submit_intent(payload, context)

        result_summary: dict[str, Any] = {
            "wedge": "invoice_payment",
            "scenario": scenario.name,
            "description": scenario.description,
            "expected_outcome": scenario.expected_outcome,
            "expected_decision_outcome": scenario.expected_decision_outcome,
            "request_id": context.request_id,
        }
        _write_json(scenario_dir / "action_intent.json", payload)

        if admission.decision is not None:
            result_summary["decision_outcome"] = admission.decision.outcome
            if admission.decision.outcome != scenario.expected_decision_outcome:
                raise RuntimeError(
                    f"Scenario {scenario.name} expected decision {scenario.expected_decision_outcome} "
                    f"but got {admission.decision.outcome}"
                )
        if admission.receipt is not None:
            _write_json(scenario_dir / "decision_receipt.json", admission.receipt.to_dict())
            result_summary["decision_receipt_id"] = admission.receipt.receipt_id
        if admission.refusal is not None:
            _write_json(scenario_dir / "refusal.json", admission.refusal.to_dict())
            result_summary["reason_code"] = admission.refusal.reason_code

        if scenario.name == "allow":
            if admission.intent is None or admission.pccb is None:
                raise RuntimeError("Allow scenario did not produce a proof-carrying admission result.")
            _write_json(scenario_dir / "pccb.json", admission.pccb.to_dict())
            request = kernel.build_execution_request(intent=admission.intent, pccb=admission.pccb, context=context)
            execution = kernel.execute(request, endpoint.handle)
            if execution.receipt is not None:
                _write_json(scenario_dir / "execution_receipt.json", execution.receipt.to_dict())
                result_summary["execution_receipt_id"] = execution.receipt.receipt_id
            if execution.refusal is not None:
                _write_json(scenario_dir / "execution_refusal.json", execution.refusal.to_dict())
                result_summary["execution_reason_code"] = execution.refusal.reason_code
            result_summary["final_outcome"] = execution.receipt.outcome if execution.receipt is not None else "unknown"
            if execution.payload is not None:
                _write_json(scenario_dir / "execution_payload.json", execution.payload)
        else:
            result_summary["final_outcome"] = admission.decision.outcome if admission.decision is not None else "unknown"
            if result_summary["final_outcome"] != scenario.expected_outcome:
                raise RuntimeError(
                    f"Scenario {scenario.name} expected final outcome {scenario.expected_outcome} "
                    f"but got {result_summary['final_outcome']}"
                )

        new_receipts = in_memory_writer.receipts[receipt_count_before:]
        new_refusals = in_memory_writer.refusals[refusal_count_before:]
        result_summary["receipt_ids"] = [item.receipt_id for item in new_receipts]
        result_summary["refusal_ids"] = [item.refusal_id for item in new_refusals]
        _write_json(scenario_dir / "summary.json", result_summary)
        manifest["scenarios"].append(result_summary)

    _write_json(artifact_root / "manifest.json", manifest)

    summary_lines = [
        "Local proof mode completed successfully.",
        f"Artifact root: {artifact_root}",
        f"Protected endpoint state: {endpoint.state_path}",
        "Invoice payment scenarios:",
    ]
    for item in manifest["scenarios"]:
        summary_lines.append(
            f" - {item['scenario']}: {item['final_outcome']} "
            f"(receipts={','.join(item['receipt_ids']) or 'none'}; refusals={','.join(item['refusal_ids']) or 'none'})"
        )
    (artifact_root / "SUMMARY.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return manifest


def run_all_local_proof_demos(artifact_root: Path) -> dict[str, Any]:
    artifact_root = artifact_root.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    refund_manifest = run_local_proof_demo(artifact_root)
    invoice_manifest = run_invoice_payment_local_proof_demo(artifact_root / "invoice_payment")
    combined_manifest = {
        "artifact_root": str(artifact_root),
        "refund": refund_manifest,
        "invoice_payment": invoice_manifest,
    }
    _write_json(artifact_root / "manifest.json", combined_manifest)

    summary_lines = [
        "Local proof mode completed successfully.",
        f"Artifact root: {artifact_root}",
        f"Refund protected endpoint state: {refund_manifest['protected_endpoint_state']}",
        f"Refund escrow DB: {refund_manifest['escrow_db']}",
        f"Invoice payment protected endpoint state: {invoice_manifest['protected_endpoint_state']}",
        f"Invoice payment escrow DB: {invoice_manifest['escrow_db']}",
        "Refund scenarios:",
    ]
    for item in refund_manifest["scenarios"]:
        summary_lines.append(
            f" - refund.{item['scenario']}: {item['final_outcome']} "
            f"(receipts={','.join(item['receipt_ids']) or 'none'}; refusals={','.join(item['refusal_ids']) or 'none'})"
        )
    summary_lines.append("Invoice payment scenarios:")
    for item in invoice_manifest["scenarios"]:
        summary_lines.append(
            f" - invoice_payment.{item['scenario']}: {item['final_outcome']} "
            f"(receipts={','.join(item['receipt_ids']) or 'none'}; refusals={','.join(item['refusal_ids']) or 'none'})"
        )
    (artifact_root / "SUMMARY.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return combined_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic local proof demo.")
    parser.add_argument(
        "--artifacts-dir",
        default=str(Path.cwd() / "artifacts" / "local_proof"),
        help="Directory where local proof artifacts should be written.",
    )
    args = parser.parse_args()
    manifest = run_all_local_proof_demos(Path(args.artifacts_dir))
    print("Local proof mode completed.")
    print(f"Artifacts: {manifest['artifact_root']}")
    print("Refund wedge:")
    for item in manifest["refund"]["scenarios"]:
        print(f"refund.{item['scenario']}: {item['final_outcome']}")
    print("Invoice payment wedge:")
    for item in manifest["invoice_payment"]["scenarios"]:
        print(f"invoice_payment.{item['scenario']}: {item['final_outcome']}")
    print(f"Refund protected endpoint state: {manifest['refund']['protected_endpoint_state']}")
    print(f"Invoice payment protected endpoint state: {manifest['invoice_payment']['protected_endpoint_state']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
