#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUIDES_DIR="$ROOT_DIR/docs/guides"
REFERENCE_DIR="$ROOT_DIR/docs/reference"
PROJECT_HISTORY_DIR="$ROOT_DIR/docs/project-history"
FAILURES=0

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}

require_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    pass "file exists: ${path#$ROOT_DIR/}"
  else
    fail "missing file: ${path#$ROOT_DIR/}"
  fi
}

require_executable() {
  local path="$1"
  if [[ -x "$path" ]]; then
    pass "file is executable: ${path#$ROOT_DIR/}"
  else
    fail "file is not executable: ${path#$ROOT_DIR/}"
  fi
}

require_json_valid() {
  local path="$1"
  if python3 -m json.tool "$path" >/dev/null 2>&1; then
    pass "valid json: ${path#$ROOT_DIR/}"
  else
    fail "invalid json: ${path#$ROOT_DIR/}"
  fi
}

require_contains() {
  local path="$1"
  local needle="$2"
  local description="$3"
  if grep -Fiq "$needle" "$path"; then
    pass "$description"
  else
    fail "$description (missing '$needle' in ${path#$ROOT_DIR/})"
  fi
}

main() {
  local required_files=(
    "$ROOT_DIR/docs/VISION.md"
    "$ROOT_DIR/docs/ACCEPTANCE_CRITERIA.md"
    "$ROOT_DIR/docs/TEST_PLAN.md"
    "$ROOT_DIR/docs/ARCHITECTURE.md"
    "$ROOT_DIR/docs/TASK_LOOP.md"
    "$ROOT_DIR/schemas/action_intent.v1.json"
    "$ROOT_DIR/schemas/pccb.v1.json"
    "$ROOT_DIR/schemas/receipt.v1.json"
    "$ROOT_DIR/schemas/refusal.v1.json"
    "$REFERENCE_DIR/contracts/ACTION_INTENT_EXTERNAL_SPEC.md"
    "$REFERENCE_DIR/contracts/PCCB_SPEC.md"
    "$REFERENCE_DIR/contracts/RECEIPT_SPEC.md"
    "$REFERENCE_DIR/contracts/REFUSAL_SPEC.md"
    "$REFERENCE_DIR/verifier/REPLAY_PROTECTION_ARCHITECTURE.md"
    "$REFERENCE_DIR/verifier/REPLAY_STORE_REFERENCE.md"
    "$ROOT_DIR/VERSIONING_POLICY.md"
    "$GUIDES_DIR/FIRST_10_MINUTES.md"
    "$GUIDES_DIR/LOCAL_PROOF_RUNBOOK.md"
    "$PROJECT_HISTORY_DIR/KERNEL_IMPLEMENTATION_SUMMARY.md"
    "$REFERENCE_DIR/wedges/REFUND_WEDGE_SPEC.md"
    "$REFERENCE_DIR/wedges/REFUND_RECEIPT_REFERENCE.md"
    "$REFERENCE_DIR/wedges/REFUND_RUNBOOK.md"
    "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_WEDGE_SPEC.md"
    "$PROJECT_HISTORY_DIR/PAYMENT_EXECUTION_CONTROL_SUMMARY.md"
    "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RECEIPT_REFERENCE.md"
    "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RUNBOOK.md"
    "$ROOT_DIR/actenon/api/invoice_payment.py"
    "$ROOT_DIR/actenon/api/refund.py"
    "$ROOT_DIR/actenon/api/intake.py"
    "$ROOT_DIR/actenon/core/errors.py"
    "$ROOT_DIR/actenon/core/kernel.py"
    "$ROOT_DIR/actenon/policy/engine.py"
    "$ROOT_DIR/actenon/policy/invoice_payment.py"
    "$ROOT_DIR/actenon/policy/refund.py"
    "$ROOT_DIR/actenon/proof/local.py"
    "$ROOT_DIR/actenon/proof/service.py"
    "$ROOT_DIR/actenon/proof/signing.py"
    "$ROOT_DIR/actenon/demo/local_proof.py"
    "$ROOT_DIR/actenon/escrow/base.py"
    "$ROOT_DIR/actenon/escrow/memory.py"
    "$ROOT_DIR/actenon/escrow/sqlite.py"
    "$ROOT_DIR/actenon/replay/base.py"
    "$ROOT_DIR/actenon/replay/dbapi.py"
    "$ROOT_DIR/actenon/replay/sqlite.py"
    "$ROOT_DIR/actenon/replay/service.py"
    "$ROOT_DIR/actenon/verifier/middleware.py"
    "$ROOT_DIR/actenon/receipts/factory.py"
    "$ROOT_DIR/actenon/receipts/invoice_payment.py"
    "$ROOT_DIR/actenon/receipts/refund.py"
    "$ROOT_DIR/actenon/receipts/writers.py"
    "$ROOT_DIR/actenon/models/contracts.py"
    "$ROOT_DIR/actenon/models/invoice_payment.py"
    "$ROOT_DIR/actenon/models/runtime.py"
    "$ROOT_DIR/examples/invoice_payment_guard_local/protected_endpoint.py"
    "$ROOT_DIR/examples/invoice_payment_guard_local/README.md"
    "$ROOT_DIR/examples/refund_guard_local/protected_endpoint.py"
    "$ROOT_DIR/examples/refund_guard_local/README.md"
    "$ROOT_DIR/tests/unit/test_invoice_payment_policy.py"
    "$ROOT_DIR/tests/integration/test_invoice_payment_local_proof.py"
    "$ROOT_DIR/tests/unit/test_refund_policy.py"
    "$ROOT_DIR/tests/integration/test_refund_local_proof.py"
    "$ROOT_DIR/tests/unit/test_replay_store.py"
    "$ROOT_DIR/tests/unit/test_sqlite_escrow.py"
    "$ROOT_DIR/tests/integration/test_replay_middleware.py"
    "$ROOT_DIR/scripts/first_run.sh"
    "$ROOT_DIR/scripts/run_local_proof.sh"
    "$ROOT_DIR/scripts/reset_demo_state.sh"
    "$ROOT_DIR/scripts/verify.sh"
    "$ROOT_DIR/scripts/judge.sh"
  )

  local acceptance_ids=(
    "AC-001"
    "AC-002"
    "AC-003"
    "AC-004"
    "AC-005"
    "AC-006"
    "AC-007"
    "AC-008"
    "AC-009"
    "AC-010"
    "AC-011"
    "AC-012"
    "AC-013"
  )

  local required_capabilities=(
    "Action Intent"
    "hard rules"
    "tenant rules"
    "dynamic context"
    "PCCB minting"
    "PCCB verification"
    "Capability Escrow"
    "replay protection"
    "protected endpoint verification"
    "refusal envelope"
    "receipt"
    "local proof mode"
    "refund execution"
  )

  local schema_files=(
    "$ROOT_DIR/schemas/action_intent.v1.json"
    "$ROOT_DIR/schemas/pccb.v1.json"
    "$ROOT_DIR/schemas/receipt.v1.json"
    "$ROOT_DIR/schemas/refusal.v1.json"
  )

  printf 'Running Protected Execution Kernel spec-harness verification from %s\n' "$ROOT_DIR"

  for file_path in "${required_files[@]}"; do
    require_file "$file_path"
  done

  require_executable "$ROOT_DIR/scripts/verify.sh"
  require_executable "$ROOT_DIR/scripts/judge.sh"
  require_executable "$ROOT_DIR/scripts/first_run.sh"
  require_executable "$ROOT_DIR/scripts/run_local_proof.sh"
  require_executable "$ROOT_DIR/scripts/reset_demo_state.sh"

  for schema_file in "${schema_files[@]}"; do
    require_json_valid "$schema_file"
  done

  require_contains "$ROOT_DIR/docs/VISION.md" "Core principle: No proof, no action." "vision states the core principle"
  require_contains "$ROOT_DIR/docs/VISION.md" "First wedge: refund execution." "vision fixes the first wedge"
  require_contains "$ROOT_DIR/docs/VISION.md" "## End State" "vision defines the end state"

  require_contains "$ROOT_DIR/docs/ARCHITECTURE.md" "## Component Responsibilities" "architecture defines component responsibilities"
  require_contains "$ROOT_DIR/docs/ARCHITECTURE.md" "## Control Flow" "architecture defines control flow"
  require_contains "$ROOT_DIR/docs/ARCHITECTURE.md" "The first wedge is refund execution only." "architecture narrows the first wedge"

  require_contains "$ROOT_DIR/docs/TEST_PLAN.md" "### Unit" "test plan includes unit coverage"
  require_contains "$ROOT_DIR/docs/TEST_PLAN.md" "### Integration" "test plan includes integration coverage"
  require_contains "$ROOT_DIR/docs/TEST_PLAN.md" "### End-To-End" "test plan includes end-to-end coverage"

  require_contains "$ROOT_DIR/docs/TASK_LOOP.md" "## Build Order" "task loop defines build order"
  require_contains "$ROOT_DIR/docs/TASK_LOOP.md" "## Developer Loop" "task loop defines the developer loop"
  require_contains "$ROOT_DIR/docs/TASK_LOOP.md" "acceptance criteria AC-001 through AC-013 are satisfied" "task loop ties completion to acceptance criteria"

  require_contains "$ROOT_DIR/docs/ACCEPTANCE_CRITERIA.md" "single rebuild acceptance gate." "acceptance criteria names the single gate"
  require_contains "$ROOT_DIR/docs/ACCEPTANCE_CRITERIA.md" "The kernel counts as complete only when all of the following are true:" "acceptance criteria defines completion summary"

  for acceptance_id in "${acceptance_ids[@]}"; do
    require_contains "$ROOT_DIR/docs/ACCEPTANCE_CRITERIA.md" "## ${acceptance_id}" "acceptance criterion ${acceptance_id} exists"
  done

  for capability in "${required_capabilities[@]}"; do
    require_contains "$ROOT_DIR/docs/ACCEPTANCE_CRITERIA.md" "$capability" "acceptance criteria cover ${capability}"
  done

  require_contains "$ROOT_DIR/schemas/action_intent.v1.json" "\"action_intent\"" "action intent schema declares its contract name"
  require_contains "$ROOT_DIR/schemas/pccb.v1.json" "\"action_hash\"" "pccb schema includes action hash binding"
  require_contains "$ROOT_DIR/schemas/pccb.v1.json" "\"audience\"" "pccb schema includes audience binding"
  require_contains "$ROOT_DIR/schemas/pccb.v1.json" "\"nonce\"" "pccb schema includes nonce binding"
  require_contains "$ROOT_DIR/schemas/receipt.v1.json" "\"approval-required\"" "receipt schema supports approval-required outcomes"
  require_contains "$ROOT_DIR/schemas/receipt.v1.json" "\"needs-evidence\"" "receipt schema supports needs-evidence outcomes"
  require_contains "$ROOT_DIR/schemas/refusal.v1.json" "\"violations\"" "refusal schema supports structured violations"
  require_contains "$REFERENCE_DIR/contracts/ACTION_INTENT_EXTERNAL_SPEC.md" "compatibility entry point" "action intent compatibility doc declares its role"
  require_contains "$REFERENCE_DIR/contracts/ACTION_INTENT_EXTERNAL_SPEC.md" "canonical Action Intent specification now lives at" "action intent compatibility doc points to the canonical spec"
  require_contains "$REFERENCE_DIR/contracts/PCCB_SPEC.md" "compatibility entry point" "pccb compatibility doc declares its role"
  require_contains "$REFERENCE_DIR/contracts/PCCB_SPEC.md" "canonical PCCB specification now lives at" "pccb compatibility doc points to the canonical spec"
  require_contains "$REFERENCE_DIR/contracts/RECEIPT_SPEC.md" "compatibility entry point" "receipt compatibility doc declares its role"
  require_contains "$REFERENCE_DIR/contracts/RECEIPT_SPEC.md" "canonical Receipt specification now lives at" "receipt compatibility doc points to the canonical spec"
  require_contains "$REFERENCE_DIR/contracts/REFUSAL_SPEC.md" "compatibility entry point" "refusal compatibility doc declares its role"
  require_contains "$REFERENCE_DIR/contracts/REFUSAL_SPEC.md" "canonical Refusal specification now lives at" "refusal compatibility doc points to the canonical spec"
  require_contains "$REFERENCE_DIR/verifier/REPLAY_PROTECTION_ARCHITECTURE.md" "kernel-owned" "replay architecture declares kernel ownership"
  require_contains "$REFERENCE_DIR/verifier/REPLAY_PROTECTION_ARCHITECTURE.md" "SQLite durable store" "replay architecture documents the durable default backend"
  require_contains "$REFERENCE_DIR/verifier/REPLAY_STORE_REFERENCE.md" "claim_once" "replay store reference documents claim_once"
  require_contains "$REFERENCE_DIR/verifier/REPLAY_STORE_REFERENCE.md" "SqliteReplayStore" "replay store reference documents the local backend"
  require_contains "$GUIDES_DIR/FIRST_10_MINUTES.md" "bash ./scripts/first_run.sh" "first 10 minutes doc gives the exact first command"
  require_contains "$GUIDES_DIR/FIRST_10_MINUTES.md" "approval_required: approval-required" "first 10 minutes doc includes the approval scenario"
  require_contains "$GUIDES_DIR/FIRST_10_MINUTES.md" "invoice_payment.allow: executed" "first 10 minutes doc includes the invoice payment allow scenario"
  require_contains "$GUIDES_DIR/LOCAL_PROOF_RUNBOOK.md" "no API keys" "local proof runbook states the no-api-key requirement"
  require_contains "$GUIDES_DIR/LOCAL_PROOF_RUNBOOK.md" "approval_required" "local proof runbook documents the approval scenario"
  require_contains "$GUIDES_DIR/LOCAL_PROOF_RUNBOOK.md" "needs_evidence" "local proof runbook documents the needs-evidence scenario"
  require_contains "$GUIDES_DIR/LOCAL_PROOF_RUNBOOK.md" "invoice_payment.allow" "local proof runbook documents invoice payment execution"
  require_contains "$GUIDES_DIR/LOCAL_PROOF_RUNBOOK.md" "invoice_payment.batch_hash_mismatch" "local proof runbook documents invoice batch hash mismatch"
  require_contains "$ROOT_DIR/VERSIONING_POLICY.md" "major version is the compatibility unit" "versioning policy defines the compatibility unit"
  require_contains "$ROOT_DIR/VERSIONING_POLICY.md" "Any of the following requires a new major version" "versioning policy defines breaking changes"
  require_contains "$PROJECT_HISTORY_DIR/KERNEL_IMPLEMENTATION_SUMMARY.md" "PCCB verification" "kernel summary documents PCCB verification"
  require_contains "$PROJECT_HISTORY_DIR/KERNEL_IMPLEMENTATION_SUMMARY.md" "protected endpoint middleware" "kernel summary documents middleware"
  require_contains "$PROJECT_HISTORY_DIR/KERNEL_IMPLEMENTATION_SUMMARY.md" "Local proof mode now works end to end" "kernel summary calls out local proof mode status"
  require_contains "$PROJECT_HISTORY_DIR/KERNEL_IMPLEMENTATION_SUMMARY.md" "first-class replay protection" "kernel summary documents replay protection"
  require_contains "$PROJECT_HISTORY_DIR/KERNEL_IMPLEMENTATION_SUMMARY.md" "first strong finance wedge is now refund execution" "kernel summary documents the refund wedge"
  require_contains "$PROJECT_HISTORY_DIR/KERNEL_IMPLEMENTATION_SUMMARY.md" "second strong finance wedge is invoice payment execution" "kernel summary documents the invoice payment wedge"
  require_contains "$REFERENCE_DIR/wedges/REFUND_WEDGE_SPEC.md" "exact amount binding" "refund wedge spec requires exact amount binding"
  require_contains "$REFERENCE_DIR/wedges/REFUND_WEDGE_SPEC.md" "exact target binding" "refund wedge spec requires exact target binding"
  require_contains "$REFERENCE_DIR/wedges/REFUND_WEDGE_SPEC.md" "approval-required" "refund wedge spec documents the approval path"
  require_contains "$REFERENCE_DIR/wedges/REFUND_WEDGE_SPEC.md" "needs-evidence" "refund wedge spec documents the evidence path"
  require_contains "$REFERENCE_DIR/wedges/REFUND_WEDGE_SPEC.md" "replay protection" "refund wedge spec documents replay protection"
  require_contains "$REFERENCE_DIR/wedges/REFUND_WEDGE_SPEC.md" "operator-readable" "refund wedge spec documents operator-readable receipts"
  require_contains "$REFERENCE_DIR/wedges/REFUND_RECEIPT_REFERENCE.md" "operator-readable" "refund receipt reference documents readable summaries"
  require_contains "$REFERENCE_DIR/wedges/REFUND_RECEIPT_REFERENCE.md" "approval-required" "refund receipt reference documents approval-required receipts"
  require_contains "$REFERENCE_DIR/wedges/REFUND_RECEIPT_REFERENCE.md" "needs-evidence" "refund receipt reference documents needs-evidence receipts"
  require_contains "$REFERENCE_DIR/wedges/REFUND_RUNBOOK.md" "bash ./scripts/run_local_proof.sh" "refund runbook gives the exact local proof command"
  require_contains "$REFERENCE_DIR/wedges/REFUND_RUNBOOK.md" "approval_required" "refund runbook includes the approval scenario"
  require_contains "$REFERENCE_DIR/wedges/REFUND_RUNBOOK.md" "no API keys" "refund runbook states the no-api-key requirement"
  require_contains "$REFERENCE_DIR/wedges/REFUND_RUNBOOK.md" "replay.sqlite3" "refund runbook documents replay state artifacts"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_WEDGE_SPEC.md" "exact payer entity binding" "invoice payment wedge spec requires exact payer binding"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_WEDGE_SPEC.md" "exact supplier or payee binding" "invoice payment wedge spec requires exact payee binding"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_WEDGE_SPEC.md" "exact invoice-set binding" "invoice payment wedge spec requires exact invoice-set binding"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_WEDGE_SPEC.md" "BATCH_HASH_MISMATCH" "invoice payment wedge spec documents batch hash refusal"
  require_contains "$PROJECT_HISTORY_DIR/PAYMENT_EXECUTION_CONTROL_SUMMARY.md" "approval and evidence gating" "payment execution summary documents approval and evidence gating"
  require_contains "$PROJECT_HISTORY_DIR/PAYMENT_EXECUTION_CONTROL_SUMMARY.md" "provider-backed payment execution adapters" "payment execution summary documents remaining provider gap"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RECEIPT_REFERENCE.md" "operator-readable" "invoice payment receipt reference documents readable summaries"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RECEIPT_REFERENCE.md" "reconciliation_id" "invoice payment receipt reference documents reconciliation references"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RUNBOOK.md" "bash ./scripts/run_local_proof.sh" "invoice payment runbook gives the exact local proof command"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RUNBOOK.md" "duplicate_invoice_payment" "invoice payment runbook documents duplicate refusal scenario"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RUNBOOK.md" "approval_missing" "invoice payment runbook documents approval scenario"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RUNBOOK.md" "no API keys" "invoice payment runbook states the no-api-key requirement"
  require_contains "$REFERENCE_DIR/wedges/INVOICE_PAYMENT_RUNBOOK.md" "replay.sqlite3" "invoice payment runbook documents replay state artifacts"

  if python3 -m compileall "$ROOT_DIR/actenon" "$ROOT_DIR/examples" "$ROOT_DIR/tests" >/dev/null 2>&1; then
    pass "python package compiles"
  else
    fail "python package failed to compile"
  fi

  if python3 -m unittest discover -s "$ROOT_DIR/tests" -p 'test_*.py' >/dev/null 2>&1; then
    pass "python tests pass"
  else
    fail "python tests failed"
  fi

  if python3 - <<'PY'
import os
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta, timezone

from actenon.api import ActionIntentIntakeService
from actenon.core import ProtectedExecutionKernel
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.models import AudienceRef, DynamicContextInput, PartyRef
from actenon.policy import (
    CapabilityScopeHardRule,
    HardRuleEngine,
    IntentChronologyHardRule,
    IntentTtlHardRule,
    PolicyEngine,
    TenantWorkflowRule,
    TenantWorkflowRuleLayer,
)
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.verifier import ProtectedEndpointMiddleware

with TemporaryDirectory() as tempdir:
    os.environ["ACTENON_REPLAY_DB"] = os.path.join(tempdir, "replay.sqlite3")
    now = datetime.now(timezone.utc)
    payload = {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": "intent_verify_001",
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
        request_id="req_verify_001",
        audience=AudienceRef(type="service", id="protected-endpoint"),
        scope_capabilities=("refund.execute",),
        now=now,
        facts={"risk_level": "normal"},
    )
    signer = HmacSha256Signer(secret=b"verify-secret", key_id="local-verify")
    writer = InMemoryOutcomeWriter()
    receipt_factory = ReceiptFactory()
    refusal_factory = RefusalFactory()
    escrow = InMemoryCapabilityEscrow()
    policy = PolicyEngine(
        hard_rules=HardRuleEngine((IntentChronologyHardRule(), IntentTtlHardRule(), CapabilityScopeHardRule())),
        tenant_workflow_rules=TenantWorkflowRuleLayer(
            tenant_rules={
                "tenant_alpha": (
                    TenantWorkflowRule(
                        rule_id="tenant_alpha.allow",
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
    )
    kernel = ProtectedExecutionKernel(
        intake=ActionIntentIntakeService(),
        policy_engine=policy,
        pccb_minter=PCCBMinter(signer=signer, issuer=PartyRef(type="service", id="kernel")),
        escrow=escrow,
        middleware=middleware,
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=writer,
    )
    admission = kernel.submit_intent(payload, context)
    assert admission.intent is not None
    assert admission.decision is not None and admission.decision.outcome == "allow"
    assert admission.pccb is not None
    request = kernel.build_execution_request(intent=admission.intent, pccb=admission.pccb, context=context)
    result = kernel.execute(request, lambda req: {"external_reference": "exec_001", "resource_version": "v1"})
    assert result.refusal is None
    assert result.receipt is not None and result.receipt.outcome == "executed"
    replay = kernel.execute(request, lambda req: {"external_reference": "exec_002"})
    assert replay.refusal is not None
    assert replay.refusal.refusal_code == "DUPLICATE_REPLAY"
    assert len(writer.receipts) >= 2
    assert len(writer.refusals) == 1
PY
  then
    pass "python kernel smoke test passes"
  else
    fail "python kernel smoke test failed"
  fi

  local demo_artifacts
  demo_artifacts="$(mktemp -d)"
  if ACTENON_DEMO_ARTIFACTS_DIR="$demo_artifacts" bash "$ROOT_DIR/scripts/run_local_proof.sh" >/dev/null 2>&1; then
    pass "local proof demo script passes"
  else
    fail "local proof demo script failed"
  fi
  if [[ -f "$demo_artifacts/manifest.json" && -f "$demo_artifacts/SUMMARY.txt" && -f "$demo_artifacts/scenarios/allow/pccb.json" ]]; then
    pass "local proof artifacts are written"
  else
    fail "local proof artifacts are missing"
  fi
  if [[ -f "$demo_artifacts/invoice_payment/manifest.json" && -f "$demo_artifacts/invoice_payment/scenarios/allow/pccb.json" ]]; then
    pass "invoice payment local proof artifacts are written"
  else
    fail "invoice payment local proof artifacts are missing"
  fi
  if [[ -f "$demo_artifacts/scenarios/approval_required/decision_receipt.json" && -f "$demo_artifacts/scenarios/needs_evidence/decision_receipt.json" ]]; then
    pass "local proof artifacts include approval and evidence decision receipts"
  else
    fail "local proof artifacts are missing approval/evidence decision receipts"
  fi
  if [[ -f "$demo_artifacts/invoice_payment/scenarios/approval_missing/decision_receipt.json" && -f "$demo_artifacts/invoice_payment/scenarios/evidence_missing/decision_receipt.json" ]]; then
    pass "invoice payment local proof artifacts include approval and evidence decision receipts"
  else
    fail "invoice payment local proof artifacts are missing approval/evidence decision receipts"
  fi
  if [[ -d "$demo_artifacts/outcomes/receipts" && -d "$demo_artifacts/outcomes/refusals" ]]; then
    pass "local proof outcome directories exist"
  else
    fail "local proof outcome directories are missing"
  fi
  if [[ -d "$demo_artifacts/invoice_payment/outcomes/receipts" && -d "$demo_artifacts/invoice_payment/outcomes/refusals" ]]; then
    pass "invoice payment local proof outcome directories exist"
  else
    fail "invoice payment local proof outcome directories are missing"
  fi
  if grep -Fq "approval_required: approval-required" "$demo_artifacts/SUMMARY.txt" && grep -Fq "needs_evidence: needs-evidence" "$demo_artifacts/SUMMARY.txt"; then
    pass "local proof summary includes approval and evidence outcomes"
  else
    fail "local proof summary is missing approval/evidence outcomes"
  fi
  if grep -Fq "invoice_payment.approval_missing: approval-required" "$demo_artifacts/SUMMARY.txt" && grep -Fq "invoice_payment.batch_hash_mismatch: deny" "$demo_artifacts/SUMMARY.txt"; then
    pass "local proof summary includes invoice payment outcomes"
  else
    fail "local proof summary is missing invoice payment outcomes"
  fi
  rm -rf "$demo_artifacts"

  if ((FAILURES > 0)); then
    printf '\nProtected Execution Kernel spec harness verification failed with %d issue(s).\n' "$FAILURES" >&2
    exit 1
  fi

  printf '\nPASS: Protected Execution Kernel spec harness is internally consistent.\n'
  printf 'Acceptance gate: scripts/verify.sh\n'
  printf 'Kernel completion bar: satisfy AC-001 through AC-013 and the refund plus invoice payment finance wedges.\n'
}

main "$@"
