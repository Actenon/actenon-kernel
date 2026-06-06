"""Local Actenon proof gate for consequential MCP tools.

The MCP transport is intentionally thin. The important boundary is here: each
tool verifies proof, checks local Preflight policy, obtains a brokered
credential, executes or refuses, and emits canonical Receipt/Refusal artifacts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from actenon.core import ContractValidationError, ProofVerificationError, RefusalException
from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.execution import ProtectedExecutor
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    ExecutionResult,
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
from actenon.models.contracts import format_timestamp
from actenon.preflight import PreflightDecision, PreflightEngine
from actenon.proof import PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.receipts import (
    CompositeOutcomeWriter,
    InMemoryOutcomeWriter,
    JsonArtifactOutcomeWriter,
    ReceiptFactory,
    RefusalFactory,
)
from actenon.replay import ReplayProtector, SqliteReplayStore


EXAMPLE_ROOT = Path(__file__).resolve().parent
DEMO_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
MCP_AUDIENCE = AudienceRef(type="service", id="actenon-mcp-consequential-tools")


@dataclass(frozen=True)
class ConsequentialToolSpec:
    tool_name: str
    capability: str
    resource_type: str
    allowed_target: str
    refused_target: str
    allowed_parameters: dict[str, Any]
    refused_parameters: dict[str, Any]


TOOL_SPECS: dict[str, ConsequentialToolSpec] = {
    "filesystem.delete": ConsequentialToolSpec(
        tool_name="filesystem.delete",
        capability="infrastructure.delete",
        resource_type="filesystem_path",
        allowed_target="sandbox:/tmp/actenon-demo/stale-build",
        refused_target="prod:/srv/customer-exports",
        allowed_parameters={
            "path": "/tmp/actenon-demo/stale-build",
            "environment": "sandbox",
            "recursive": True,
        },
        refused_parameters={
            "path": "/srv/customer-exports",
            "environment": "production",
            "recursive": True,
        },
    ),
    "database.migrate": ConsequentialToolSpec(
        tool_name="database.migrate",
        capability="migration.apply",
        resource_type="database",
        allowed_target="sandbox-db",
        refused_target="prod-db-primary",
        allowed_parameters={
            "database": "sandbox-db",
            "migration_id": "2026_01_add_demo_index",
            "environment": "sandbox",
        },
        refused_parameters={
            "database": "prod-db-primary",
            "migration_id": "2026_01_rewrite_customer_table",
            "environment": "production",
        },
    ),
    "iam.grant": ConsequentialToolSpec(
        tool_name="iam.grant",
        capability="iam.permission.grant",
        resource_type="iam_principal",
        allowed_target="user:sandbox-analyst",
        refused_target="user:contractor-prod",
        allowed_parameters={
            "principal": "user:sandbox-analyst",
            "role": "read_only",
            "environment": "sandbox",
        },
        refused_parameters={
            "principal": "user:contractor-prod",
            "role": "admin",
            "environment": "production",
        },
    ),
    "data.export": ConsequentialToolSpec(
        tool_name="data.export",
        capability="data.export",
        resource_type="dataset",
        allowed_target="sandbox-events",
        refused_target="customer-pii-prod",
        allowed_parameters={
            "dataset": "sandbox-events",
            "row_count": 250,
            "destination": "internal",
            "environment": "sandbox",
        },
        refused_parameters={
            "dataset": "customer-pii-prod",
            "row_count": 50000,
            "destination": "external",
            "sensitive_data": True,
            "environment": "production",
        },
    ),
    "payment.release": ConsequentialToolSpec(
        tool_name="payment.release",
        capability="payment.release",
        resource_type="payment_batch",
        allowed_target="batch_sandbox_001",
        refused_target="batch_prod_777",
        allowed_parameters={
            "batch_id": "batch_sandbox_001",
            "amount_minor": 1250,
            "currency": "USD",
            "environment": "sandbox",
        },
        refused_parameters={
            "batch_id": "batch_prod_777",
            "amount_minor": 25000000,
            "currency": "USD",
            "environment": "production",
        },
    ),
}


@dataclass(frozen=True)
class DemoToolCall:
    tool_name: str
    intent: ActionIntent
    pccb: PCCB
    preflight_evidence: dict[str, Any]

    def to_mcp_arguments(self) -> dict[str, str]:
        return {
            "intent_json": json.dumps(self.intent.to_dict(), sort_keys=True),
            "pccb_json": json.dumps(self.pccb.to_dict(), sort_keys=True),
            "preflight_evidence_json": json.dumps(self.preflight_evidence, sort_keys=True),
        }


@dataclass(frozen=True)
class ProtectedMCPToolOutcome:
    ok: bool
    tool_name: str
    execution: ExecutionResult
    preflight_decision: PreflightDecision
    var_emission: dict[str, Any]
    artifact_root: Path

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "tool_name": self.tool_name,
            "flow": [
                "agent",
                "MCP tool call",
                "Actenon proof gate",
                "tool executes/refuses",
                "VAR emitted",
            ],
            "preflight": self.preflight_decision.to_dict(),
            "artifact_root": str(self.artifact_root),
            "var": self.var_emission,
        }
        if self.execution.payload is not None:
            payload["protected_response"] = self.execution.payload
        if self.execution.receipt is not None:
            payload["receipt"] = self.execution.receipt.to_dict()
        if self.execution.refusal is not None:
            payload["refusal"] = self.execution.refusal.to_dict()
        return payload


def supported_tool_names() -> tuple[str, ...]:
    return tuple(TOOL_SPECS)


def build_request_id(prefix: str = "mcp") -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


def _tool_slug(tool_name: str) -> str:
    return tool_name.replace(".", "_").replace(":", "_").replace("/", "_")


def _spec_for(tool_name: str) -> ConsequentialToolSpec:
    try:
        return TOOL_SPECS[tool_name]
    except KeyError as exc:
        raise ValueError(f"unsupported MCP tool: {tool_name}") from exc


def _intent_for(tool_name: str, *, scenario: str) -> ActionIntent:
    spec = _spec_for(tool_name)
    if scenario == "allow":
        target_id = spec.allowed_target
        parameters = spec.allowed_parameters
    elif scenario == "refuse":
        target_id = spec.refused_target
        parameters = spec.refused_parameters
    else:
        raise ValueError("scenario must be 'allow' or 'refuse'")
    environment = str(parameters.get("environment", "unknown"))
    return ActionIntent(
        intent_id=f"intent_mcp_{_tool_slug(tool_name)}_{scenario}",
        issued_at=DEMO_NOW,
        expires_at=DEMO_NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_mcp_demo"),
        requester=PartyRef(type="agent", id="mcp-agent"),
        action=ActionSpec(
            name=tool_name,
            capability=spec.capability,
            parameters=dict(parameters),
        ),
        target=TargetRef(
            resource_type=spec.resource_type,
            resource_id=target_id,
            selectors={"environment": environment},
        ),
        justification=f"Local MCP hero path demo for {tool_name}.",
        context={"environment": environment},
    )


def _context_for(intent: ActionIntent, *, request_id: str) -> DynamicContextInput:
    return DynamicContextInput(
        request_id=request_id,
        audience=MCP_AUDIENCE,
        scope_capabilities=(intent.action.capability,),
        now=DEMO_NOW,
        facts={"mcp_tool": intent.action.name, "environment": intent.context.get("environment")},
        parameter_constraints=dict(intent.action.parameters),
        resource_selectors=(intent.target.selectors,),
    )


def build_demo_tool_call(tool_name: str, *, scenario: str = "allow", request_id: str | None = None) -> DemoToolCall:
    intent = _intent_for(tool_name, scenario=scenario)
    context = _context_for(intent, request_id=request_id or f"req_demo_{_tool_slug(tool_name)}_{scenario}")
    signer = build_local_proof_signer()
    pccb = PCCBMinter(
        signer=signer,
        issuer=PartyRef(type="service", id="actenon-local-mcp-demo"),
        pccb_id_factory=lambda: f"pccb_{context.request_id}",
        nonce_factory=lambda: f"nonce-{context.request_id}",
    ).mint(
        intent,
        PolicyDecision(
            outcome="allow",
            summary="Demo proof minted for the MCP tool gate.",
            rule_evaluations=(),
            reason_codes=("MCP_DEMO_PROOF_MINTED",),
        ),
        context,
    )
    return DemoToolCall(tool_name=tool_name, intent=intent, pccb=pccb, preflight_evidence={})


def _coerce_mapping(raw: Mapping[str, Any] | str | None, *, field_name: str) -> dict[str, Any] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        if not raw.strip():
            return None
        parsed = json.loads(raw)
    else:
        parsed = raw
    if not isinstance(parsed, Mapping):
        raise ContractValidationError(f"{field_name} must be a JSON object.")
    return dict(parsed)


def _policy_from_preflight(decision: PreflightDecision) -> PolicyDecision:
    outcome = {
        "allow": "allow",
        "deny": "deny",
        "approval_required": "approval-required",
        "needs_evidence": "needs-evidence",
    }[decision.outcome]
    evaluations = tuple(
        RuleEvaluation(
            rule_id=rule_id,
            outcome=outcome,
            reason_code=decision.reason_code,
            summary=decision.summary,
            required_evidence=tuple(decision.required_evidence),
            approver_types=tuple(decision.required_approvals),
        )
        for rule_id in (decision.matched_rules or ("mcp.preflight",))
    )
    return PolicyDecision(
        outcome=outcome,
        summary=decision.summary,
        rule_evaluations=evaluations,
        reason_codes=(decision.reason_code,),
        required_evidence=tuple(decision.required_evidence),
        approver_types=tuple(decision.required_approvals),
    )


def _tool_binding_policy(tool_name: str, intent: ActionIntent) -> PolicyDecision | None:
    spec = _spec_for(tool_name)
    if intent.action.name == tool_name and intent.action.capability == spec.capability:
        return None
    summary = "The Action Intent is not bound to this MCP tool handler."
    return PolicyDecision(
        outcome="deny",
        summary=summary,
        rule_evaluations=(
            RuleEvaluation(
                rule_id="mcp.tool_binding",
                outcome="deny",
                reason_code="MCP_TOOL_INTENT_MISMATCH",
                summary=summary,
                details={
                    "expected_tool": tool_name,
                    "expected_capability": spec.capability,
                    "observed_tool": intent.action.name,
                    "observed_capability": intent.action.capability,
                },
            ),
        ),
        reason_codes=("MCP_TOOL_INTENT_MISMATCH",),
    )


def _outcome_writer(example_root: Path) -> CompositeOutcomeWriter:
    memory_writer = InMemoryOutcomeWriter()
    artifact_writer = JsonArtifactOutcomeWriter(example_root / "artifacts" / "outcomes")
    return CompositeOutcomeWriter(memory_writer, artifact_writer)


def _receipt_factory(request_id: str) -> ReceiptFactory:
    return ReceiptFactory(receipt_id_factory=lambda: f"rcpt_{request_id}")


def _refusal_factory(request_id: str) -> RefusalFactory:
    return RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}")


def _execute_simulated_side_effect(
    tool_name: str,
    request: ProtectedExecutionRequest,
    credential: BrokeredCredential,
) -> dict[str, Any]:
    target = request.intent.target.resource_id
    return {
        "external_reference": f"{_tool_slug(tool_name)}:{target}",
        "mcp_tool": tool_name,
        "capability": request.intent.action.capability,
        "simulated_side_effect": {
            "state": "completed",
            "target": target,
            "parameters": request.intent.action.parameters,
        },
        "credential_reference": credential.secret_reference,
        "credential_material_exposed": False,
    }


def _write_var_emission(
    *,
    example_root: Path,
    tool_name: str,
    intent: ActionIntent,
    receipt: Receipt,
    refusal: Refusal | None,
) -> dict[str, Any]:
    var_root = example_root / "artifacts" / "var"
    var_root.mkdir(parents=True, exist_ok=True)
    artifact_kind = "receipt"
    artifact_id = receipt.receipt_id
    var_emission = {
        "kind": "actenon.local.var_emission",
        "standard_surface": "VAR",
        "standard_surface_name": "Verifiable Action Receipt",
        "emitted_at": format_timestamp(receipt.occurred_at),
        "tool_name": tool_name,
        "capability": intent.action.capability,
        "outcome": receipt.outcome,
        "artifact_kind": artifact_kind,
        "artifact_id": artifact_id,
        "receipt_id": receipt.receipt_id,
        "refusal_id": refusal.refusal_id if refusal is not None else None,
        "local_artifact_paths": {
            "receipt": str(example_root / "artifacts" / "outcomes" / "receipts" / f"{receipt.receipt_id}.json"),
            "refusal": str(example_root / "artifacts" / "outcomes" / "refusals" / f"{refusal.refusal_id}.json")
            if refusal is not None
            else None,
        },
        "hosted_dependency": False,
        "cloud_dependency": False,
        "note": "In this local example, the emitted VAR surface is the canonical Receipt; a Refusal is linked when execution is blocked.",
    }
    path = var_root / f"{receipt.receipt_id}.json"
    path.write_text(json.dumps(var_emission, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {**var_emission, "path": str(path)}


def _refuse_without_pccb(
    *,
    tool_name: str,
    intent: ActionIntent,
    context: DynamicContextInput,
    preflight_decision: PreflightDecision,
    request_id: str,
    example_root: Path,
    exc: RefusalException,
) -> ProtectedMCPToolOutcome:
    writer = _outcome_writer(example_root)
    refusal = _refusal_factory(request_id).create_from_exception(
        exc,
        occurred_at=context.now,
        intent=intent,
        context=context,
    )
    receipt = _receipt_factory(request_id).create_refused_receipt(intent, context, refusal)
    writer.write_refusal(refusal)
    writer.write_receipt(receipt)
    var_emission = _write_var_emission(
        example_root=example_root,
        tool_name=tool_name,
        intent=intent,
        receipt=receipt,
        refusal=refusal,
    )
    return ProtectedMCPToolOutcome(
        ok=False,
        tool_name=tool_name,
        execution=ExecutionResult(receipt=receipt, refusal=refusal, payload=None),
        preflight_decision=preflight_decision,
        var_emission=var_emission,
        artifact_root=example_root / "artifacts",
    )


def invoke_protected_tool(
    tool_name: str,
    *,
    intent_payload: Mapping[str, Any] | str | None = None,
    pccb_payload: Mapping[str, Any] | str | None = None,
    preflight_evidence: Mapping[str, Any] | str | None = None,
    request_id: str | None = None,
    example_root: Path = EXAMPLE_ROOT,
) -> ProtectedMCPToolOutcome:
    """Run one MCP tool call through the local Actenon proof gate."""

    _spec_for(tool_name)
    resolved_request_id = request_id or build_request_id(f"mcp_{_tool_slug(tool_name)}")

    if intent_payload is None and pccb_payload is None:
        demo_call = build_demo_tool_call(tool_name, scenario="allow", request_id=resolved_request_id)
        intent = demo_call.intent
        pccb = demo_call.pccb
        evidence = dict(demo_call.preflight_evidence)
    else:
        intent_raw = _coerce_mapping(intent_payload, field_name="intent_json")
        if intent_raw is None:
            raise ContractValidationError("intent_json is required when pccb_json is supplied.")
        try:
            intent = ActionIntent.from_dict(intent_raw)
        except ValueError as exc:
            raise ContractValidationError(str(exc)) from exc
        pccb_raw = _coerce_mapping(pccb_payload, field_name="pccb_json")
        try:
            pccb = PCCB.from_dict(pccb_raw) if pccb_raw is not None else None
        except ValueError as exc:
            raise ContractValidationError(str(exc)) from exc
        evidence = _coerce_mapping(preflight_evidence, field_name="preflight_evidence_json") or {}

    context = _context_for(intent, request_id=resolved_request_id)
    preflight_decision = PreflightEngine().check(intent, evidence_context=evidence)
    binding_policy = _tool_binding_policy(tool_name, intent)
    policy_decision = binding_policy or _policy_from_preflight(preflight_decision)

    if pccb is None:
        return _refuse_without_pccb(
            tool_name=tool_name,
            intent=intent,
            context=context,
            preflight_decision=preflight_decision,
            request_id=resolved_request_id,
            example_root=example_root,
            exc=ProofVerificationError("PCCB_REQUIRED", "The MCP tool call did not include a proof credential block."),
        )

    request = ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)
    broker = InMemoryCredentialBroker(
        ttl=timedelta(seconds=60),
        credential_id_factory=lambda: f"cred_{resolved_request_id}",
        secret_reference_prefix="memory://mcp-tool-credential",
    )
    executor = ProtectedExecutor(
        proof_verifier=PCCBVerifier(build_local_proof_signer()),
        credential_broker=broker,
        replay_protector=ReplayProtector(SqliteReplayStore(example_root / "state" / "replay.sqlite3")),
        receipt_factory=_receipt_factory(resolved_request_id),
        refusal_factory=_refusal_factory(resolved_request_id),
        outcome_writer=_outcome_writer(example_root),
    )
    execution = executor.execute(
        request,
        lambda protected_request, credential: _execute_simulated_side_effect(tool_name, protected_request, credential),
        policy_decision=policy_decision,
    )
    if execution.receipt is None:
        raise RuntimeError("protected executor returned no receipt")
    var_emission = _write_var_emission(
        example_root=example_root,
        tool_name=tool_name,
        intent=intent,
        receipt=execution.receipt,
        refusal=execution.refusal,
    )
    return ProtectedMCPToolOutcome(
        ok=execution.refusal is None,
        tool_name=tool_name,
        execution=execution,
        preflight_decision=preflight_decision,
        var_emission=var_emission,
        artifact_root=example_root / "artifacts",
    )
