from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from actenon.api import ActionIntentIntakeService, compute_invoice_payment_batch_hash
from actenon.core import ProtectedExecutionKernel
from actenon.core.errors import ContractValidationError
from actenon.core.json import loads_no_duplicate_keys
from actenon.escrow import build_sqlite_capability_escrow
from actenon.local_runtime import bootstrap_local_runtime, resolve_local_runtime_paths
from actenon.models import AudienceRef, PartyRef, PolicyDecision, RuleEvaluation, build_intent_record
from actenon.models.contracts import ActionIntent, format_timestamp, parse_timestamp
from actenon.models.runtime import DynamicContextInput
from actenon.policy import build_invoice_payment_policy_engine, build_refund_policy_engine
from actenon.preflight import PreflightEngine
from actenon.proof import LOCAL_PROOF_KEY_ID, PCCBMinter, PCCBVerifier, VerifierDisclosureMode, build_local_proof_signer
from actenon.proof.signers.well_known import WELL_KNOWN_KEYS_PATH
from actenon.receipts import (
    JsonArtifactOutcomeWriter,
    JsonArtifactReceiptStore,
    JsonArtifactRefusalStore,
    ReceiptFactory,
    RefusalFactory,
)
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.ui.trace_viewer.app import TraceViewerHandler
from actenon.verifier import ProtectedEndpointMiddleware


LEGACY_WELL_KNOWN_KEYS_PATH = "/.well-known/actenon-keys.json"


@dataclass(frozen=True)
class LocalRuntimeServerPaths:
    root: Path
    artifacts_root: Path
    requests_root: Path
    outcomes_root: Path
    state_root: Path
    service_manifest_path: Path
    replay_db_path: Path
    escrow_db_path: Path
    key_discovery_path: Path


@dataclass(frozen=True)
class LocalRuntimeStartupInfo:
    runtime_root: str
    issuer_url: str
    intents_url: str
    preflight_url: str
    health_url: str
    issuer: dict[str, Any]
    supported_capabilities: tuple[str, ...]
    key_discovery_url: str
    key_discovery_alias_url: str
    key_discovery_available: bool
    key_discovery_summary: str
    key_discovery_document_path: str
    trace_viewer_url: str | None
    trace_viewer_status: str
    artifact_dir: str
    replay_store_path: str
    escrow_store_path: str
    next_step_example: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_root": self.runtime_root,
            "issuer_url": self.issuer_url,
            "intents_url": self.intents_url,
            "preflight_url": self.preflight_url,
            "health_url": self.health_url,
            "issuer": self.issuer,
            "supported_capabilities": list(self.supported_capabilities),
            "key_discovery_url": self.key_discovery_url,
            "key_discovery_alias_url": self.key_discovery_alias_url,
            "key_discovery_available": self.key_discovery_available,
            "key_discovery_summary": self.key_discovery_summary,
            "key_discovery_document_path": self.key_discovery_document_path,
            "trace_viewer_url": self.trace_viewer_url,
            "trace_viewer_status": self.trace_viewer_status,
            "artifact_dir": self.artifact_dir,
            "replay_store_path": self.replay_store_path,
            "escrow_store_path": self.escrow_store_path,
            "next_step_example": self.next_step_example,
        }


@dataclass
class ManagedHttpServer:
    server: ThreadingHTTPServer
    thread: threading.Thread
    url: str

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@dataclass
class LocalRuntimeServerSession:
    runtime_server: ManagedHttpServer
    startup_info: LocalRuntimeStartupInfo
    trace_viewer_server: ManagedHttpServer | None = None

    def close(self) -> None:
        if self.trace_viewer_server is not None:
            self.trace_viewer_server.close()
        self.runtime_server.close()


@dataclass
class LocalRuntimePolicyRouter:
    refund_engine: Any
    invoice_payment_engine: Any

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> PolicyDecision:
        capability = intent.action.capability
        if capability == "refund.execute":
            return self.refund_engine.evaluate(intent, context)
        if capability == "invoice_payment.execute":
            return self.invoice_payment_engine.evaluate(intent, context)
        evaluation = RuleEvaluation(
            rule_id="runtime.unsupported_capability",
            outcome="deny",
            reason_code="UNSUPPORTED_CAPABILITY",
            summary="The local runtime does not expose an issuer route for this capability.",
            details={"capability": capability},
        )
        return PolicyDecision(
            outcome="deny",
            summary=evaluation.summary,
            rule_evaluations=(evaluation,),
            reason_codes=(evaluation.reason_code,),
        )


def resolve_local_runtime_server_paths(runtime_dir: str | Path | None = None) -> LocalRuntimeServerPaths:
    runtime_paths = resolve_local_runtime_paths(runtime_dir)
    return LocalRuntimeServerPaths(
        root=runtime_paths.root,
        artifacts_root=runtime_paths.runtime_artifacts_root,
        requests_root=runtime_paths.runtime_requests_root,
        outcomes_root=runtime_paths.runtime_outcomes_root,
        state_root=runtime_paths.runtime_state_root,
        service_manifest_path=runtime_paths.runtime_service_manifest_path,
        replay_db_path=runtime_paths.runtime_state_root / "replay.sqlite3",
        escrow_db_path=runtime_paths.runtime_state_root / "escrow.sqlite3",
        key_discovery_path=runtime_paths.keys_root / "actenon-keys.json",
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _runtime_issuer() -> PartyRef:
    return PartyRef(type="service", id="actenon_local_runtime", display_name="Actenon Local Runtime")


def _runtime_supported_capabilities() -> tuple[str, ...]:
    return ("refund.execute", "invoice_payment.execute")


def _safe_segment(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value)
    return cleaned[:96] or "request"


def _merge_mapping(base: dict[str, Any], override: Mapping[str, Any] | None) -> dict[str, Any]:
    if override is None:
        return dict(base)
    merged = dict(base)
    merged.update(dict(override))
    return merged


def _parse_audience(raw: Any, *, default: AudienceRef) -> AudienceRef:
    if raw is None:
        return default
    if isinstance(raw, str):
        if ":" in raw:
            audience_type, audience_id = raw.split(":", 1)
        else:
            audience_type, audience_id = default.type, raw
        return AudienceRef(type=audience_type, id=audience_id)
    if isinstance(raw, Mapping):
        return AudienceRef.from_dict(raw, "context.audience")
    raise ContractValidationError("context.audience must be a string or audience object")


def _parse_context_now(raw: Any) -> datetime:
    if raw is None:
        return _utc_now()
    if not isinstance(raw, str):
        raise ContractValidationError("context.now must be an RFC3339 string")
    return parse_timestamp(raw, "context.now")


def _parse_resource_selectors(raw: Any, *, default: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    if raw is None:
        return default
    if not isinstance(raw, list) or any(not isinstance(item, Mapping) for item in raw):
        raise ContractValidationError("context.resource_selectors must be a list of objects")
    return tuple(dict(item) for item in raw)


def _parse_string_tuple(raw: Any, *, default: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    if raw is None:
        return default
    if not isinstance(raw, list):
        raise ContractValidationError(f"{field_name} must be a list of strings")
    values = tuple(str(item) for item in raw)
    return values


def _load_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = loads_no_duplicate_keys(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_valid_key_discovery_document(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, None
    try:
        payload = loads_no_duplicate_keys(path.read_text(encoding="utf-8"))
    except ValueError:
        return None, "key-discovery publication file is not valid JSON"
    if not isinstance(payload, Mapping):
        return None, "key-discovery publication file must be a JSON object"
    if payload.get("format") == "actenon-local-hmac-key-v1":
        return None, "local HMAC key material must not be served as public key discovery"
    contract = payload.get("contract")
    if not isinstance(contract, Mapping):
        return None, "key-discovery publication file must declare a contract object"
    if contract.get("name") != "key_discovery" or contract.get("version") != "v1":
        return None, "key-discovery publication file must declare key_discovery v1"
    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys:
        return None, "key-discovery publication file must include at least one published verification key"
    return dict(payload), None


def _default_refund_facts(intent: ActionIntent, runtime_dir: str | Path | None) -> dict[str, Any]:
    payment_id = intent.target.resource_id
    state_path = resolve_local_runtime_paths(runtime_dir).local_proof_root / "state" / "protected_endpoint_state.json"
    state = _load_json_if_present(state_path) or {}
    payment = state.get("payments", {}).get(payment_id, {})
    risk_level = "normal"
    scenario = str(intent.context.get("demo_scenario") or intent.metadata.get("scenario") or "")
    if scenario == "deny":
        risk_level = "blocked"
    elif scenario == "approval_required":
        risk_level = "approval"
    elif scenario == "needs_evidence":
        risk_level = "review"
    return {
        "risk_level": risk_level,
        "scenario": scenario or None,
        "payment_id": payment_id,
        "payment_currency": payment.get("currency", intent.action.parameters.get("currency")),
        "remaining_refundable_minor": payment.get("remaining_refundable_minor", intent.action.parameters.get("amount_minor", 0)),
        "prohibited_actions": ("refund.currency_override", "refund.target_override"),
        "abort_conditions": (
            "remaining_refundable_minor_below_requested_amount",
            "payment_currency_mismatch",
        ),
        "blast_radius_limits": {
            "max_payment_targets": {
                "value": 1,
                "summary": "A single refund delegation may target only one payment resource.",
            },
            "max_amount_minor": {
                "value": intent.action.parameters.get("amount_minor"),
                "summary": "Do not exceed the delegated refund amount.",
                "unit": "minor_units",
            },
        },
    }


def _default_invoice_payment_facts(intent: ActionIntent, runtime_dir: str | Path | None) -> dict[str, Any]:
    params = intent.action.parameters
    payment_batch_id = str(params["payment_batch_id"])
    state_path = (
        resolve_local_runtime_paths(runtime_dir).invoice_payment_local_proof_root
        / "state"
        / "protected_endpoint_state.json"
    )
    state = _load_json_if_present(state_path) or {}
    invoices = state.get("invoices", {})
    payment_batches = state.get("payment_batches", {})
    duplicate_invoice_ids = sorted(
        invoice_id
        for invoice_id in params.get("invoice_ids", [])
        if invoices.get(invoice_id, {}).get("status") == "paid"
    )
    batch_record = payment_batches.get(payment_batch_id, {})
    scenario = str(intent.context.get("demo_scenario") or intent.metadata.get("scenario") or "")
    required_approval_chain: list[str] = []
    provided_approval_chain: list[str] = []
    required_approver_types: list[str] = []
    required_evidence_types: list[str] = []
    if scenario == "approval_missing":
        required_approval_chain = ["approver_manager", "approver_controller"]
        provided_approval_chain = ["approver_manager"]
        required_approver_types = ["finance-controller", "treasury-operator"]
    elif scenario == "evidence_missing":
        required_evidence_types = ["invoice_pdf", "supplier_statement"]
    return {
        "risk_level": "normal",
        "scenario": scenario or None,
        "expected_payer_entity_id": params["payer_entity_id"],
        "expected_supplier_id": params["supplier_id"],
        "expected_bank_account_reference": params["bank_account_reference"],
        "expected_invoice_ids": list(params["invoice_ids"]),
        "expected_amount_minor": params["amount_minor"],
        "expected_currency": params["currency"],
        "expected_payment_date": params["payment_date"],
        "expected_batch_hash": batch_record.get(
            "batch_hash",
            compute_invoice_payment_batch_hash(
                payer_entity_id=params["payer_entity_id"],
                supplier_id=params["supplier_id"],
                bank_account_reference=params["bank_account_reference"],
                invoice_ids=tuple(str(item) for item in params["invoice_ids"]),
                amount_minor=int(params["amount_minor"]),
                currency=str(params["currency"]),
                payment_date=str(params["payment_date"]),
                payment_batch_id=payment_batch_id,
            ),
        ),
        "duplicate_invoice_ids": duplicate_invoice_ids,
        "duplicate_payment_detected": bool(batch_record.get("payment_execution_ids")),
        "required_approval_chain": required_approval_chain,
        "provided_approval_chain": provided_approval_chain,
        "required_approver_types": required_approver_types,
        "required_evidence_types": required_evidence_types,
        "prohibited_actions": ("invoice_payment.payee_override", "invoice_payment.entity_override"),
        "abort_conditions": (
            "duplicate_invoice_detected",
            "bank_account_mismatch",
            "batch_hash_mismatch",
        ),
        "blast_radius_limits": {
            "max_invoice_count": {
                "value": len(params["invoice_ids"]),
                "summary": "A delegated payment batch may cover only the declared invoice set.",
            },
            "max_amount_minor": {
                "value": params["amount_minor"],
                "summary": "Do not exceed the delegated payment amount.",
                "unit": "minor_units",
            },
            "max_batch_targets": {
                "value": 1,
                "summary": "A single delegated payment may target only one payment batch.",
            },
        },
    }


def _default_parameter_constraints(intent: ActionIntent) -> dict[str, Any]:
    params = intent.action.parameters
    if intent.action.capability == "refund.execute":
        return {
            "exact_amount_minor": params.get("amount_minor"),
            "exact_currency": params.get("currency"),
            "target_resource_id": intent.target.resource_id,
        }
    if intent.action.capability == "invoice_payment.execute":
        return {
            "exact_payer_entity_id": params["payer_entity_id"],
            "exact_supplier_id": params["supplier_id"],
            "exact_bank_account_reference": params["bank_account_reference"],
            "exact_invoice_ids": list(params["invoice_ids"]),
            "exact_amount_minor": params["amount_minor"],
            "exact_currency": params["currency"],
            "exact_payment_date": params["payment_date"],
            "exact_payment_batch_id": params["payment_batch_id"],
            "exact_batch_hash": params["batch_hash"],
        }
    return {}


def _default_resource_selectors(intent: ActionIntent) -> tuple[dict[str, Any], ...]:
    return ({"resource_id": intent.target.resource_id},)


def _default_context_for_intent(intent: ActionIntent, runtime_dir: str | Path | None) -> DynamicContextInput:
    if intent.action.capability == "refund.execute":
        return DynamicContextInput(
            request_id=f"req_{uuid4().hex}",
            audience=AudienceRef(type="service", id="local-refund-endpoint"),
            scope_capabilities=("refund.execute",),
            now=_utc_now(),
            facts=_default_refund_facts(intent, runtime_dir),
            parameter_constraints=_default_parameter_constraints(intent),
            resource_selectors=_default_resource_selectors(intent),
        )
    if intent.action.capability == "invoice_payment.execute":
        return DynamicContextInput(
            request_id=f"req_{uuid4().hex}",
            audience=AudienceRef(type="service", id="local-invoice-payment-endpoint"),
            scope_capabilities=("invoice_payment.execute",),
            now=_utc_now(),
            facts=_default_invoice_payment_facts(intent, runtime_dir),
            parameter_constraints=_default_parameter_constraints(intent),
            resource_selectors=_default_resource_selectors(intent),
        )
    return DynamicContextInput(
        request_id=f"req_{uuid4().hex}",
        audience=AudienceRef(type="service", id="local-runtime-endpoint"),
        scope_capabilities=(intent.action.capability,),
        now=_utc_now(),
        parameter_constraints=_default_parameter_constraints(intent),
        resource_selectors=_default_resource_selectors(intent),
    )


def _context_from_raw(intent: ActionIntent, raw: Mapping[str, Any] | None, runtime_dir: str | Path | None) -> DynamicContextInput:
    default = _default_context_for_intent(intent, runtime_dir)
    raw = dict(raw or {})
    return DynamicContextInput(
        request_id=str(raw.get("request_id", default.request_id)),
        audience=_parse_audience(raw.get("audience"), default=default.audience),
        scope_capabilities=_parse_string_tuple(
            raw.get("scope_capabilities"),
            default=default.scope_capabilities,
            field_name="context.scope_capabilities",
        ),
        now=_parse_context_now(raw.get("now")) if raw.get("now") is not None else default.now,
        facts=_merge_mapping(default.facts, raw.get("facts") if isinstance(raw.get("facts"), Mapping) else None),
        parameter_constraints=_merge_mapping(
            default.parameter_constraints,
            raw.get("parameter_constraints") if isinstance(raw.get("parameter_constraints"), Mapping) else None,
        ),
        resource_selectors=_parse_resource_selectors(raw.get("resource_selectors"), default=default.resource_selectors),
        required_evidence_types=_parse_string_tuple(
            raw.get("required_evidence_types"),
            default=default.required_evidence_types,
            field_name="context.required_evidence_types",
        ),
        approver_types=_parse_string_tuple(
            raw.get("approver_types"),
            default=default.approver_types,
            field_name="context.approver_types",
        ),
        max_ttl_seconds=int(raw.get("max_ttl_seconds", default.max_ttl_seconds)),
    )


def _fallback_context(raw: Mapping[str, Any] | None) -> DynamicContextInput:
    raw = dict(raw or {})
    default_audience = AudienceRef(type="service", id="actenon-local-runtime")
    return DynamicContextInput(
        request_id=str(raw.get("request_id", f"req_{uuid4().hex}")),
        audience=_parse_audience(raw.get("audience"), default=default_audience),
        scope_capabilities=_parse_string_tuple(
            raw.get("scope_capabilities"),
            default=(),
            field_name="context.scope_capabilities",
        ),
        now=_parse_context_now(raw.get("now")) if raw.get("now") is not None else _utc_now(),
        facts=dict(raw.get("facts") or {}),
        parameter_constraints=dict(raw.get("parameter_constraints") or {}),
        resource_selectors=_parse_resource_selectors(raw.get("resource_selectors"), default=()),
        required_evidence_types=_parse_string_tuple(
            raw.get("required_evidence_types"),
            default=(),
            field_name="context.required_evidence_types",
        ),
        approver_types=_parse_string_tuple(
            raw.get("approver_types"),
            default=(),
            field_name="context.approver_types",
        ),
        max_ttl_seconds=int(raw.get("max_ttl_seconds", 900)),
    )


def _extract_request_payload(raw: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any] | None]:
    action_intent = raw.get("action_intent")
    if isinstance(action_intent, Mapping):
        context = raw.get("context")
        if context is not None and not isinstance(context, Mapping):
            raise ContractValidationError("context must be a JSON object when provided")
        return dict(action_intent), dict(context) if isinstance(context, Mapping) else None
    return dict(raw), None


def _decision_payload(decision: PolicyDecision | None) -> dict[str, Any] | None:
    if decision is None:
        return None
    return {
        "outcome": decision.outcome,
        "summary": decision.summary,
        "reason_codes": list(decision.reason_codes),
        "required_evidence": list(decision.required_evidence),
        "approver_types": list(decision.approver_types),
        "rule_evaluations": [
            {
                "rule_id": item.rule_id,
                "outcome": item.outcome,
                "reason_code": item.reason_code,
                "summary": item.summary,
                "details": item.details,
                "required_evidence": list(item.required_evidence),
                "approver_types": list(item.approver_types),
            }
            for item in decision.rule_evaluations
        ],
    }


class LocalProofRuntimeService:
    def __init__(self, runtime_dir: str | Path | None = None) -> None:
        self.runtime_dir = runtime_dir
        self.runtime_paths = resolve_local_runtime_paths(runtime_dir)
        self.paths = resolve_local_runtime_server_paths(runtime_dir)
        self.paths.requests_root.mkdir(parents=True, exist_ok=True)
        self.paths.outcomes_root.mkdir(parents=True, exist_ok=True)
        self.paths.state_root.mkdir(parents=True, exist_ok=True)

        self.intake = ActionIntentIntakeService()
        self.signer = build_local_proof_signer()
        self.receipt_store = JsonArtifactReceiptStore(self.paths.outcomes_root)
        self.refusal_store = JsonArtifactRefusalStore(self.paths.outcomes_root)
        self.receipt_factory = ReceiptFactory()
        self.refusal_factory = RefusalFactory()
        self.outcome_writer = JsonArtifactOutcomeWriter(self.paths.outcomes_root)
        self.escrow = build_sqlite_capability_escrow(self.paths.escrow_db_path)
        self.replay_store = SqliteReplayStore(self.paths.replay_db_path)
        self.policy_router = LocalRuntimePolicyRouter(
            refund_engine=build_refund_policy_engine(receipt_store=self.receipt_store),
            invoice_payment_engine=build_invoice_payment_policy_engine(receipt_store=self.receipt_store),
        )
        self.preflight_engine = PreflightEngine()
        self.kernel = ProtectedExecutionKernel(
            intake=self.intake,
            policy_engine=self.policy_router,
            pccb_minter=PCCBMinter(
                signer=self.signer,
                issuer=_runtime_issuer(),
            ),
            escrow=self.escrow,
            middleware=ProtectedEndpointMiddleware(
                proof_verifier=PCCBVerifier(self.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
                escrow=self.escrow,
                receipt_factory=self.receipt_factory,
                refusal_factory=self.refusal_factory,
                outcome_writer=self.outcome_writer,
                replay_protector=ReplayProtector(self.replay_store),
            ),
            receipt_factory=self.receipt_factory,
            refusal_factory=self.refusal_factory,
            outcome_writer=self.outcome_writer,
        )

    def key_discovery_status(self) -> tuple[bool, str]:
        payload, error = _load_valid_key_discovery_document(self.paths.key_discovery_path)
        if payload is not None:
            return True, "publishable key-discovery document is available from the local runtime keys directory."
        if error is not None:
            return False, f"{error}; fix {self.paths.key_discovery_path} before treating this runtime as publicly discoverable."
        return False, (
            "default local single-node HS256 mode does not publish public verification material; "
            f"place a publishable key_discovery document at {self.paths.key_discovery_path} to serve one."
        )

    def health_payload(self, *, base_url: str, trace_viewer_url: str | None) -> dict[str, Any]:
        key_available, key_summary = self.key_discovery_status()
        return {
            "ok": True,
            "issuer_url": base_url,
            "intents_url": f"{base_url}/v1/intents",
            "preflight_url": f"{base_url}/v1/preflight",
            "health_url": f"{base_url}/healthz",
            "issuer": _runtime_issuer().to_dict(),
            "supported_capabilities": list(_runtime_supported_capabilities()),
            "key_discovery_url": f"{base_url}{WELL_KNOWN_KEYS_PATH}",
            "key_discovery_alias_url": f"{base_url}{LEGACY_WELL_KNOWN_KEYS_PATH}",
            "key_discovery_available": key_available,
            "key_discovery_summary": key_summary,
            "key_discovery_document_path": str(self.paths.key_discovery_path),
            "trace_viewer_url": trace_viewer_url,
            "trace_viewer_status": "started" if trace_viewer_url is not None else "not started",
            "artifact_dir": str(self.paths.artifacts_root),
            "replay_store_path": str(self.paths.replay_db_path),
            "escrow_store_path": str(self.paths.escrow_db_path),
            "next_step_example": f"curl -s {base_url}/healthz",
            "trust_mode": {
                "type": "single-node-local-proof",
                "algorithm": "HS256",
                "key_id": LOCAL_PROOF_KEY_ID,
                "publishable": False,
            },
        }

    def key_discovery_response(self) -> tuple[int, dict[str, Any]]:
        payload, error = _load_valid_key_discovery_document(self.paths.key_discovery_path)
        if payload is not None:
            return HTTPStatus.OK, payload
        if error is not None:
            return HTTPStatus.CONFLICT, {
                "ok": False,
                "available": False,
                "reason_code": "KEY_DISCOVERY_INVALID",
                "summary": error,
                "canonical_path": WELL_KNOWN_KEYS_PATH,
                "legacy_path": LEGACY_WELL_KNOWN_KEYS_PATH,
                "publication_path": str(self.paths.key_discovery_path),
                "trust_mode": {
                    "type": "single-node-local-proof",
                    "algorithm": "HS256",
                    "key_id": LOCAL_PROOF_KEY_ID,
                    "publishable": False,
                },
            }
        return HTTPStatus.CONFLICT, {
            "ok": False,
            "available": False,
            "reason_code": "KEY_DISCOVERY_UNAVAILABLE",
            "summary": "Default local single-node HS256 mode does not publish public verification material.",
            "canonical_path": WELL_KNOWN_KEYS_PATH,
            "legacy_path": LEGACY_WELL_KNOWN_KEYS_PATH,
            "publication_path": str(self.paths.key_discovery_path),
            "trust_mode": {
                "type": "single-node-local-proof",
                "algorithm": "HS256",
                "key_id": LOCAL_PROOF_KEY_ID,
                "publishable": False,
            },
        }

    def preflight(self, raw_request: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        try:
            action_intent_payload, raw_context = _extract_request_payload(raw_request)
            evidence_context = dict(raw_request.get("evidence_context") or raw_request.get("evidence") or {})
            if raw_context is not None and isinstance(raw_context.get("facts"), Mapping):
                evidence_context = {**raw_context["facts"], **evidence_context}
            decision = self.preflight_engine.check(action_intent_payload, evidence_context=evidence_context)
        except (ContractValidationError, ValueError, TypeError) as exc:
            return HTTPStatus.BAD_REQUEST, {
                "ok": False,
                "reason_code": "PREFLIGHT_SCHEMA_INVALID",
                "summary": str(exc),
            }
        return HTTPStatus.OK, {
            "ok": True,
            "request_id": str(raw_request.get("request_id", "")),
            "decision": decision.to_dict(),
        }

    def submit_intent(self, raw_request: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        action_intent_payload, raw_context = _extract_request_payload(raw_request)
        parsed_intent: ActionIntent | None = None
        try:
            parsed_intent = self.intake.parse(action_intent_payload)
            context = _context_from_raw(parsed_intent, raw_context, self.runtime_dir)
        except ContractValidationError:
            context = _fallback_context(raw_context)

        admission = self.kernel.submit_intent(action_intent_payload, context)
        artifact_paths = self._write_request_artifacts(
            payload=action_intent_payload,
            context=context,
            admission=admission,
            parsed_intent=parsed_intent,
        )
        response = {
            "ok": admission.refusal is None,
            "request_id": context.request_id,
            "issuer": _runtime_issuer().to_dict(),
            "supported_capabilities": list(_runtime_supported_capabilities()),
            "decision": _decision_payload(admission.decision),
            "escrow_id": admission.escrow_id,
            "pccb": admission.pccb.to_dict() if admission.pccb is not None else None,
            "receipt": admission.receipt.to_dict() if admission.receipt is not None else None,
            "refusal": admission.refusal.to_dict() if admission.refusal is not None else None,
            "artifacts": artifact_paths,
        }
        status = HTTPStatus.BAD_REQUEST if admission.intent is None else HTTPStatus.OK
        return status, response

    def _write_request_artifacts(
        self,
        *,
        payload: Mapping[str, Any],
        context: DynamicContextInput,
        admission: Any,
        parsed_intent: ActionIntent | None,
    ) -> dict[str, str | None]:
        intent_id = parsed_intent.intent_id if parsed_intent is not None else "invalid_intent"
        request_dir = self.paths.requests_root / f"{_safe_segment(context.request_id)}_{_safe_segment(intent_id)}"
        request_dir.mkdir(parents=True, exist_ok=True)
        if parsed_intent is not None:
            (request_dir / "action_intent.json").write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        else:
            (request_dir / "request_payload.json").write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        (request_dir / "context.json").write_text(
            json.dumps(
                {
                    "request_id": context.request_id,
                    "audience": context.audience.to_dict(),
                    "scope_capabilities": list(context.scope_capabilities),
                    "now": format_timestamp(context.now),
                    "facts": context.facts,
                    "parameter_constraints": context.parameter_constraints,
                    "resource_selectors": list(context.resource_selectors),
                    "required_evidence_types": list(context.required_evidence_types),
                    "approver_types": list(context.approver_types),
                    "max_ttl_seconds": context.max_ttl_seconds,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        pccb_path = None
        if admission.pccb is not None:
            pccb_path = request_dir / "pccb.json"
            pccb_path.write_text(json.dumps(admission.pccb.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        intent_record_path = None
        if parsed_intent is not None and admission.decision is not None:
            intent_record = build_intent_record(
                source="local-runtime-issuer",
                intent=parsed_intent,
                context=context,
                decision=admission.decision,
                pccb_id=admission.pccb.pccb_id if admission.pccb is not None else None,
                receipt_id=admission.receipt.receipt_id if admission.receipt is not None else None,
                refusal_id=admission.refusal.refusal_id if admission.refusal is not None else None,
            )
            intent_record_path = request_dir / "intent_record.json"
            intent_record_path.write_text(
                json.dumps(intent_record.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if admission.receipt is not None:
            (request_dir / "receipt.json").write_text(
                json.dumps(admission.receipt.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if admission.refusal is not None:
            (request_dir / "refusal.json").write_text(
                json.dumps(admission.refusal.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return {
            "request_dir": str(request_dir),
            "action_intent": str(request_dir / "action_intent.json") if parsed_intent is not None else None,
            "context": str(request_dir / "context.json"),
            "intent_record": str(intent_record_path) if intent_record_path is not None else None,
            "pccb": str(pccb_path) if pccb_path is not None else None,
            "receipt": str(request_dir / "receipt.json") if admission.receipt is not None else None,
            "refusal": str(request_dir / "refusal.json") if admission.refusal is not None else None,
        }


def _start_server(server: ThreadingHTTPServer, *, name: str) -> ManagedHttpServer:
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    return ManagedHttpServer(server=server, thread=thread, url=url)


def _build_runtime_handler(
    *,
    service: LocalProofRuntimeService,
    trace_viewer_url_getter: callable,
) -> type[BaseHTTPRequestHandler]:
    class RuntimeHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send_json(
                    HTTPStatus.OK,
                    service.health_payload(
                        base_url=self._base_url(),
                        trace_viewer_url=trace_viewer_url_getter(),
                    ),
                )
                return
            if self.path in {WELL_KNOWN_KEYS_PATH, LEGACY_WELL_KNOWN_KEYS_PATH}:
                status, payload = service.key_discovery_response()
                self._send_json(status, payload)
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in {"/v1/intents", "/v1/preflight"}:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = self.rfile.read(length)
                payload = loads_no_duplicate_keys(body or b"{}")
            except ValueError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "ok": False,
                        "reason_code": "SCHEMA_INVALID",
                        "summary": "Request body must be valid JSON.",
                    },
                )
                return
            if not isinstance(payload, Mapping):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "ok": False,
                        "reason_code": "SCHEMA_INVALID",
                        "summary": "Request body must be a JSON object.",
                    },
                )
                return
            if self.path == "/v1/preflight":
                status, response = service.preflight(payload)
            else:
                status, response = service.submit_intent(payload)
            self._send_json(status, response)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _base_url(self) -> str:
            host = self.server.server_address[0]
            port = self.server.server_address[1]
            return f"http://{host}:{port}"

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return RuntimeHandler


def _start_trace_viewer(runtime_dir: str | Path | None, *, host: str, port: int, service_root: Path) -> ManagedHttpServer:
    runtime_paths = resolve_local_runtime_paths(runtime_dir)
    artifact_roots = (
        runtime_paths.local_proof_root.resolve(),
        runtime_paths.invoice_payment_local_proof_root.resolve(),
        runtime_paths.portable_proof_root.resolve(),
        runtime_paths.simulations_root.resolve(),
        service_root.resolve(),
    )
    repo_root = runtime_paths.root.resolve()
    handler = lambda *handler_args, **handler_kwargs: TraceViewerHandler(  # noqa: E731
        *handler_args,
        repo_root=repo_root,
        artifact_roots=artifact_roots,
        **handler_kwargs,
    )
    server = ThreadingHTTPServer((host, port), handler)
    return _start_server(server, name="actenon-trace-viewer")


def start_local_runtime_services(
    *,
    runtime_dir: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8787,
    enable_trace_viewer: bool = True,
    trace_viewer_port: int = 8421,
) -> LocalRuntimeServerSession:
    bootstrap_local_runtime(runtime_dir)
    service = LocalProofRuntimeService(runtime_dir)
    trace_viewer_server: ManagedHttpServer | None = None
    trace_viewer_status = "disabled by configuration" if not enable_trace_viewer else "not started"

    def trace_viewer_url() -> str | None:
        return trace_viewer_server.url if trace_viewer_server is not None else None

    runtime_server = ThreadingHTTPServer(
        (host, port),
        _build_runtime_handler(service=service, trace_viewer_url_getter=trace_viewer_url),
    )
    managed_runtime_server = _start_server(runtime_server, name="actenon-local-runtime")

    if enable_trace_viewer:
        try:
            trace_viewer_server = _start_trace_viewer(
                runtime_dir,
                host=host,
                port=trace_viewer_port,
                service_root=service.paths.artifacts_root,
            )
            trace_viewer_status = "started"
        except OSError as exc:
            trace_viewer_server = None
            trace_viewer_status = f"not started ({exc})"

    key_available, key_summary = service.key_discovery_status()
    startup_info = LocalRuntimeStartupInfo(
        runtime_root=str(resolve_local_runtime_paths(runtime_dir).root),
        issuer_url=managed_runtime_server.url,
        intents_url=f"{managed_runtime_server.url}/v1/intents",
        preflight_url=f"{managed_runtime_server.url}/v1/preflight",
        health_url=f"{managed_runtime_server.url}/healthz",
        issuer=_runtime_issuer().to_dict(),
        supported_capabilities=_runtime_supported_capabilities(),
        key_discovery_url=f"{managed_runtime_server.url}{WELL_KNOWN_KEYS_PATH}",
        key_discovery_alias_url=f"{managed_runtime_server.url}{LEGACY_WELL_KNOWN_KEYS_PATH}",
        key_discovery_available=key_available,
        key_discovery_summary=key_summary,
        key_discovery_document_path=str(service.paths.key_discovery_path),
        trace_viewer_url=trace_viewer_server.url if trace_viewer_server is not None else None,
        trace_viewer_status=trace_viewer_status,
        artifact_dir=str(service.paths.artifacts_root),
        replay_store_path=str(service.paths.replay_db_path),
        escrow_store_path=str(service.paths.escrow_db_path),
        next_step_example=f"curl -s {managed_runtime_server.url}/healthz",
    )
    _write_json(
        service.paths.service_manifest_path,
        {
            "format": "actenon-local-runtime-service-v1",
            "generated_at": format_timestamp(_utc_now()),
            "runtime": startup_info.to_dict(),
            "trace_viewer_enabled": trace_viewer_server is not None,
        },
    )
    return LocalRuntimeServerSession(
        runtime_server=managed_runtime_server,
        startup_info=startup_info,
        trace_viewer_server=trace_viewer_server,
    )
