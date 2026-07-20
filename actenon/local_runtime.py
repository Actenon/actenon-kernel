from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_bytes
from tempfile import TemporaryDirectory
from typing import Any

from actenon.api import ActionIntentIntakeService, build_invoice_payment_action_intent_payload
from actenon.core import ProtectedExecutionKernel, RefusalException
from actenon.core.json import loads_no_duplicate_keys
from actenon.demo.local_proof import run_invoice_payment_local_proof_demo, run_local_proof_demo
from actenon.demo.portable_local_proof import build_hello_world_action_intent_payload, FIXED_BASE_TIME
from actenon.evidence import (
    EvidenceQuery,
    EvidenceQueryService,
    EvidenceVerdict,
    JsonArtifactActionIntentStore,
    JsonArtifactPCCBStore,
)
from actenon.escrow import build_sqlite_capability_escrow
from actenon.credentials import InMemoryCredentialBroker
from actenon.models import ActionIntent, AudienceRef, DynamicContextInput, PCCB, PartyRef, PolicyDecision, Receipt, Refusal, RuleEvaluation
from actenon.models.contracts import CorrelationRef, format_timestamp, parse_timestamp
from actenon.models.intent_record import build_intent_record
from actenon.models.serialization import build_artifact_digest
from actenon.policy import (
    CapabilityScopeHardRule,
    HardRuleEngine,
    IntentChronologyHardRule,
    IntentTtlHardRule,
    PolicyEngine,
    TenantWorkflowRule,
    TenantWorkflowRuleLayer,
    build_invoice_payment_policy_engine,
)
from actenon.proof import LOCAL_PROOF_KEY_ID, PCCBMinter, PCCBVerifier, build_action_hash_input, build_local_proof_signer
from actenon.proof.canonical import sha256_hex
from actenon.preflight import PreflightDecision, PreflightEngine
from actenon.receipts import (
    JsonArtifactOutcomeWriter,
    JsonArtifactReceiptStore,
    JsonArtifactRefusalStore,
    ReceiptFactory,
    RefusalFactory,
)
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.scanner import scan_replay_harness
from actenon.verifier import ProtectedEndpointMiddleware, VerifierSDK
from examples.hello_world_protected_resource_python.protected_resource import HelloWorldProtectedResource


DEFAULT_LOCAL_RUNTIME_DIR = Path("artifacts") / "local_runtime"
LOCAL_RUNTIME_FORMAT = "actenon-local-runtime-v1"
LOCAL_RUNTIME_BUNDLE_FORMAT = "actenon-local-runtime-bundle-v1"
LOCAL_RUNTIME_BUNDLE_EXTENSION = ".actenon"
LOCAL_HMAC_KEY_FORMAT = "actenon-local-hmac-key-v1"
BUNDLE_FILE_HASH_CANONICALIZATION = "sha-256-bytes"
SIMULATION_SCENARIOS = (
    "valid-proof",
    "audience-mismatch",
    "action-hash-mismatch",
    "expired-proof",
    "replay-refused",
    "mcp-tool-proof-laundering",
    "iam-escalation",
    "data-export",
)
INCIDENT_SIMULATIONS = (
    "prod-delete",
    "replit",
    "openai-eggs",
    "amazon-kiro",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _write_json(target: Path, payload: Any) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json(target: Path) -> dict[str, Any]:
    payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON file must contain an object: {target}")
    return payload


def _ensure_removed(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _remove_dir_if_empty(path: Path) -> None:
    try:
        path.rmdir()
    except OSError:
        return


def _sha256_bytes_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file_hex(path: Path) -> str:
    return _sha256_bytes_hex(path.read_bytes())


def _migrate_legacy_runtime_layout(paths: LocalRuntimePaths) -> None:
    legacy_labs_root = paths.root / "lab"
    if legacy_labs_root.exists() and not paths.labs_root.exists():
        legacy_labs_root.rename(paths.labs_root)

    legacy_runtime_root = paths.root / "runtime_server"
    if not legacy_runtime_root.exists():
        return

    legacy_service_manifest = legacy_runtime_root / "service_manifest.json"
    if legacy_service_manifest.exists() and not paths.runtime_service_manifest_path.exists():
        paths.runtime_service_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_service_manifest.rename(paths.runtime_service_manifest_path)

    for name, destination in (
        ("requests", paths.runtime_requests_root),
        ("outcomes", paths.runtime_outcomes_root),
    ):
        source = legacy_runtime_root / name
        if source.exists() and not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            source.rename(destination)

    legacy_state_root = legacy_runtime_root / "state"
    if legacy_state_root.exists():
        paths.runtime_state_root.mkdir(parents=True, exist_ok=True)
        for child in sorted(legacy_state_root.iterdir()):
            target = paths.runtime_state_root / child.name
            if not target.exists():
                child.rename(target)
        _remove_dir_if_empty(legacy_state_root)

    _remove_dir_if_empty(legacy_runtime_root)


@dataclass(frozen=True)
class LocalRuntimePaths:
    root: Path
    labs_root: Path
    local_proof_root: Path
    invoice_payment_local_proof_root: Path
    portable_proof_root: Path
    runtime_artifacts_root: Path
    runtime_requests_root: Path
    runtime_outcomes_root: Path
    runtime_state_root: Path
    runtime_service_manifest_path: Path
    simulations_root: Path
    bundles_root: Path
    keys_root: Path
    runtime_manifest_path: Path
    runtime_summary_path: Path


@dataclass(frozen=True)
class LocalRuntimeStorage:
    runtime_root: Path
    artifacts_root: Path
    state_root: Path
    outcomes_root: Path
    replay_db_path: Path
    capability_escrow_db_path: Path
    intent_store: JsonArtifactActionIntentStore
    pccb_store: JsonArtifactPCCBStore
    receipt_store: JsonArtifactReceiptStore
    refusal_store: JsonArtifactRefusalStore
    evidence_query_service: EvidenceQueryService

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_root": str(self.runtime_root),
            "artifacts_root": str(self.artifacts_root),
            "state_root": str(self.state_root),
            "outcomes_root": str(self.outcomes_root),
            "replay_store": {
                "type": "sqlite",
                "path": str(self.replay_db_path),
            },
            "capability_escrow": {
                "type": "sqlite",
                "path": str(self.capability_escrow_db_path),
            },
            "receipt_store": {
                "type": "json-artifact-store",
                "root": str(self.outcomes_root),
                "receipts_dir": str(self.outcomes_root / "receipts"),
            },
            "refusal_store": {
                "type": "json-artifact-store",
                "root": str(self.outcomes_root),
                "refusals_dir": str(self.outcomes_root / "refusals"),
            },
            "evidence_query_source": {
                "type": "local-artifact-index",
                "intent_root": str(self.artifacts_root),
                "pccb_root": str(self.artifacts_root),
                "outcomes_root": str(self.outcomes_root),
            },
        }


@dataclass(frozen=True)
class RuntimeCheck:
    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
        }
        if self.remediation is not None:
            payload["remediation"] = self.remediation
        return payload


@dataclass(frozen=True)
class RuntimeDoctorReport:
    overall_status: str
    runtime_root: str
    mode: str
    checks: tuple[RuntimeCheck, ...]

    def summary_counts(self) -> dict[str, int]:
        ok_count = sum(1 for item in self.checks if item.status == "ok")
        fail_count = sum(1 for item in self.checks if item.status != "ok")
        return {"total": len(self.checks), "ok": ok_count, "fail": fail_count}

    def action_items(self) -> tuple[dict[str, str], ...]:
        return tuple(
            {"name": item.name, "remediation": item.remediation}
            for item in self.checks
            if item.status != "ok" and item.remediation is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "runtime_root": self.runtime_root,
            "mode": self.mode,
            "summary": self.summary_counts(),
            "action_items": list(self.action_items()),
            "checks": [item.to_dict() for item in self.checks],
        }


@dataclass(frozen=True)
class SimulationScenarioResult:
    name: str
    status: str
    summary: str
    artifact_dir: str
    title: str | None = None
    refusal_code: str | None = None
    receipt_id: str | None = None
    perspectives: tuple["SimulationPerspective", ...] = ()
    lesson: str | None = None
    summary_path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "artifact_dir": self.artifact_dir,
            "title": self.title,
            "reason_code": self.refusal_code,
            "receipt_id": self.receipt_id,
            "perspectives": [item.to_dict() for item in self.perspectives],
            "lesson": self.lesson,
            "summary_path": self.summary_path,
            "details": self.details,
        }
        return payload


@dataclass(frozen=True)
class SimulationPerspective:
    key: str
    basis: str
    status: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "basis": self.basis,
            "status": self.status,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class IncidentSimulationDefinition:
    name: str
    title: str
    inspired_by: str
    disclaimer: str
    primary_focus: str
    lesson: str


@dataclass(frozen=True)
class SimulationReport:
    scenario: str
    runtime_root: str
    succeeded: bool
    results: tuple[SimulationScenarioResult, ...]
    mode: str = "technical"
    framing_note: str | None = None
    takeaways: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "runtime_root": self.runtime_root,
            "succeeded": self.succeeded,
            "mode": self.mode,
            "framing_note": self.framing_note,
            "results": [item.to_dict() for item in self.results],
            "takeaways": list(self.takeaways),
        }


INCIDENT_DEFINITIONS: dict[str, IncidentSimulationDefinition] = {
    "prod-delete": IncidentSimulationDefinition(
        name="prod-delete",
        title="Production Destructive Action Pattern",
        inspired_by="Generic production destructive-action pattern. This is not a named factual incident report.",
        disclaimer="This simulation is source-disciplined pattern language: it shows a class of execution-gap failure without asserting facts about any named incident.",
        primary_focus="No receipt, no prod delete.",
        lesson="If the protected endpoint owns the credential and preflight requires approval, a production delete can stop before side effects instead of relying on agent discretion.",
    ),
    "replit": IncidentSimulationDefinition(
        name="replit",
        title="Replit-Style Destructive Drift",
        inspired_by="Pattern simulation for Replit-style database or developer-tool destructive drift. This is not a cited factual incident report.",
        disclaimer="This is category teaching aid and pattern language, not an exact forensic reconstruction of any single incident.",
        primary_focus="Action drift without execution-edge binding.",
        lesson="If the execution edge does not verify the exact bounded action, an agent can widen a safe change into a destructive one and still say it was following intent.",
    ),
    "openai-eggs": IncidentSimulationDefinition(
        name="openai-eggs",
        title="Unauthorized Purchase Boundary Pattern",
        inspired_by="Generic consumer-purchase agent execution pattern without a clear execution-edge confirmation boundary. This is not a named factual incident report.",
        disclaimer="This is category teaching aid and pattern language, not an exact forensic reconstruction of any single transaction.",
        primary_focus="Raw purchase requests need execution-edge admission, not just upstream trust.",
        lesson="A dangerous purchase flow needs exact merchant, amount, target, and approval state at the execution edge. A loose approval story is not enough.",
    ),
    "amazon-kiro": IncidentSimulationDefinition(
        name="amazon-kiro",
        title="Wrong-Environment Action Pattern",
        inspired_by="Generic wrong-environment operation pattern with broader execution reach than intended. This is not a named factual incident report.",
        disclaimer="This is category teaching aid and pattern language, not an exact forensic reconstruction of any single outage.",
        primary_focus="Wrong-endpoint execution when broad environment trust replaces audience binding.",
        lesson="Upstream intent is not enough if the execution edge does not verify who the proof is actually for. Audience binding stops the wrong environment from accepting the call.",
    ),
}


def resolve_local_runtime_paths(runtime_dir: str | Path | None = None) -> LocalRuntimePaths:
    root = Path(runtime_dir or DEFAULT_LOCAL_RUNTIME_DIR).resolve()
    return LocalRuntimePaths(
        root=root,
        labs_root=root / "labs",
        local_proof_root=root / "labs" / "local_proof",
        invoice_payment_local_proof_root=root / "labs" / "invoice_payment_local_proof",
        portable_proof_root=root / "labs" / "portable_local_proof",
        runtime_artifacts_root=root / "artifacts",
        runtime_requests_root=root / "artifacts" / "requests",
        runtime_outcomes_root=root / "artifacts" / "outcomes",
        runtime_state_root=root / "state",
        runtime_service_manifest_path=root / "service_manifest.json",
        simulations_root=root / "simulations",
        bundles_root=root / "bundles",
        keys_root=root / "keys",
        runtime_manifest_path=root / "runtime_manifest.json",
        runtime_summary_path=root / "SUMMARY.txt",
    )


def _build_storage_bundle(
    *,
    runtime_root: Path,
    artifacts_root: Path,
    state_root: Path,
    outcomes_root: Path,
) -> LocalRuntimeStorage:
    intent_store = JsonArtifactActionIntentStore(artifacts_root)
    pccb_store = JsonArtifactPCCBStore(artifacts_root)
    receipt_store = JsonArtifactReceiptStore(outcomes_root)
    refusal_store = JsonArtifactRefusalStore(outcomes_root)
    evidence_query_service = EvidenceQueryService(
        intent_store=intent_store,
        pccb_store=pccb_store,
        receipt_store=receipt_store,
        refusal_store=refusal_store,
    )
    return LocalRuntimeStorage(
        runtime_root=runtime_root,
        artifacts_root=artifacts_root,
        state_root=state_root,
        outcomes_root=outcomes_root,
        replay_db_path=state_root / "replay.sqlite3",
        capability_escrow_db_path=state_root / "escrow.sqlite3",
        intent_store=intent_store,
        pccb_store=pccb_store,
        receipt_store=receipt_store,
        refusal_store=refusal_store,
        evidence_query_service=evidence_query_service,
    )


def build_local_runtime_storage(runtime_dir: str | Path | None = None) -> LocalRuntimeStorage:
    paths = resolve_local_runtime_paths(runtime_dir)
    return _build_storage_bundle(
        runtime_root=paths.root,
        artifacts_root=paths.runtime_artifacts_root,
        state_root=paths.runtime_state_root,
        outcomes_root=paths.runtime_outcomes_root,
    )


def _build_local_proof_lab_storage(runtime_dir: str | Path | None = None) -> LocalRuntimeStorage:
    paths = resolve_local_runtime_paths(runtime_dir)
    return _build_storage_bundle(
        runtime_root=paths.root,
        artifacts_root=paths.local_proof_root,
        state_root=paths.local_proof_root / "state",
        outcomes_root=paths.local_proof_root / "outcomes",
    )


def bootstrap_local_runtime(runtime_dir: str | Path | None = None) -> dict[str, Any]:
    paths = resolve_local_runtime_paths(runtime_dir)
    paths.root.mkdir(parents=True, exist_ok=True)
    _migrate_legacy_runtime_layout(paths)
    paths.labs_root.mkdir(parents=True, exist_ok=True)
    paths.runtime_artifacts_root.mkdir(parents=True, exist_ok=True)
    paths.runtime_state_root.mkdir(parents=True, exist_ok=True)
    paths.simulations_root.mkdir(parents=True, exist_ok=True)
    paths.bundles_root.mkdir(parents=True, exist_ok=True)
    paths.keys_root.mkdir(parents=True, exist_ok=True)

    _ensure_removed(paths.local_proof_root)
    _ensure_removed(paths.invoice_payment_local_proof_root)
    _ensure_removed(paths.portable_proof_root)

    local_manifest = run_local_proof_demo(paths.local_proof_root)
    invoice_payment_manifest = run_invoice_payment_local_proof_demo(paths.invoice_payment_local_proof_root)
    portable_manifest = _bootstrap_portable_runtime(paths.portable_proof_root)
    runtime_storage = build_local_runtime_storage(paths.root)
    local_proof_storage = _build_local_proof_lab_storage(paths.root)

    manifest = {
        "format": LOCAL_RUNTIME_FORMAT,
        "generated_at": format_timestamp(_utc_now()),
        "runtime_root": str(paths.root),
        "trust_mode": {
            "type": "single-node-local-proof",
            "algorithm": "HS256",
            "key_id": LOCAL_PROOF_KEY_ID,
            "publishable": False,
        },
        "paths": {
            "labs_root": str(paths.labs_root),
            "local_proof": str(paths.local_proof_root),
            "invoice_payment_local_proof": str(paths.invoice_payment_local_proof_root),
            "portable_local_proof": str(paths.portable_proof_root),
            "runtime_artifacts": str(paths.runtime_artifacts_root),
            "runtime_state": str(paths.runtime_state_root),
            "runtime_service_manifest": str(paths.runtime_service_manifest_path),
            "simulations": str(paths.simulations_root),
            "bundles": str(paths.bundles_root),
            "keys": str(paths.keys_root),
        },
        "storage": runtime_storage.to_dict(),
        "labs": {
            "local_proof_manifest": str(paths.local_proof_root / "manifest.json"),
            "invoice_payment_local_proof_manifest": str(paths.invoice_payment_local_proof_root / "manifest.json"),
            "portable_local_proof_manifest": str(paths.portable_proof_root / "manifest.json"),
        },
        "commands": {
            "serve": "actenon up",
            "bootstrap_only": "actenon up --bootstrap-only",
            "doctor": "actenon doctor",
            "simulate": "actenon simulate --scenario all",
            "bundle_export": "actenon bundle export",
            "evidence_query": f"actenon evidence query --intent-id intent_allow --artifacts-dir {paths.local_proof_root}",
        },
        "manifests": {
            "local_proof": local_manifest,
            "invoice_payment_local_proof": invoice_payment_manifest,
            "portable_local_proof": portable_manifest,
        },
    }
    _write_json(paths.runtime_manifest_path, manifest)
    paths.runtime_summary_path.write_text(
        "\n".join(
            [
                "Actenon local single-node runtime is bootstrapped.",
                f"Runtime root: {paths.root}",
                f"Labs root: {paths.labs_root}",
                f"Refund proof lab: {paths.local_proof_root}",
                f"Invoice payment issuer lab: {paths.invoice_payment_local_proof_root}",
                f"Portable verifier lab: {paths.portable_proof_root}",
                f"Runtime artifacts: {paths.runtime_artifacts_root}",
                f"Runtime state: {paths.runtime_state_root}",
                f"Runtime service manifest: {paths.runtime_service_manifest_path}",
                f"Runtime replay store: {runtime_storage.replay_db_path}",
                f"Runtime capability escrow: {runtime_storage.capability_escrow_db_path}",
                f"Runtime receipt store: {runtime_storage.outcomes_root / 'receipts'}",
                f"Runtime refusal store: {runtime_storage.outcomes_root / 'refusals'}",
                f"Runtime evidence query source: {runtime_storage.artifacts_root}",
                f"Refund proof lab state: {local_proof_storage.state_root}",
                f"Refund proof lab receipts: {local_proof_storage.outcomes_root / 'receipts'}",
                f"Refund proof lab refusals: {local_proof_storage.outcomes_root / 'refusals'}",
                f"Simulations dir: {paths.simulations_root}",
                f"Bundle export dir: {paths.bundles_root}",
                f"Keys dir: {paths.keys_root}",
                "Start the local issuer/verifier HTTP surface with: actenon up",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def _bootstrap_portable_runtime(artifact_root: Path) -> dict[str, Any]:
    artifact_root.mkdir(parents=True, exist_ok=True)
    payload = build_hello_world_action_intent_payload()
    intake = ActionIntentIntakeService()
    intent = intake.parse(payload)
    context = DynamicContextInput(
        request_id="req_runtime_portable_001",
        audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
        scope_capabilities=("protected_resource.read",),
        now=FIXED_BASE_TIME,
        parameter_constraints={"exact_message": "portable hello world"},
        resource_selectors=({"resource_id": "hello_resource_demo_001"},),
    )
    pccb = PCCBMinter(
        signer=build_local_proof_signer(),
        issuer=PartyRef(type="service", id="portable_local_issuer", display_name="Portable Local Issuer"),
        pccb_id_factory=lambda: "pccb_runtime_portable_001",
        nonce_factory=lambda: "nonce-runtime-portable-00000001",
    ).mint(
        intent,
        decision=PolicyDecision(
            outcome="allow",
            summary="Local runtime portable proof mode allows the hello-world protected resource example.",
            rule_evaluations=(),
            reason_codes=("LOCAL_PROOF_ALLOW",),
        ),
        context=context,
    )
    sdk = VerifierSDK(build_local_proof_signer())
    verified = sdk.verify(intent=intent, pccb=pccb, context=context)
    response = HelloWorldProtectedResource().handle(verified)

    _write_json(artifact_root / "action_intent.json", payload)
    _write_json(artifact_root / "pccb.json", pccb.to_dict())
    _write_json(
        artifact_root / "verification_result.json",
        {
            "request_id": verified.context.request_id,
            "audience": verified.context.audience.to_dict(),
            "action_hash": verified.pccb.action_hash.to_dict(),
        },
    )
    _write_json(artifact_root / "protected_resource_response.json", response)

    manifest = {
        "artifact_root": str(artifact_root),
        "action_intent": str(artifact_root / "action_intent.json"),
        "pccb": str(artifact_root / "pccb.json"),
        "verification_result": str(artifact_root / "verification_result.json"),
        "protected_resource_response": str(artifact_root / "protected_resource_response.json"),
    }
    _write_json(artifact_root / "manifest.json", manifest)
    (artifact_root / "SUMMARY.txt").write_text(
        "\n".join(
            [
                "Portable local verifier lab completed successfully.",
                f"Artifact root: {artifact_root}",
                f"Intent id: {intent.intent_id}",
                f"PCCB id: {pccb.pccb_id}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def doctor_local_runtime(runtime_dir: str | Path | None = None, *, deep: bool = False) -> RuntimeDoctorReport:
    paths = resolve_local_runtime_paths(runtime_dir)
    checks: list[RuntimeCheck] = []
    runtime_storage = build_local_runtime_storage(paths.root)
    runtime_artifacts_root = paths.runtime_artifacts_root
    runtime_state_root = paths.runtime_state_root
    runtime_service_manifest_path = paths.runtime_service_manifest_path
    runtime_service_manifest = _load_json_if_present(runtime_service_manifest_path)

    checks.append(
        RuntimeCheck(
            name="python_runtime",
            status="ok" if sys.version_info >= (3, 9) else "fail",
            summary=f"Python {sys.version_info.major}.{sys.version_info.minor} detected.",
            details={"version": sys.version.split()[0]},
            remediation="Use Python 3.9 or newer for the supported local runtime." if sys.version_info < (3, 9) else None,
        )
    )

    try:
        with sqlite3.connect(":memory:") as connection:
            connection.execute("SELECT 1")
        checks.append(RuntimeCheck(name="sqlite", status="ok", summary="sqlite3 stdlib runtime is available."))
    except Exception as exc:  # pragma: no cover - depends on interpreter build
        checks.append(
            RuntimeCheck(
                name="sqlite",
                status="fail",
                summary="sqlite3 stdlib runtime is unavailable.",
                details={"error": str(exc)},
                remediation="Use a Python build with sqlite3 enabled.",
            )
        )

    try:
        signer = build_local_proof_signer()
        signature = signer.sign(b"actenon-doctor")
        signer_ok = signer.verify(b"actenon-doctor", signature)
        checks.append(
            RuntimeCheck(
                name="signer",
                status="ok" if signer_ok else "fail",
                summary="Local proof signer is configured and usable." if signer_ok else "Local proof signer failed its self-check.",
                details={"algorithm": signer.algorithm, "key_id": signer.key_id},
                remediation="Check the local proof signer implementation and trust-mode configuration." if not signer_ok else None,
            )
        )
    except Exception as exc:
        checks.append(
            RuntimeCheck(
                name="signer",
                status="fail",
                summary="Local proof signer could not be initialized.",
                details={"error": str(exc)},
                remediation="Inspect the local proof signer path and trust-mode setup.",
            )
        )

    manifest = _load_json_if_present(paths.runtime_manifest_path)
    checks.append(
        RuntimeCheck(
            name="runtime_manifest",
            status="ok" if manifest is not None else "fail",
            summary="Runtime manifest is present." if manifest is not None else "Runtime manifest is missing. Run `actenon up` first.",
            remediation="Run `actenon up` to prepare the local runtime." if manifest is None else None,
        )
    )

    local_lab_ok = False
    if deep:
        local_proof_storage = _build_local_proof_lab_storage(paths.root)
        local_manifest_path = paths.local_proof_root / "manifest.json"
        local_manifest = _load_json_if_present(local_manifest_path)
        local_receipts_dir = local_proof_storage.outcomes_root / "receipts"
        local_refusals_dir = local_proof_storage.outcomes_root / "refusals"
        local_replay_db = local_proof_storage.replay_db_path
        local_escrow_db = local_proof_storage.capability_escrow_db_path
        local_lab_ok = (
            local_manifest is not None
            and local_receipts_dir.is_dir()
            and local_refusals_dir.is_dir()
            and local_replay_db.exists()
            and local_escrow_db.exists()
        )
        checks.append(
            RuntimeCheck(
                name="local_proof_lab",
                status="ok" if local_lab_ok else "fail",
                summary="Local proof lab artifacts, refusal/receipt outputs, replay DB, and durable escrow DB are present."
                if local_lab_ok
                else "Local proof lab is incomplete. Run `actenon up` first.",
                remediation="Run `actenon up --bootstrap-only` or `actenon up` to rebuild the shipped proof labs." if not local_lab_ok else None,
            )
        )

        if local_lab_ok:
            try:
                receipt_count = len(runtime_storage.receipt_store.list_receipts())
                refusal_count = len(runtime_storage.refusal_store.list_refusals())
                checks.append(
                    RuntimeCheck(
                        name="local_runtime_storage",
                        status="ok",
                        summary="Durable local replay, escrow, receipt, refusal, and evidence-query storage is wired.",
                        details={
                            "replay_store": str(runtime_storage.replay_db_path),
                            "capability_escrow": str(runtime_storage.capability_escrow_db_path),
                            "receipt_count": receipt_count,
                            "refusal_count": refusal_count,
                            "evidence_query_root": str(runtime_storage.artifacts_root),
                        },
                    )
                )
            except Exception as exc:
                checks.append(
                    RuntimeCheck(
                        name="local_runtime_storage",
                        status="fail",
                        summary="Durable local runtime storage could not be inspected cleanly.",
                        details={"error": str(exc)},
                        remediation="Delete the local runtime directory and rebuild it with `actenon up` if the storage files are corrupted.",
                    )
                )

    runtime_replay_db = runtime_state_root / "replay.sqlite3"
    try:
        SqliteReplayStore(runtime_replay_db)
        with sqlite3.connect(str(runtime_replay_db), timeout=30.0) as connection:
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("SELECT COUNT(*) FROM action_consumption").fetchone()
        checks.append(
            RuntimeCheck(
                name="replay_store",
                status="ok",
                summary="Runtime replay store is accessible.",
                details={"path": str(runtime_replay_db)},
            )
        )
    except Exception as exc:
        checks.append(
            RuntimeCheck(
                name="replay_store",
                status="fail",
                summary="Runtime replay store is not accessible.",
                details={"path": str(runtime_replay_db), "error": str(exc)},
                remediation="Start the runtime with `actenon up` to initialize the durable replay store, or remove the runtime directory to rebuild it.",
            )
        )

    runtime_escrow_db = runtime_state_root / "escrow.sqlite3"
    try:
        build_sqlite_capability_escrow(runtime_escrow_db)
        with sqlite3.connect(str(runtime_escrow_db), timeout=30.0) as connection:
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("SELECT COUNT(*) FROM capability_escrow").fetchone()
        checks.append(
            RuntimeCheck(
                name="escrow_store",
                status="ok",
                summary="Runtime capability escrow is accessible.",
                details={"path": str(runtime_escrow_db)},
            )
        )
    except Exception as exc:
        checks.append(
            RuntimeCheck(
                name="escrow_store",
                status="fail",
                summary="Runtime capability escrow is not accessible.",
                details={"path": str(runtime_escrow_db), "error": str(exc)},
                remediation="Start the runtime with `actenon up` to initialize the durable escrow store, or remove the runtime directory to rebuild it.",
            )
        )

    try:
        runtime_artifacts_root.mkdir(parents=True, exist_ok=True)
        probe_path = runtime_artifacts_root / ".doctor-write-probe"
        probe_path.write_text("ok\n", encoding="utf-8")
        probe_path.unlink()
        checks.append(
            RuntimeCheck(
                name="artifact_directory",
                status="ok",
                summary="Runtime artifact directory is writable.",
                details={"path": str(runtime_artifacts_root)},
            )
        )
    except Exception as exc:
        checks.append(
            RuntimeCheck(
                name="artifact_directory",
                status="fail",
                summary="Runtime artifact directory is not writable.",
                details={"path": str(runtime_artifacts_root), "error": str(exc)},
                remediation="Check filesystem permissions for the runtime directory or choose a writable `--runtime-dir`.",
            )
        )

    if deep and local_lab_ok:
        try:
            scratch_root = runtime_artifacts_root / ".doctor-outcomes"
            _ensure_removed(scratch_root)
            writer = JsonArtifactOutcomeWriter(scratch_root)
            sample_intent = ActionIntentIntakeService().parse(_load_json(paths.local_proof_root / "scenarios" / "allow" / "action_intent.json"))
            sample_context = DynamicContextInput(
                request_id="doctor_outcome_writer",
                audience=AudienceRef(type="service", id="local-refund-endpoint"),
                scope_capabilities=(sample_intent.action.capability,),
                now=FIXED_BASE_TIME,
            )
            sample_receipt = Receipt(
                receipt_id="rcpt_doctor_writer",
                intent_id=sample_intent.intent_id,
                occurred_at=FIXED_BASE_TIME,
                outcome="deny",
                phase="decision",
                tenant=sample_intent.tenant,
                subject=sample_intent.requester,
                action=sample_intent.action,
                target=sample_intent.target,
                correlation=CorrelationRef(request_id=sample_context.request_id),
                summary="Doctor write probe receipt.",
                side_effects={"state": "none"},
            )
            sample_refusal = Refusal(
                refusal_id="rfsl_doctor_writer",
                intent_id=sample_intent.intent_id,
                category="runtime",
                reason_code="DOCTOR_PROBE",
                message="Doctor write probe refusal.",
                retryable=False,
                refused_at=FIXED_BASE_TIME,
                tenant=sample_intent.tenant,
                subject=sample_intent.requester,
                audience=sample_context.audience,
                action=sample_intent.action,
                target=sample_intent.target,
                correlation=CorrelationRef(request_id=sample_context.request_id),
            )
            writer.write_receipt(sample_receipt)
            writer.write_refusal(sample_refusal)
            checks.append(
                RuntimeCheck(
                    name="outcome_writer",
                    status="ok",
                    summary="Receipt and refusal writing works against a local scratch artifact root.",
                    details={"scratch_root": str(scratch_root)},
                )
            )
        except Exception as exc:
            checks.append(
                RuntimeCheck(
                    name="outcome_writer",
                    status="fail",
                    summary="Receipt and refusal writing did not complete cleanly.",
                    details={"error": str(exc)},
                    remediation="Check filesystem permissions for the runtime artifact root and inspect the JSON artifact writer configuration.",
                )
            )
        finally:
            _ensure_removed(runtime_artifacts_root / ".doctor-outcomes")

    if deep:
        portable_intent_path = paths.portable_proof_root / "action_intent.json"
        portable_pccb_path = paths.portable_proof_root / "pccb.json"
        portable_ok = portable_intent_path.exists() and portable_pccb_path.exists()
        checks.append(
            RuntimeCheck(
                name="portable_verifier_lab",
                status="ok" if portable_ok else "fail",
                summary="Portable verifier lab artifacts are present." if portable_ok else "Portable verifier lab is incomplete. Run `actenon up` first.",
                remediation="Run `actenon up --bootstrap-only` or `actenon up` to rebuild the portable verifier lab." if not portable_ok else None,
            )
        )

        if portable_ok:
            try:
                intent = ActionIntentIntakeService().parse(_load_json(portable_intent_path))
                pccb = PCCB.from_dict(_load_json(portable_pccb_path))
                sdk = VerifierSDK(build_local_proof_signer())
                verified = sdk.verify(
                    intent=intent,
                    pccb=pccb,
                    context=sdk.build_context(
                        request_id="doctor_portable_verify",
                        audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
                        now=pccb.issued_at,
                        scope_capabilities=pccb.scope.capabilities,
                        parameter_constraints=pccb.scope.parameter_constraints,
                        resource_selectors=pccb.scope.resource_selectors,
                    ),
                )
                checks.append(
                    RuntimeCheck(
                        name="portable_verification",
                        status="ok",
                        summary="Portable verifier path accepts the local runtime proof pair.",
                        details={"intent_id": verified.intent.intent_id, "pccb_id": verified.pccb.pccb_id},
                    )
                )
            except Exception as exc:
                checks.append(
                    RuntimeCheck(
                        name="portable_verification",
                        status="fail",
                        summary="Portable verifier path failed against the local runtime proof pair.",
                        details={"error": str(exc)},
                        remediation="Rebuild the runtime with `actenon up` and inspect the portable proof artifacts if this keeps failing.",
                    )
                )

        if local_lab_ok:
            try:
                result = local_proof_storage.evidence_query_service.query(EvidenceQuery(intent_id="intent_allow"))
                status = "ok" if result.verdict == EvidenceVerdict.VERIFIED_EXECUTION else "fail"
                checks.append(
                    RuntimeCheck(
                        name="evidence_query",
                        status=status,
                        summary="Local evidence query resolved the expected executed allow path."
                        if status == "ok"
                        else "Local evidence query did not resolve the expected executed allow path.",
                        details={"verdict": result.verdict.value, "receipt_id": result.receipt_id},
                    )
                )
            except Exception as exc:
                checks.append(
                    RuntimeCheck(
                        name="evidence_query",
                        status="fail",
                        summary="Local evidence query failed against the runtime artifact set.",
                        details={"error": str(exc)},
                        remediation="Check the receipt/refusal artifact roots under the local proof lab and rerun `actenon up` if they are incomplete.",
                    )
                )

    if runtime_service_manifest is None:
        checks.append(
            RuntimeCheck(
                name="runtime_server",
                status="fail",
                summary="Local proof server has not been started for this runtime directory.",
                details={"manifest": str(runtime_service_manifest_path)},
                remediation="Start the foreground runtime with `actenon up` so the local issuer HTTP surface is available.",
            )
        )
        checks.append(
            RuntimeCheck(
                name="key_discovery",
                status="fail",
                summary="Key discovery is not being served because the local runtime server is not running.",
                details={"manifest": str(runtime_service_manifest_path)},
                remediation="Start the runtime with `actenon up`; local HS256 mode will then serve an explicit unavailable response unless you add publishable key material.",
            )
        )
        checks.append(
            RuntimeCheck(
                name="trace_viewer",
                status="fail",
                summary="Trace viewer is not running because the local runtime session is not active.",
                details={"manifest": str(runtime_service_manifest_path)},
                remediation="Start the runtime with `actenon up` to launch the read-only local trace viewer, unless you intentionally disable it.",
            )
        )
    else:
        service_runtime = dict(runtime_service_manifest.get("runtime", {}))
        health_url = service_runtime.get("health_url")
        try:
            health_status, health_payload = _http_json_status(str(health_url))
            server_ok = health_status == 200 and bool(health_payload.get("ok"))
            checks.append(
                RuntimeCheck(
                    name="runtime_server",
                    status="ok" if server_ok else "fail",
                    summary="Local proof server is running." if server_ok else "Local proof server did not answer a healthy response.",
                    details={
                        "health_url": health_url,
                        "status_code": health_status,
                        "issuer_url": service_runtime.get("issuer_url"),
                    },
                    remediation="Start the runtime with `actenon up` and keep that process running." if not server_ok else None,
                )
            )
        except Exception as exc:
            checks.append(
                RuntimeCheck(
                    name="runtime_server",
                    status="fail",
                    summary="Local proof server is not reachable.",
                    details={"health_url": health_url, "error": str(exc)},
                    remediation="Start the runtime with `actenon up` and keep that process running.",
                )
            )

        key_url = service_runtime.get("key_discovery_url")
        try:
            key_status, key_payload = _http_json_status(str(key_url))
            key_ok = key_status in {200, 409}
            if key_status == 200:
                key_summary = "Key discovery is being served from the local runtime."
            else:
                key_summary = "Key discovery route is serving an explicit unavailable response in local HS256 mode."
            checks.append(
                RuntimeCheck(
                    name="key_discovery",
                    status="ok" if key_ok else "fail",
                    summary=key_summary if key_ok else "Key discovery route did not return a valid runtime response.",
                    details={
                        "url": key_url,
                        "status_code": key_status,
                        "available": key_payload.get("available", key_payload.get("key_discovery_available")),
                        "reason_code": key_payload.get("reason_code"),
                    },
                    remediation="If you expect publishable verifier keys, place `actenon-keys.json` under the runtime keys directory and keep the runtime serving." if not key_ok else None,
                )
            )
        except Exception as exc:
            checks.append(
                RuntimeCheck(
                    name="key_discovery",
                    status="fail",
                    summary="Key discovery route is not reachable.",
                    details={"url": key_url, "error": str(exc)},
                    remediation="Start the runtime with `actenon up`; add a publishable key-discovery document only if you need public verification material.",
                )
            )

        trace_url = service_runtime.get("trace_viewer_url")
        if trace_url:
            try:
                trace_status, trace_payload = _http_json_status(f"{trace_url}/api/runs")
                trace_ok = trace_status == 200 and isinstance(trace_payload.get("runs"), list)
                checks.append(
                    RuntimeCheck(
                        name="trace_viewer",
                        status="ok" if trace_ok else "fail",
                        summary="Trace viewer is reachable." if trace_ok else "Trace viewer did not answer a valid response.",
                        details={"url": trace_url, "status_code": trace_status},
                        remediation="Start the runtime without `--no-trace-viewer`, or inspect the trace viewer port if it failed to bind." if not trace_ok else None,
                    )
                )
            except Exception as exc:
                checks.append(
                    RuntimeCheck(
                        name="trace_viewer",
                        status="fail",
                        summary="Trace viewer is not reachable.",
                        details={"url": trace_url, "error": str(exc)},
                        remediation="Start the runtime without `--no-trace-viewer`, or inspect the trace viewer port if it failed to bind.",
                    )
                )
        else:
            checks.append(
                RuntimeCheck(
                    name="trace_viewer",
                    status="ok",
                    summary="Trace viewer is not configured for this runtime session.",
                    details={},
                )
            )

    if deep:
        try:
            report = scan_replay_harness()
            checks.append(
                RuntimeCheck(
                    name="scanner_harness",
                    status="ok" if report.overall_status == "NO_OBVIOUS_EXECUTION_GAP_FOUND" else "fail",
                    summary="Execution-gap scanner harness passed."
                    if report.overall_status == "NO_OBVIOUS_EXECUTION_GAP_FOUND"
                    else "Execution-gap scanner harness reported a boundary issue.",
                    details={"status": report.overall_status},
                )
            )
        except Exception as exc:
            checks.append(
                RuntimeCheck(
                        name="scanner_harness",
                        status="fail",
                        summary="Execution-gap scanner harness could not be run.",
                        details={"error": str(exc)},
                        remediation="Inspect the scanner harness implementation and the local Python environment.",
                    )
                )

    overall_status = "ready" if all(item.status == "ok" for item in checks) else "needs_attention"
    return RuntimeDoctorReport(
        overall_status=overall_status,
        runtime_root=str(paths.root),
        mode="deep" if deep else "fast",
        checks=tuple(checks),
    )


def _simulation_status_is_success(status: str) -> bool:
    return status in {"verified", "refused", "approval-required", "needs-evidence"}


def _build_incident_takeaways(selected: tuple[str, ...]) -> tuple[str, ...]:
    incident_names = {INCIDENT_DEFINITIONS[item].title for item in selected if item in INCIDENT_DEFINITIONS}
    takeaways = [
        "Incident simulations are educational pattern reconstructions. They teach the boundary, not a private forensic timeline.",
        "Weak controls fail when a dangerous request reaches the side effect path without execution-edge verification of the exact action, audience, and target.",
        "Proof helps only when the execution edge actually verifies it. Upstream approval state without execution-edge enforcement is still weak control.",
        "Proof alone is not the whole story: replay defense and other runtime checks still live at the protected endpoint.",
        "Bounded Action Intent changes the outcome by constraining what may execute, where it may execute, and what artifacts prove the result afterward.",
    ]
    if incident_names:
        takeaways.append("Incidents covered: " + ", ".join(sorted(incident_names)) + ".")
    return tuple(takeaways)


def _trace_viewer_follow_up(paths: LocalRuntimePaths, *, label: str, scenario_dir: Path) -> dict[str, Any]:
    runtime_service_manifest = _load_json_if_present(paths.runtime_service_manifest_path) or {}
    runtime_payload = runtime_service_manifest.get("runtime")
    trace_viewer_url = runtime_payload.get("trace_viewer_url") if isinstance(runtime_payload, dict) else None
    if trace_viewer_url:
        return {
            "available": True,
            "url": trace_viewer_url,
            "summary": "Refresh the local trace viewer and open the Incident Simulator run to inspect the persisted incident artifacts.",
            "artifact_dir": str(scenario_dir),
            "run_title": "Incident Simulator",
            "scenario_label": label,
        }
    return {
        "available": False,
        "url": None,
        "summary": "Start `actenon up` if you want a local trace viewer after the simulation finishes.",
        "artifact_dir": str(scenario_dir),
        "run_title": "Incident Simulator",
        "scenario_label": label,
    }


def _build_generic_action_intent_payload(
    *,
    intent_id: str,
    issued_at: datetime,
    action_name: str,
    capability: str,
    target_resource_type: str,
    target_resource_id: str,
    parameters: dict[str, Any],
    constraints: dict[str, Any],
    justification: str,
) -> dict[str, Any]:
    return {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": intent_id,
        "issued_at": format_timestamp(issued_at),
        "expires_at": format_timestamp(issued_at + timedelta(minutes=5)),
        "tenant": {"tenant_id": "tenant_demo"},
        "requester": {"type": "service", "id": "simulator_agent"},
        "action": {
            "name": action_name,
            "capability": capability,
            "parameters": parameters,
            "constraints": constraints,
            "scope": {
                "target_resource_type": target_resource_type,
                "single_use": True,
            },
        },
        "target": {
            "resource_type": target_resource_type,
            "resource_id": target_resource_id,
        },
        "justification": justification,
        "metadata": {"simulation": "incident"},
        "context": {"mode": "incident-simulator"},
    }


def _preflight_status(outcome: str) -> str:
    return outcome.replace("_", "-")


def _policy_decision_from_preflight(decision: PreflightDecision) -> PolicyDecision:
    outcome = _preflight_status(decision.outcome)
    rule_id = decision.matched_rules[0] if decision.matched_rules else "preflight.default"
    return PolicyDecision(
        outcome=outcome,
        summary=decision.summary,
        rule_evaluations=(
            RuleEvaluation(
                rule_id=rule_id,
                outcome=outcome,
                reason_code=decision.reason_code,
                summary=decision.summary,
                details=decision.metadata,
                required_evidence=decision.required_evidence,
                approver_types=decision.required_approvals,
            ),
        ),
        reason_codes=(decision.reason_code,),
        required_evidence=decision.required_evidence,
        approver_types=decision.required_approvals,
    )


def _write_pattern_simulation_artifacts(
    paths: LocalRuntimePaths,
    scenario_dir: Path,
    *,
    name: str,
    title: str,
    payload: dict[str, Any],
    evidence_context: dict[str, Any],
    counterfactual_summary: str,
    counterfactual_effect: dict[str, Any],
    broker_summary: str,
    lesson: str,
    framing: dict[str, str],
) -> SimulationScenarioResult:
    now = parse_timestamp(payload["issued_at"], "issued_at")
    intake = ActionIntentIntakeService()
    intent = intake.parse(payload)
    context = DynamicContextInput(
        request_id=f"req_sim_{name.replace('-', '_')}",
        audience=AudienceRef(type="service", id="protected-actenon-endpoint"),
        scope_capabilities=(intent.action.capability,),
        now=now,
        facts=dict(evidence_context),
        parameter_constraints=dict(intent.action.parameters),
        resource_selectors=({"resource_id": intent.target.resource_id},),
    )
    preflight = PreflightEngine().check(payload, evidence_context=evidence_context)
    status = _preflight_status(preflight.outcome)
    policy_decision = _policy_decision_from_preflight(preflight)
    receipt_factory = ReceiptFactory(receipt_id_factory=lambda: f"rcpt_sim_{name.replace('-', '_')}_decision")
    refusal_factory = RefusalFactory(refusal_id_factory=lambda: f"rfsl_sim_{name.replace('-', '_')}_preflight")
    decision_receipt = receipt_factory.create_decision_receipt(intent, policy_decision, context)
    refusal = None
    refused_receipt = None
    if preflight.outcome != "allow":
        refusal = refusal_factory.create_from_exception(
            RefusalException(
                category="preflight",
                refusal_code=preflight.reason_code,
                message=preflight.summary,
                retryable=preflight.outcome in {"approval_required", "needs_evidence"},
                rule_refs=preflight.matched_rules,
                details=preflight.to_dict(),
            ),
            occurred_at=context.now,
            intent=intent,
            context=context,
        )
        refused_receipt = ReceiptFactory(
            receipt_id_factory=lambda: f"rcpt_sim_{name.replace('-', '_')}_refused"
        ).create_refused_receipt(intent, context, refusal)

    broker = InMemoryCredentialBroker(credential_id_factory=lambda: f"cred_sim_{name.replace('-', '_')}_001")
    broker_called = False
    brokered_credential = None
    if preflight.outcome == "allow":
        brokered_credential = broker.acquire(intent, PCCB.from_dict(_minimal_simulation_pccb_payload(intent, context)), context)
        broker.release(brokered_credential, {"outcome": "simulated"})
        broker_called = True
    broker_boundary = {
        "agent_has_standing_credential": False,
        "protected_endpoint_brokers_authority": True,
        "broker_called": broker_called,
        "credential_issued": brokered_credential is not None,
        "credential_reference": brokered_credential.to_public_dict() if brokered_credential is not None else None,
        "raw_secret_exposed": False,
        "summary": broker_summary,
    }
    non_claims = {
        "not_a_factual_incident_report": True,
        "does_not_claim_business_correctness": True,
        "does_not_claim_downstream_provider_finality": True,
        "does_not_claim_adapter_honesty": True,
        "does_not_claim_replay_protection_without_protected_endpoint_state": True,
        "summary": "The simulation proves the boundary shape and local decision artifacts. It does not prove business-policy correctness, downstream provider finality, adapter honesty, or replay protection unless deployed at a protected endpoint.",
    }

    _write_json(scenario_dir / "action_intent.json", payload)
    _write_json(
        scenario_dir / "without_actenon.json",
        {
            "status": "would_execute",
            "summary": counterfactual_summary,
            "effect": counterfactual_effect,
            "credential_mode": "standing-agent-credential",
        },
    )
    _write_json(scenario_dir / "preflight_decision.json", preflight.to_dict())
    _write_json(scenario_dir / "decision_receipt.json", decision_receipt.to_dict())
    if refusal is not None:
        _write_json(scenario_dir / "refusal.json", refusal.to_dict())
    if refused_receipt is not None:
        _write_json(scenario_dir / "refused_receipt.json", refused_receipt.to_dict())
    _write_json(scenario_dir / "credential_broker_boundary.json", broker_boundary)
    _write_json(scenario_dir / "what_actenon_does_not_claim.json", non_claims)
    intent_record_path = _write_intent_record_artifact(
        scenario_dir,
        source="hero-simulator",
        intent=intent,
        context=context,
        decision=policy_decision,
        receipt=decision_receipt,
        refusal=refusal,
        prohibited_actions=("direct_agent_credential_use", "unverified_side_effect"),
        abort_conditions=("preflight_not_allow", "missing_proof", "standing_agent_credential_detected"),
        required_approvals=preflight.required_approvals,
        required_evidence=preflight.required_evidence,
    )

    perspectives = (
        SimulationPerspective(
            key="without_actenon",
            basis="counterfactual",
            status="would_execute",
            summary=counterfactual_summary,
        ),
        SimulationPerspective(
            key="with_preflight",
            basis="observed",
            status=status,
            summary=f"Observed: Preflight returned {status} with {preflight.reason_code}.",
        ),
        SimulationPerspective(
            key="with_credential_broker",
            basis="observed",
            status="side_door_removed",
            summary=broker_summary,
        ),
        SimulationPerspective(
            key="receipt_or_refusal",
            basis="observed",
            status="recorded",
            summary="Observed: the decision and non-execution outcome were written as inspectable Receipt/Refusal artifacts before any side effect.",
        ),
        SimulationPerspective(
            key="non_claims",
            basis="scope",
            status="bounded",
            summary=non_claims["summary"],
        ),
    )
    return SimulationScenarioResult(
        name=name,
        title=title,
        status=status,
        summary=f"{title}: {preflight.summary}",
        artifact_dir=str(scenario_dir),
        refusal_code=preflight.reason_code if refusal is not None else None,
        receipt_id=decision_receipt.receipt_id,
        perspectives=perspectives,
        lesson=lesson,
        details={
            "kind": "pattern",
            "framing": framing,
            "preflight_decision": preflight.to_dict(),
            "credential_broker": broker_boundary,
            "non_claims": non_claims,
            "trace_viewer_follow_up": _trace_viewer_follow_up(paths, label=title, scenario_dir=scenario_dir),
            "intent_record_path": intent_record_path,
        },
    )


def _minimal_simulation_pccb_payload(intent: Any, context: DynamicContextInput) -> dict[str, Any]:
    """Build a local placeholder PCCB shape only for broker-reference demos."""

    issued_at = context.now
    expires_at = issued_at + timedelta(minutes=2)
    action_hash_value = sha256_hex(build_action_hash_input(intent))
    return {
        "contract": {"name": "pccb", "version": "v1"},
        "pccb_id": f"pccb_broker_demo_{intent.intent_id}",
        "intent_id": intent.intent_id,
        "issued_at": format_timestamp(issued_at),
        "not_before": format_timestamp(issued_at),
        "expires_at": format_timestamp(expires_at),
        "issuer": {"type": "service", "id": "hero_simulator"},
        "subject": intent.requester.to_dict(),
        "tenant": intent.tenant.to_dict(),
        "audience": context.audience.to_dict(),
        "action": intent.action.to_dict(),
        "target": intent.target.to_dict(),
        "scope": {
            "mode": "exact",
            "capabilities": [intent.action.capability],
            "single_use": True,
            "resource_selectors": [{"resource_id": intent.target.resource_id}],
            "parameter_constraints": dict(intent.action.parameters),
        },
        "nonce": f"nonce-broker-demo-{intent.intent_id}",
        "action_hash": {
            "algorithm": "sha-256",
            "canonicalization": "actenon-jcs-sha256-v1",
            "value": action_hash_value,
        },
        "signature": {
            "algorithm": "HS256",
            "key_id": LOCAL_PROOF_KEY_ID,
            "encoding": "base64url",
            "value": "simulation-placeholder-not-for-verification",
        },
    }


def _bounded_intent_details(
    *,
    payload: dict[str, Any],
    audience: AudienceRef,
    pccb: PCCB | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details = {
        "intent_id": payload["intent_id"],
        "capability": payload["action"]["capability"],
        "audience": audience.to_dict(),
        "target": payload["target"],
        "constraints": payload["action"].get("constraints", {}),
        "scope": payload["action"].get("scope", {}),
        "single_use": payload["action"].get("scope", {}).get("single_use", False),
    }
    if pccb is not None:
        details["pccb_id"] = pccb.pccb_id
        details["action_hash"] = pccb.action_hash.to_dict()
    if extra:
        details.update(extra)
    return details


def _simulate_incident_proof_refusal(
    paths: LocalRuntimePaths,
    scenario_dir: Path,
    *,
    incident: IncidentSimulationDefinition,
    payload: dict[str, Any],
    mint_audience: AudienceRef,
    verify_audience: AudienceRef,
    verify_now: datetime,
    counterfactual_summary: str,
    counterfactual_effect: dict[str, Any],
    expected_refusal_code: str,
    proof_bound_summary: str,
    proof_only_gap_summary: str,
    bounded_intent_summary: str,
    prohibited_actions: tuple[str, ...],
    abort_conditions: tuple[str, ...],
    blast_radius_limits: dict[str, Any],
    mutate_action_hash: bool = False,
) -> SimulationScenarioResult:
    intake = ActionIntentIntakeService()
    intent = intake.parse(payload)
    mint_context = DynamicContextInput(
        request_id=f"req_incident_{incident.name.replace('-', '_')}",
        audience=mint_audience,
        scope_capabilities=(intent.action.capability,),
        now=verify_now if incident.name == "openai-eggs" else parse_timestamp(payload["issued_at"], "issued_at"),
        parameter_constraints=dict(payload["action"].get("constraints", {})),
        resource_selectors=({"resource_id": payload["target"]["resource_id"]},),
    )
    bounded_pccb = PCCBMinter(
        signer=build_local_proof_signer(),
        issuer=PartyRef(type="service", id="incident_simulator", display_name="Incident Simulator"),
        pccb_id_factory=lambda: f"pccb_incident_{incident.name.replace('-', '_')}",
        nonce_factory=lambda: f"nonce-incident-{incident.name.replace('-', '-')}-00000001",
    ).mint(
        intent,
        decision=PolicyDecision(
            outcome="allow",
            summary=f"{incident.title} mints a bounded proof for the intended protected action.",
            rule_evaluations=(),
            reason_codes=("SIMULATION_ALLOW",),
        ),
        context=mint_context,
    )
    pccb = bounded_pccb
    if mutate_action_hash:
        pccb_payload = pccb.to_dict()
        pccb_payload["action_hash"]["value"] = "badc0ffe" * 8
        pccb = PCCB.from_dict(pccb_payload)

    _write_json(scenario_dir / "action_intent.json", payload)
    _write_json(scenario_dir / "pccb.json", pccb.to_dict())
    intent_record_path = _write_intent_record_artifact(
        scenario_dir,
        source="incident-simulator",
        intent=intent,
        context=mint_context,
        decision=PolicyDecision(
            outcome="allow",
            summary=f"{incident.title} delegates a bounded machine action for protected execution.",
            rule_evaluations=(),
            reason_codes=("INCIDENT_SIMULATION_ALLOW",),
        ),
        pccb=bounded_pccb,
        prohibited_actions=prohibited_actions,
        abort_conditions=abort_conditions,
        blast_radius_limits=blast_radius_limits,
    )
    _write_json(
        scenario_dir / "counterfactual_unprotected_execution.json",
        {
            "status": "would_execute",
            "summary": counterfactual_summary,
            "effect": counterfactual_effect,
        },
    )

    sdk = VerifierSDK(build_local_proof_signer())
    verify_context = sdk.build_context(
        request_id=f"req_incident_verify_{incident.name.replace('-', '_')}",
        audience=verify_audience,
        now=verify_now,
        scope_capabilities=pccb.scope.capabilities,
        parameter_constraints=pccb.scope.parameter_constraints,
        resource_selectors=pccb.scope.resource_selectors,
    )
    try:
        sdk.verify(intent=intent, pccb=pccb, context=verify_context)
    except RefusalException as exc:
        refusal = RefusalFactory(refusal_id_factory=lambda: f"rfsl_incident_{incident.name.replace('-', '_')}").create_from_exception(
            exc,
            occurred_at=verify_context.now,
            intent=intent,
            context=verify_context,
            pccb_id=pccb.pccb_id,
            action_hash=pccb.action_hash,
        )
        if refusal.reason_code != expected_refusal_code:
            raise RuntimeError(
                f"{incident.name} simulation returned {refusal.reason_code!r}, expected {expected_refusal_code!r}"
            )
        _write_json(scenario_dir / "refusal.json", refusal.to_dict())
        perspectives = (
            SimulationPerspective(
                key="weak_control_path",
                basis="counterfactual",
                status="would_execute",
                summary=counterfactual_summary,
            ),
            SimulationPerspective(
                key="proof_bound_path",
                basis="observed",
                status="refused",
                summary=proof_bound_summary,
            ),
            SimulationPerspective(
                key="proof_only_gap",
                basis="generalized-runtime-gap",
                status="still_needs_runtime_state",
                summary=proof_only_gap_summary,
            ),
            SimulationPerspective(
                key="bounded_intent_change",
                basis="observed",
                status="constrained",
                summary=bounded_intent_summary,
            ),
        )
        return SimulationScenarioResult(
            name=incident.name,
            title=incident.title,
            status="refused",
            summary=f"{incident.title} was stopped before side effects with {refusal.reason_code}.",
            artifact_dir=str(scenario_dir),
            refusal_code=refusal.reason_code,
            perspectives=perspectives,
            lesson=incident.lesson,
            details={
                "kind": "incident",
                "framing": {
                    "inspired_by": incident.inspired_by,
                    "disclaimer": incident.disclaimer,
                    "primary_focus": incident.primary_focus,
                },
                "trace_viewer_follow_up": _trace_viewer_follow_up(paths, label=incident.title, scenario_dir=scenario_dir),
                "intent_record_path": intent_record_path,
                "bounded_intent": _bounded_intent_details(
                    payload=payload,
                    audience=mint_audience,
                    pccb=bounded_pccb,
                    extra={
                        "intent_record_path": intent_record_path,
                    },
                ),
            },
        )
    raise RuntimeError(f"{incident.name} simulation unexpectedly verified instead of refusing with {expected_refusal_code}")


def _simulate_openai_eggs_incident(paths: LocalRuntimePaths, scenario_dir: Path) -> SimulationScenarioResult:
    incident = INCIDENT_DEFINITIONS["openai-eggs"]
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    payload = build_invoice_payment_action_intent_payload(
        intent_id="intent_incident_openai_eggs_001",
        tenant_id="tenant_demo",
        requester_id="shopping_agent",
        payer_entity_id="consumer_demo",
        supplier_id="grocery_demo_eggs",
        bank_account_reference="consumer_card_ending_4242",
        invoice_ids=("order_eggs_001",),
        amount_minor=3143,
        currency="USD",
        payment_date="2026-01-01",
        payment_batch_id="batch_eggs_001",
        issued_at=now,
        proposer_id="shopping_agent",
        justification="Purchase one basket of groceries including eggs.",
        context={"incident": incident.name},
        metadata={"incident": incident.name},
    )
    intake = ActionIntentIntakeService()
    intent = intake.parse(payload)
    context = DynamicContextInput(
        request_id="req_incident_openai_eggs_001",
        audience=AudienceRef(type="service", id="local-purchase-endpoint"),
        scope_capabilities=("invoice_payment.execute",),
        now=now,
        facts={
            "risk_level": "approval",
            "expected_payer_entity_id": "consumer_demo",
            "expected_supplier_id": "grocery_demo_eggs",
            "expected_bank_account_reference": "consumer_card_ending_4242",
            "expected_invoice_ids": ["order_eggs_001"],
            "expected_amount_minor": 3143,
            "expected_currency": "USD",
            "expected_payment_date": "2026-01-01",
            "expected_batch_hash": payload["action"]["parameters"]["batch_hash"],
            "required_approval_chain": ["customer_confirmed"],
            "provided_approval_chain": [],
            "required_approver_types": ["customer"],
            "approval_required": True,
            "prohibited_actions": ("invoice_payment.payee_override", "invoice_payment.amount_override"),
            "abort_conditions": ("merchant_mismatch", "amount_exceeds_delegated_limit"),
            "blast_radius_limits": {
                "max_checkout_targets": {
                    "value": 1,
                    "summary": "A delegated purchase may target only one merchant checkout.",
                },
                "max_amount_minor": {
                    "value": 3143,
                    "summary": "Do not exceed the delegated purchase amount.",
                    "unit": "minor_units",
                },
            },
        },
        parameter_constraints=dict(payload["action"]["constraints"]),
        resource_selectors=({"resource_id": payload["target"]["resource_id"]},),
        approver_types=("customer",),
    )
    outcome_writer = JsonArtifactOutcomeWriter(scenario_dir / "outcomes")
    signer = build_local_proof_signer()
    escrow = build_sqlite_capability_escrow(scenario_dir / "state" / "escrow.sqlite3")
    replay_protector = ReplayProtector(SqliteReplayStore(scenario_dir / "state" / "replay.sqlite3"))
    kernel = ProtectedExecutionKernel(
        intake=ActionIntentIntakeService(),
        policy_engine=build_invoice_payment_policy_engine(),
        pccb_minter=PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="incident_simulator", display_name="Incident Simulator"),
            pccb_id_factory=lambda: "pccb_incident_openai_eggs_001",
            nonce_factory=lambda: "nonce-incident-openai-eggs-00000001",
        ),
        escrow=escrow,
        middleware=ProtectedEndpointMiddleware(
            proof_verifier=PCCBVerifier(signer),
            escrow=escrow,
            receipt_factory=ReceiptFactory(receipt_id_factory=lambda: "rcpt_incident_openai_eggs_exec"),
            refusal_factory=RefusalFactory(refusal_id_factory=lambda: "rfsl_incident_openai_eggs_exec"),
            outcome_writer=outcome_writer,
            replay_protector=replay_protector,
        ),
        receipt_factory=ReceiptFactory(receipt_id_factory=lambda: "rcpt_incident_openai_eggs_decision"),
        refusal_factory=RefusalFactory(refusal_id_factory=lambda: "rfsl_incident_openai_eggs_decision"),
        outcome_writer=outcome_writer,
        escrow_id_factory=lambda: "esc_incident_openai_eggs_001",
    )
    admission = kernel.submit_intent(payload, context)
    if admission.decision is None or admission.receipt is None:
        raise RuntimeError("openai-eggs simulation did not return a decision receipt")
    if admission.decision.outcome != "approval-required":
        raise RuntimeError("openai-eggs simulation expected approval-required")
    _write_json(scenario_dir / "action_intent.json", payload)
    _write_json(
        scenario_dir / "counterfactual_unprotected_execution.json",
        {
            "status": "would_execute",
            "summary": "Counterfactual weak control path: a plain consumer purchase request reaches checkout and authorizes the charge without any execution-edge admission boundary.",
            "effect": {
                "merchant": "grocery_demo_eggs",
                "amount_minor": 3143,
                "currency": "USD",
                "target": payload["target"],
            },
        },
    )
    _write_json(
        scenario_dir / "decision.json",
        {
            "outcome": admission.decision.outcome,
            "summary": admission.decision.summary,
            "reason_codes": list(admission.decision.reason_codes),
        },
    )
    _write_json(scenario_dir / "decision_receipt.json", admission.receipt.to_dict())
    intent_record_path = _write_intent_record_artifact(
        scenario_dir,
        source="incident-simulator",
        intent=intent,
        context=context,
        decision=admission.decision,
        receipt=admission.receipt,
    )
    perspectives = (
        SimulationPerspective(
            key="weak_control_path",
            basis="counterfactual",
            status="would_execute",
            summary="Counterfactual: a plain purchase request reaches the dangerous endpoint and the charge goes through without execution-edge trust.",
        ),
        SimulationPerspective(
            key="proof_bound_path",
            basis="observed",
            status="approval-required",
            summary="Observed: execution-edge admission normalized the request into a canonical Action Intent and stopped before proof minting with APPROVAL_MISSING.",
        ),
        SimulationPerspective(
            key="proof_only_gap",
            basis="generalized-runtime-gap",
            status="still_needs_exact_binding",
            summary="A generic approval story is still too broad. Once proof exists, the execution edge must still verify exact merchant, amount, target, and replay state.",
        ),
        SimulationPerspective(
            key="bounded_intent_change",
            basis="observed",
            status="constrained",
            summary="Observed: the local Action Intent bound the purchase to one supplier, one amount, one batch, and one single-use execution path.",
        ),
    )
    return SimulationScenarioResult(
        name=incident.name,
        title=incident.title,
        status="approval-required",
        summary="Execution-edge admission required approval before any purchase proof was minted.",
        artifact_dir=str(scenario_dir),
        receipt_id=admission.receipt.receipt_id,
        perspectives=perspectives,
        lesson=incident.lesson,
        details={
            "kind": "incident",
            "framing": {
                "inspired_by": incident.inspired_by,
                "disclaimer": incident.disclaimer,
                "primary_focus": incident.primary_focus,
            },
            "trace_viewer_follow_up": _trace_viewer_follow_up(paths, label=incident.title, scenario_dir=scenario_dir),
            "intent_record_path": intent_record_path,
            "bounded_intent": _bounded_intent_details(
                payload=payload,
                audience=context.audience,
                pccb=None,
                extra={
                    "decision_outcome": admission.decision.outcome,
                    "required_approvals": ["customer_confirmed"],
                    "provided_approvals": [],
                    "batch_hash": payload["action"]["parameters"]["batch_hash"],
                    "intent_record_path": intent_record_path,
                },
            ),
        },
    )


def _simulate_prod_delete_incident(paths: LocalRuntimePaths, scenario_dir: Path) -> SimulationScenarioResult:
    incident = INCIDENT_DEFINITIONS["prod-delete"]
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    payload = _build_generic_action_intent_payload(
        intent_id="intent_pattern_prod_delete_001",
        issued_at=now,
        action_name="database.delete",
        capability="database.delete",
        target_resource_type="database",
        target_resource_id="prod-db-primary",
        parameters={
            "environment": "production",
            "operation": "delete_database",
            "change_ticket": "CHG-9001",
            "backup_verified": True,
        },
        constraints={
            "exact_environment": "production",
            "exact_target": "prod-db-primary",
            "single_target_only": True,
        },
        justification="Delete a production database after migration cleanup.",
    )
    return _write_pattern_simulation_artifacts(
        paths,
        scenario_dir,
        name=incident.name,
        title=incident.title,
        payload=payload,
        evidence_context={
            "environment": "production",
            "change_ticket": "CHG-9001",
            "backup_verified": True,
            "approval_present": False,
        },
        counterfactual_summary=(
            "Without Actenon: an agent holding standing database credentials would reach the production delete path."
        ),
        counterfactual_effect={
            "would_have_executed": "database.delete",
            "target": {"resource_type": "database", "resource_id": "prod-db-primary"},
            "side_effect": "production database deletion",
        },
        broker_summary=(
            "With the credential-broker boundary, the agent has no production database credential; the protected endpoint "
            "would broker authority only after proof and policy allow the action."
        ),
        lesson="No receipt, no prod delete.",
        framing={
            "inspired_by": incident.inspired_by,
            "disclaimer": incident.disclaimer,
            "primary_focus": incident.primary_focus,
        },
    )


def _simulate_mcp_tool_proof_laundering(paths: LocalRuntimePaths, scenario_dir: Path) -> SimulationScenarioResult:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    payload = _build_generic_action_intent_payload(
        intent_id="intent_pattern_mcp_laundering_001",
        issued_at=now,
        action_name="mcp.tool.invoke",
        capability="infrastructure.delete",
        target_resource_type="mcp_tool",
        target_resource_id="prod-infra-delete-tool",
        parameters={
            "environment": "production",
            "source_tool_id": "staging-cleanup-tool",
            "presented_tool_id": "prod-infra-delete-tool",
            "change_ticket": "CHG-9100",
            "backup_verified": True,
        },
        constraints={
            "exact_tool_id": "staging-cleanup-tool",
            "exact_environment": "staging",
        },
        justification="Invoke a bounded MCP cleanup tool.",
    )
    return _write_pattern_simulation_artifacts(
        paths,
        scenario_dir,
        name="mcp-tool-proof-laundering",
        title="MCP Tool Proof-Laundering Pattern",
        payload=payload,
        evidence_context={
            "environment": "production",
            "change_ticket": "CHG-9100",
            "backup_verified": True,
            "approval_present": False,
        },
        counterfactual_summary=(
            "Without Actenon: a proof or approval story minted for one tool could be carried to a different side-effecting tool."
        ),
        counterfactual_effect={
            "would_have_executed": "infrastructure.delete",
            "source_tool_id": "staging-cleanup-tool",
            "presented_tool_id": "prod-infra-delete-tool",
            "bypass": "tool handler trusts upstream state instead of verifying exact audience and action.",
        },
        broker_summary=(
            "With a credential-broker boundary, the MCP handler owns the production authority and will not broker it to a "
            "mismatched or unapproved tool invocation."
        ),
        lesson="Frameworks plan. Tool handlers verify. No receipt, no tool side effect.",
        framing={
            "inspired_by": "Generic MCP/tool-handler proof-laundering pattern, not a named factual incident report.",
            "disclaimer": "This simulation demonstrates a tool-boundary failure mode without asserting facts about any named incident.",
            "primary_focus": "Wrong tool, wrong audience, or widened side effect at the MCP handler.",
        },
    )


def _simulate_iam_escalation(paths: LocalRuntimePaths, scenario_dir: Path) -> SimulationScenarioResult:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    payload = _build_generic_action_intent_payload(
        intent_id="intent_pattern_iam_escalation_001",
        issued_at=now,
        action_name="iam.permission.grant",
        capability="iam.permission.grant",
        target_resource_type="principal",
        target_resource_id="agent-runtime-service-account",
        parameters={
            "environment": "production",
            "role": "admin",
            "scope": "*",
            "change_ticket": "CHG-9200",
        },
        constraints={
            "max_role": "read_only",
            "exact_principal": "agent-runtime-service-account",
        },
        justification="Grant temporary operational access.",
    )
    return _write_pattern_simulation_artifacts(
        paths,
        scenario_dir,
        name="iam-escalation",
        title="IAM Privilege-Escalation Pattern",
        payload=payload,
        evidence_context={
            "environment": "production",
            "change_ticket": "CHG-9200",
            "role": "admin",
            "approval_present": False,
        },
        counterfactual_summary=(
            "Without Actenon: an agent with standing IAM authority could attach an admin role directly to its runtime principal."
        ),
        counterfactual_effect={
            "would_have_executed": "iam.permission.grant",
            "target": {"resource_type": "principal", "resource_id": "agent-runtime-service-account"},
            "role": "admin",
            "scope": "*",
        },
        broker_summary=(
            "With a credential-broker boundary, the agent does not hold IAM admin credentials; the protected endpoint refuses "
            "to broker privilege without required approval."
        ),
        lesson="No receipt, no privilege.",
        framing={
            "inspired_by": "Generic IAM privilege-escalation pattern, not a named factual incident report.",
            "disclaimer": "This simulation demonstrates a privileged access boundary failure mode without asserting facts about any named incident.",
            "primary_focus": "Standing IAM credentials let agent actions bypass proof and approval.",
        },
    )


def _simulate_data_export(paths: LocalRuntimePaths, scenario_dir: Path) -> SimulationScenarioResult:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    payload = _build_generic_action_intent_payload(
        intent_id="intent_pattern_data_export_001",
        issued_at=now,
        action_name="customer.export",
        capability="data.export",
        target_resource_type="warehouse_table",
        target_resource_id="customer_prod_profiles",
        parameters={
            "environment": "production",
            "row_count": 25000,
            "sensitive_data": True,
            "destination": "s3://external-vendor-drop/customer-profiles",
            "change_ticket": "CHG-9300",
        },
        constraints={
            "max_rows": 500,
            "allowed_destination": "internal-analytics",
        },
        justification="Export customer profile rows for analysis.",
    )
    return _write_pattern_simulation_artifacts(
        paths,
        scenario_dir,
        name="data-export",
        title="Sensitive Data Export Pattern",
        payload=payload,
        evidence_context={
            "environment": "production",
            "change_ticket": "CHG-9300",
            "row_count": 25000,
            "sensitive_data": True,
            "destination": "s3://external-vendor-drop/customer-profiles",
        },
        counterfactual_summary=(
            "Without Actenon: an agent with standing warehouse export permission could copy a broad sensitive dataset to an external destination."
        ),
        counterfactual_effect={
            "would_have_executed": "data.export",
            "target": {"resource_type": "warehouse_table", "resource_id": "customer_prod_profiles"},
            "row_count": 25000,
            "destination": "s3://external-vendor-drop/customer-profiles",
        },
        broker_summary=(
            "With a credential-broker boundary, the agent has no direct warehouse export credential; the protected endpoint "
            "requires approval before brokering export authority."
        ),
        lesson="No receipt, no export.",
        framing={
            "inspired_by": "Generic sensitive data export/exfiltration pattern, not a named factual incident report.",
            "disclaimer": "This simulation demonstrates a data-export boundary failure mode without asserting facts about any named incident.",
            "primary_focus": "Read permission is not the same as authority to export sensitive data externally.",
        },
    )


def _simulate_named_incident(paths: LocalRuntimePaths, incident_name: str) -> SimulationScenarioResult:
    incident = INCIDENT_DEFINITIONS[incident_name]
    scenario_dir = paths.simulations_root / incident_name
    if incident_name == "prod-delete":
        return _simulate_prod_delete_incident(paths, scenario_dir)
    if incident_name == "replit":
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        payload = _build_generic_action_intent_payload(
            intent_id="intent_incident_replit_001",
            issued_at=now,
            action_name="database.schema.apply",
            capability="database.migration.execute",
            target_resource_type="database",
            target_resource_id="customer_prod_primary",
            parameters={
                "environment": "production",
                "migration_id": "2026_01_add_projects_index",
                "change_set_sha256": "mig_2026_01_add_projects_index",
            },
            constraints={
                "exact_environment": "production",
                "exact_migration_id": "2026_01_add_projects_index",
                "exact_change_set_sha256": "mig_2026_01_add_projects_index",
            },
            justification="Apply a single reviewed schema migration to the production customer database.",
        )
        return _simulate_incident_proof_refusal(
            paths,
            scenario_dir,
            incident=incident,
            payload=payload,
            mint_audience=AudienceRef(type="service", id="local-db-admin-endpoint"),
            verify_audience=AudienceRef(type="service", id="local-db-admin-endpoint"),
            verify_now=now,
            counterfactual_summary="Counterfactual weak control path: a broadly trusted development agent turns an intended schema migration into a destructive database action and the execution edge never rechecks the exact action.",
            counterfactual_effect={
                "would_have_executed": "database destructive action",
                "target": payload["target"],
                "operator_story": "The tool already had the power, so the widened action would reach the database anyway.",
            },
            expected_refusal_code="ACTION_HASH_MISMATCH",
            proof_bound_summary="Observed: the protected endpoint refused the mutated action because the presented PCCB no longer matched the Action Intent hash.",
            proof_only_gap_summary="Even a correctly signed destructive action would still need protected-endpoint replay and runtime controls. Signature alone does not make repeated or misrouted execution safe.",
            bounded_intent_summary="Observed: bounded intent froze the exact migration, target database, and change-set hash so the request could not silently widen into a destructive operation.",
            prohibited_actions=("database.drop", "database.reset", "database.bulk_delete"),
            abort_conditions=("change_set_hash_mismatch", "unexpected_table_drop_detected"),
            blast_radius_limits={
                "max_database_targets": {
                    "value": 1,
                    "summary": "A delegated migration may target only one database.",
                },
                "max_change_sets": {
                    "value": 1,
                    "summary": "A delegated migration may apply only one reviewed change set.",
                },
            },
            mutate_action_hash=True,
        )
    if incident_name == "amazon-kiro":
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        payload = _build_generic_action_intent_payload(
            intent_id="intent_incident_amazon_kiro_001",
            issued_at=now,
            action_name="environment.rebuild",
            capability="environment.rebuild.execute",
            target_resource_type="environment",
            target_resource_id="cost-explorer-sandbox",
            parameters={
                "environment": "cost-explorer-sandbox",
                "template_id": "sandbox_restore_v3",
                "operation": "rebuild_environment",
            },
            constraints={
                "exact_environment": "cost-explorer-sandbox",
                "exact_template_id": "sandbox_restore_v3",
                "exact_operation": "rebuild_environment",
            },
            justification="Rebuild the intended sandbox environment only.",
        )
        return _simulate_incident_proof_refusal(
            paths,
            scenario_dir,
            incident=incident,
            payload=payload,
            mint_audience=AudienceRef(type="service", id="sandbox-environment-runner"),
            verify_audience=AudienceRef(type="service", id="production-environment-runner"),
            verify_now=now,
            counterfactual_summary="Counterfactual weak control path: an agent with broad environment authority sends a sandbox action to the wrong execution edge and the wrong environment accepts it.",
            counterfactual_effect={
                "would_have_executed": "wrong-environment rebuild",
                "target": {"resource_type": "environment", "resource_id": "production-environment-runner"},
                "operator_story": "Upstream intent said sandbox, but the production runner never rechecked the audience at execution time.",
            },
            expected_refusal_code="AUDIENCE_MISMATCH",
            proof_bound_summary="Observed: audience binding turned the wrong-environment call into a deterministic refusal at the protected endpoint.",
            proof_only_gap_summary="Audience binding closes the wrong-endpoint hole, but valid proof still needs protected-endpoint state for replay and other runtime-only invariants.",
            bounded_intent_summary="Observed: bounded intent fixed the execution edge to the sandbox runner and kept the same action from being replayed or redirected as general environment authority.",
            prohibited_actions=("environment.production_rebuild", "environment.cross_account_apply"),
            abort_conditions=("audience_mismatch", "unexpected_environment_target"),
            blast_radius_limits={
                "max_environment_targets": {
                    "value": 1,
                    "summary": "A delegated environment action may target only one runtime audience.",
                },
                "max_operations": {
                    "value": 1,
                    "summary": "A delegated environment action may perform only one rebuild operation.",
                },
            },
        )
    if incident_name == "openai-eggs":
        return _simulate_openai_eggs_incident(paths, scenario_dir)
    raise ValueError(f"unsupported incident simulation: {incident_name!r}")


def simulate_local_runtime(
    runtime_dir: str | Path | None = None,
    *,
    scenario: str = "all",
    incident: str | None = None,
) -> SimulationReport:
    if incident is not None and incident != "all" and incident not in INCIDENT_SIMULATIONS:
        raise ValueError(f"unsupported incident simulation: {incident!r}")
    if incident is None and scenario != "all" and scenario not in SIMULATION_SCENARIOS:
        raise ValueError(f"unsupported simulation scenario: {scenario!r}")

    paths = resolve_local_runtime_paths(runtime_dir)
    paths.simulations_root.mkdir(parents=True, exist_ok=True)

    selected = INCIDENT_SIMULATIONS if incident == "all" else ((incident,) if incident is not None else (SIMULATION_SCENARIOS if scenario == "all" else (scenario,)))
    results: list[SimulationScenarioResult] = []
    for name in selected:
        scenario_dir = paths.simulations_root / name
        _ensure_removed(scenario_dir)
        scenario_dir.mkdir(parents=True, exist_ok=True)
        if incident is not None:
            result = _simulate_named_incident(paths, name)
        elif name == "mcp-tool-proof-laundering":
            result = _simulate_mcp_tool_proof_laundering(paths, scenario_dir)
        elif name == "iam-escalation":
            result = _simulate_iam_escalation(paths, scenario_dir)
        elif name == "data-export":
            result = _simulate_data_export(paths, scenario_dir)
        elif name == "replay-refused":
            result = _simulate_replay_refused(scenario_dir)
        else:
            result = _simulate_portable_verifier_case(scenario_dir, name)
        results.append(_persist_simulation_story(scenario_dir, result))

    report = SimulationReport(
        scenario=incident or scenario,
        runtime_root=str(paths.root),
        succeeded=all(_simulation_status_is_success(item.status) for item in results),
        results=tuple(results),
        mode="incident" if incident is not None else "technical",
        framing_note="Educational simulations and pattern reconstructions. They illustrate boundary failures and protective outcomes without claiming exact forensic reconstruction."
        if incident is not None
        else None,
        takeaways=_build_incident_takeaways(selected) if incident is not None else _build_simulation_takeaways(selected),
    )
    _write_json(paths.simulations_root / "manifest.json", report.to_dict())
    return report


def _build_simulation_takeaways(selected: tuple[str, ...]) -> tuple[str, ...]:
    takeaways = [
        "Without execution-edge verification, an upstream allow can still reach the wrong endpoint or wrong parameters.",
        "The protected endpoint is where proof becomes consequential: the side effect happens only after the edge verifies the exact action.",
    ]
    proof_catch_scenarios = {"audience-mismatch", "action-hash-mismatch", "expired-proof"}
    if any(item in proof_catch_scenarios for item in selected):
        takeaways.append(
            "Proof binding catches wrong audience, mutated action, and expired proof before side effects."
        )
    if "replay-refused" in selected:
        takeaways.append(
            "Proof alone does not stop replay. Replay protection is a protected-endpoint runtime property backed by state."
        )
    if any(item in {"mcp-tool-proof-laundering", "iam-escalation", "data-export"} for item in selected):
        takeaways.append(
            "Preflight and credential brokering make the side door explicit: agents should not hold standing production credentials for consequential actions."
        )
    takeaways.append(
        "The Action Intent plus Receipt or Refusal turns each incident into an inspectable record instead of an anecdote."
    )
    return tuple(takeaways)


def _persist_simulation_story(scenario_dir: Path, result: SimulationScenarioResult) -> SimulationScenarioResult:
    summary_path = scenario_dir / "INCIDENT_SUMMARY.md"
    story_payload = {
        "name": result.name,
        "title": result.title,
        "status": result.status,
        "summary": result.summary,
        "lesson": result.lesson,
        "perspectives": [item.to_dict() for item in result.perspectives],
        "reason_code": result.refusal_code,
        "receipt_id": result.receipt_id,
        "details": result.details,
    }
    _write_json(scenario_dir / "incident_story.json", story_payload)
    if result.details.get("framing") is not None:
        _write_json(scenario_dir / "framing.json", result.details["framing"])
    if result.details.get("trace_viewer_follow_up") is not None:
        _write_json(scenario_dir / "trace_viewer_follow_up.json", result.details["trace_viewer_follow_up"])
    if result.details.get("bounded_intent") is not None:
        bounded_intent_perspective = next((item for item in result.perspectives if item.key == "bounded_intent_change"), None)
        bounded_intent_payload = {
            "summary": bounded_intent_perspective.summary if bounded_intent_perspective is not None else None,
            "details": result.details["bounded_intent"],
        }
        _write_json(scenario_dir / "bounded_intent_change.json", bounded_intent_payload)
    for perspective in result.perspectives:
        if perspective.key == "bounded_intent_change":
            continue
        _write_json(scenario_dir / f"{perspective.key}.json", perspective.to_dict())
    summary_lines = [
        f"# {result.title or result.name}",
        "",
        f"Simulation id: `{result.name}`",
        "",
        f"Status: `{result.status}`",
        "",
        result.summary,
    ]
    framing = result.details.get("framing")
    if isinstance(framing, dict):
        summary_lines.extend(
            [
                "",
                "Framing:",
                "",
                f"- Inspired by: {framing.get('inspired_by', '')}",
                f"- Disclaimer: {framing.get('disclaimer', '')}",
                f"- Primary focus: {framing.get('primary_focus', '')}",
            ]
        )
    if result.lesson is not None:
        summary_lines.extend(["", f"Lesson: {result.lesson}"])
    if result.refusal_code is not None:
        summary_lines.extend(["", f"Reason code: `{result.refusal_code}`"])
    if result.receipt_id is not None:
        summary_lines.extend(["", f"Receipt id: `{result.receipt_id}`"])
    intent_record_path = result.details.get("intent_record_path")
    if isinstance(intent_record_path, str):
        summary_lines.extend(["", f"Intent Record: `{intent_record_path}`"])
    summary_lines.extend(["", "Perspectives:"])
    for item in result.perspectives:
        summary_lines.extend(
            [
                "",
                f"- `{item.key}` [{item.basis}] -> `{item.status}`",
                f"  {item.summary}",
            ]
        )
    trace_viewer_follow_up = result.details.get("trace_viewer_follow_up")
    if isinstance(trace_viewer_follow_up, dict):
        summary_lines.extend(
            [
                "",
                "Trace Viewer Follow-Up:",
                "",
                f"- Available: `{trace_viewer_follow_up.get('available')}`",
                f"- Summary: {trace_viewer_follow_up.get('summary', '')}",
            ]
        )
        if trace_viewer_follow_up.get("url"):
            summary_lines.append(f"- URL: {trace_viewer_follow_up['url']}")
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return SimulationScenarioResult(
        name=result.name,
        status=result.status,
        summary=result.summary,
        artifact_dir=result.artifact_dir,
        title=result.title,
        refusal_code=result.refusal_code,
        receipt_id=result.receipt_id,
        perspectives=result.perspectives,
        lesson=result.lesson,
        summary_path=str(summary_path),
        details=result.details,
    )


def _write_portable_counterfactual_execution(
    scenario_dir: Path,
    *,
    intent: ActionIntent,
    presented_pccb_id: str,
    request_id: str,
) -> None:
    message = intent.action.parameters.get("message")
    payload = {
        "status": "would_execute",
        "summary": "Counterfactual unprotected execution: the endpoint acted on the presented request without verifying proof at the execution edge.",
        "presented_pccb_id": presented_pccb_id,
        "unprotected_response": {
            "resource_id": intent.target.resource_id,
            "message": message,
            "request_id": request_id,
            "intent_id": intent.intent_id,
            "pccb_id": presented_pccb_id,
            "operator_summary": f"Counterfactual unprotected endpoint would have returned the message '{message}' without proof verification.",
        },
    }
    _write_json(scenario_dir / "counterfactual_unprotected_execution.json", payload)


def _write_replay_counterfactual_execution(scenario_dir: Path) -> None:
    payload = {
        "status": "would_execute_twice",
        "summary": "Counterfactual unprotected execution: without replay enforcement at the protected endpoint, the same proof-bearing request could drive two side effects.",
        "unprotected_side_effects": [
            {"external_reference": "exec_sim_001", "sequence": 1},
            {"external_reference": "exec_sim_002", "sequence": 2},
        ],
    }
    _write_json(scenario_dir / "counterfactual_unprotected_execution.json", payload)


def _write_intent_record_artifact(
    scenario_dir: Path,
    *,
    source: str,
    intent: ActionIntent,
    context: DynamicContextInput,
    decision: PolicyDecision,
    pccb: PCCB | None = None,
    receipt: Receipt | None = None,
    refusal: Refusal | None = None,
    prohibited_actions: tuple[str, ...] | None = None,
    abort_conditions: tuple[str, ...] | None = None,
    blast_radius_limits: dict[str, Any] | None = None,
    required_approvals: tuple[str, ...] | None = None,
    required_evidence: tuple[str, ...] | None = None,
) -> str:
    intent_record = build_intent_record(
        source=source,
        intent=intent,
        context=context,
        decision=decision,
        pccb_id=pccb.pccb_id if pccb is not None else None,
        receipt_id=receipt.receipt_id if receipt is not None else None,
        refusal_id=refusal.refusal_id if refusal is not None else None,
        prohibited_actions=prohibited_actions,
        abort_conditions=abort_conditions,
        blast_radius_limits=blast_radius_limits,
        required_approvals=required_approvals,
        required_evidence=required_evidence,
    )
    path = scenario_dir / "intent_record.json"
    _write_json(path, intent_record.to_dict())
    return str(path)


def _simulate_portable_verifier_case(scenario_dir: Path, scenario_name: str) -> SimulationScenarioResult:
    payload = build_hello_world_action_intent_payload()
    intake = ActionIntentIntakeService()
    intent = intake.parse(payload)
    decision = PolicyDecision(
        outcome="allow",
        summary=f"Simulation {scenario_name} mints a portable proof.",
        rule_evaluations=(),
        reason_codes=("LOCAL_PROOF_ALLOW",),
    )
    mint_context = DynamicContextInput(
        request_id=f"req_sim_{scenario_name.replace('-', '_')}",
        audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
        scope_capabilities=("protected_resource.read",),
        now=FIXED_BASE_TIME,
        parameter_constraints={"exact_message": "portable hello world"},
        resource_selectors=({"resource_id": "hello_resource_demo_001"},),
    )
    pccb = PCCBMinter(
        signer=build_local_proof_signer(),
        issuer=PartyRef(type="service", id="portable_local_issuer", display_name="Portable Local Issuer"),
        pccb_id_factory=lambda: f"pccb_sim_{scenario_name.replace('-', '_')}",
        nonce_factory=lambda: f"nonce-sim-{scenario_name.replace('-', '-')}-00000001",
    ).mint(
        intent,
        decision=decision,
        context=mint_context,
    )

    verification_audience = AudienceRef(type="service", id="portable-hello-world-endpoint")
    verification_now = pccb.issued_at
    if scenario_name == "audience-mismatch":
        verification_audience = AudienceRef(type="service", id="wrong-endpoint")
    if scenario_name == "expired-proof":
        verification_now = pccb.expires_at + timedelta(minutes=1)
    if scenario_name == "action-hash-mismatch":
        pccb_payload = pccb.to_dict()
        pccb_payload["action_hash"]["value"] = "deadbeef" * 8
        pccb = PCCB.from_dict(pccb_payload)

    _write_json(scenario_dir / "action_intent.json", payload)
    _write_json(scenario_dir / "pccb.json", pccb.to_dict())
    intent_record_path = _write_intent_record_artifact(
        scenario_dir,
        source="incident-simulator-technical",
        intent=intent,
        context=mint_context,
        decision=decision,
        pccb=pccb,
        prohibited_actions=("protected_resource.write", "protected_resource.delete"),
        abort_conditions=("audience_mismatch", "action_hash_mismatch", "intent_expired"),
        blast_radius_limits={
            "max_resource_targets": {
                "value": 1,
                "summary": "The delegated read may touch only one protected resource.",
            },
        },
    )
    _write_portable_counterfactual_execution(
        scenario_dir,
        intent=intent,
        presented_pccb_id=pccb.pccb_id,
        request_id=f"req_unprotected_{scenario_name.replace('-', '_')}",
    )

    sdk = VerifierSDK(build_local_proof_signer())
    verify_context = sdk.build_context(
        request_id=f"req_verify_{scenario_name.replace('-', '_')}",
        audience=verification_audience,
        now=verification_now,
        scope_capabilities=pccb.scope.capabilities,
        parameter_constraints=pccb.scope.parameter_constraints,
        resource_selectors=pccb.scope.resource_selectors,
    )
    counterfactual = SimulationPerspective(
        key="without_execution_edge",
        basis="counterfactual",
        status="would_execute",
        summary="Counterfactual: if the endpoint trusted upstream allow state instead of verifying at execution time, the request would reach the side effect path unchecked.",
    )
    try:
        verified = sdk.verify(intent=intent, pccb=pccb, context=verify_context)
        response = HelloWorldProtectedResource().handle(verified)
        _write_json(
            scenario_dir / "verification_result.json",
            {
                "status": "verified",
                "request_id": verified.context.request_id,
                "audience": verified.context.audience.to_dict(),
                "pccb_id": verified.pccb.pccb_id,
                "action_hash": verified.pccb.action_hash.to_dict(),
                "protected_resource_response": response,
            },
        )
        perspectives = (
            counterfactual,
            SimulationPerspective(
                key="proof_verifier_only",
                basis="observed",
                status="would_verify",
                summary="Observed: the proof pair verified successfully for the intended audience, time window, and action hash.",
            ),
            SimulationPerspective(
                key="protected_endpoint_runtime",
                basis="observed",
                status="executed",
                summary="Observed: the protected resource executed only after the verifier accepted the bound proof.",
            ),
            SimulationPerspective(
                key="action_intent_record",
                basis="observed",
                status="recorded_execution",
                summary="Observed: the Action Intent, PCCB, and successful execution result are persisted as inspectable artifacts for later evidence lookup.",
            ),
        )
        return SimulationScenarioResult(
            name=scenario_name,
            status="verified",
            summary="Portable proof verified and the protected resource executed locally.",
            artifact_dir=str(scenario_dir),
            perspectives=perspectives,
            lesson="The happy path stays inspectable: proof-bound execution gives you both execution and evidence, not just a side effect.",
            details={
                "pccb_id": verified.pccb.pccb_id,
                "intent_id": verified.intent.intent_id,
                "intent_record_path": intent_record_path,
            },
        )
    except RefusalException as exc:
        refusal = RefusalFactory(refusal_id_factory=lambda: f"rfsl_sim_{scenario_name.replace('-', '_')}").create_from_exception(
            exc,
            occurred_at=verify_context.now,
            intent=intent,
            context=verify_context,
            pccb_id=pccb.pccb_id,
            action_hash=pccb.action_hash,
        )
        _write_json(scenario_dir / "refusal.json", refusal.to_dict())
        refusal_reason = {
            "audience-mismatch": "Audience binding turned a wrong-endpoint execution attempt into a deterministic refusal before side effects.",
            "action-hash-mismatch": "Action-hash binding turned a mutated request into a deterministic refusal before side effects.",
            "expired-proof": "Expiry enforcement turned a stale proof into a deterministic refusal before side effects.",
        }.get(scenario_name, "Protected-endpoint verification blocked the request before side effects.")
        perspectives = (
            counterfactual,
            SimulationPerspective(
                key="proof_verifier_only",
                basis="observed",
                status="would_refuse",
                summary=f"Observed: proof verification rejected the request with {refusal.reason_code}.",
            ),
            SimulationPerspective(
                key="protected_endpoint_runtime",
                basis="observed",
                status="refused",
                summary=f"Observed: the protected endpoint refused the request before any side effect with {refusal.reason_code}.",
            ),
            SimulationPerspective(
                key="action_intent_record",
                basis="observed",
                status="recorded_refusal",
                summary="Observed: the Action Intent and Refusal artifacts preserve the blocked attempt for incident review and evidence lookup.",
            ),
        )
        return SimulationScenarioResult(
            name=scenario_name,
            status="refused",
            summary=f"Portable proof verification failed with {refusal.reason_code}.",
            artifact_dir=str(scenario_dir),
            refusal_code=refusal.reason_code,
            perspectives=perspectives,
            lesson=refusal_reason,
            details={
                "category": refusal.category,
                "message": refusal.message,
                "intent_record_path": intent_record_path,
            },
        )


def _simulate_replay_refused(scenario_dir: Path) -> SimulationScenarioResult:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    receipt_counter = {"value": 0}

    def next_receipt_id() -> str:
        receipt_counter["value"] += 1
        return f"rcpt_sim_replay_{receipt_counter['value']:04d}"

    payload = {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": "intent_sim_replay_001",
        "issued_at": format_timestamp(now),
        "expires_at": format_timestamp(now + timedelta(minutes=5)),
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
        request_id="req_sim_replay_001",
        audience=AudienceRef(type="service", id="protected-endpoint"),
        scope_capabilities=("refund.execute",),
        now=now,
        facts={"risk_level": "normal"},
    )
    signer = build_local_proof_signer()
    outcome_writer = JsonArtifactOutcomeWriter(scenario_dir / "outcomes")
    escrow = build_sqlite_capability_escrow(scenario_dir / "state" / "escrow.sqlite3")
    replay_protector = ReplayProtector(SqliteReplayStore(scenario_dir / "state" / "replay.sqlite3"))
    middleware = ProtectedEndpointMiddleware(
        proof_verifier=PCCBVerifier(signer),
        escrow=escrow,
        receipt_factory=ReceiptFactory(receipt_id_factory=next_receipt_id),
        refusal_factory=RefusalFactory(refusal_id_factory=lambda: "rfsl_sim_replay_001"),
        outcome_writer=outcome_writer,
        replay_protector=replay_protector,
    )
    kernel = ProtectedExecutionKernel(
        intake=ActionIntentIntakeService(),
        policy_engine=PolicyEngine(
            hard_rules=HardRuleEngine((IntentChronologyHardRule(), IntentTtlHardRule(), CapabilityScopeHardRule())),
            tenant_workflow_rules=TenantWorkflowRuleLayer(
                tenant_rules={
                    "tenant_alpha": (
                        TenantWorkflowRule(
                            rule_id="tenant_alpha.refund.allow",
                            outcome="allow",
                            summary="The tenant workflow authorizes this action.",
                            reason_code="WORKFLOW_ALLOW",
                            capabilities=("refund.execute",),
                            required_fact_values={"risk_level": "normal"},
                        ),
                    )
                }
            ),
        ),
        pccb_minter=PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="local_kernel", display_name="Local Kernel"),
            pccb_id_factory=lambda: "pccb_sim_replay_001",
            nonce_factory=lambda: "nonce-sim-replay-00000001",
        ),
        escrow=middleware.escrow,
        middleware=middleware,
        receipt_factory=middleware.receipt_factory,
        refusal_factory=middleware.refusal_factory,
        outcome_writer=outcome_writer,
        escrow_id_factory=lambda: "esc_sim_replay_001",
    )

    admission = kernel.submit_intent(payload, context)
    if admission.intent is None or admission.pccb is None or admission.receipt is None:
        raise RuntimeError("replay simulation failed to create an allow-path admission result")

    sdk = VerifierSDK(signer)
    proof_only_context = sdk.build_context(
        request_id="req_sim_replay_verify",
        audience=context.audience,
        now=context.now,
        scope_capabilities=admission.pccb.scope.capabilities,
        parameter_constraints=admission.pccb.scope.parameter_constraints,
        resource_selectors=admission.pccb.scope.resource_selectors,
    )
    proof_only_first = sdk.verify(intent=admission.intent, pccb=admission.pccb, context=proof_only_context)
    proof_only_second = sdk.verify(intent=admission.intent, pccb=admission.pccb, context=proof_only_context)
    _write_json(
        scenario_dir / "proof_only_verification.json",
        {
            "first_verification": {
                "request_id": proof_only_first.context.request_id,
                "pccb_id": proof_only_first.pccb.pccb_id,
            },
            "second_verification": {
                "request_id": proof_only_second.context.request_id,
                "pccb_id": proof_only_second.pccb.pccb_id,
            },
            "summary": "Proof-only verification accepts the same PCCB twice because replay defense is not encoded in the signature alone.",
        },
    )
    _write_replay_counterfactual_execution(scenario_dir)

    request = kernel.build_execution_request(intent=admission.intent, pccb=admission.pccb, context=context)
    first = kernel.execute(request, lambda _request: {"external_reference": "exec_sim_001"})
    duplicate = kernel.execute(request, lambda _request: {"external_reference": "exec_sim_002"})

    _write_json(scenario_dir / "action_intent.json", payload)
    _write_json(scenario_dir / "pccb.json", admission.pccb.to_dict())
    _write_json(scenario_dir / "decision_receipt.json", admission.receipt.to_dict())
    intent_record_path = _write_intent_record_artifact(
        scenario_dir,
        source="incident-simulator-technical",
        intent=admission.intent,
        context=context,
        decision=admission.decision,
        pccb=admission.pccb,
        receipt=admission.receipt,
        prohibited_actions=("refund.duplicate_execution",),
        abort_conditions=("duplicate_replay_detected",),
        blast_radius_limits={
            "max_side_effects": {
                "value": 1,
                "summary": "A single-use delegated refund may execute at most once.",
            },
        },
    )
    if first.receipt is not None:
        _write_json(scenario_dir / "execution_receipt.json", first.receipt.to_dict())
    if duplicate.refusal is not None:
        _write_json(scenario_dir / "replay_refusal.json", duplicate.refusal.to_dict())
    if duplicate.receipt is not None:
        _write_json(scenario_dir / "replay_refused_receipt.json", duplicate.receipt.to_dict())

    if duplicate.refusal is None:
        raise RuntimeError("replay simulation did not produce a duplicate replay refusal")
    perspectives = (
        SimulationPerspective(
            key="without_execution_edge",
            basis="counterfactual",
            status="would_execute_twice",
            summary="Counterfactual: without execution-edge replay enforcement, the same proof-bearing request could drive two side effects.",
        ),
        SimulationPerspective(
            key="proof_verifier_only",
            basis="observed",
            status="would_verify_twice",
            summary="Observed: proof verification alone accepted the same PCCB twice. Replay defense is not a signature property.",
        ),
        SimulationPerspective(
            key="protected_endpoint_runtime",
            basis="observed",
            status="first_execution_then_refused",
            summary=f"Observed: the protected endpoint executed once and refused the duplicate with {duplicate.refusal.reason_code}.",
        ),
        SimulationPerspective(
            key="action_intent_record",
            basis="observed",
            status="recorded_refusal",
            summary="Observed: the Action Intent, first execution Receipt, and replay Refusal show exactly which attempt succeeded and which duplicate was blocked.",
        ),
    )
    return SimulationScenarioResult(
        name="replay-refused",
        status="refused",
        summary="Duplicate execution was refused by the replay layer.",
        artifact_dir=str(scenario_dir),
        refusal_code=duplicate.refusal.reason_code,
        receipt_id=duplicate.receipt.receipt_id if duplicate.receipt is not None else None,
        perspectives=perspectives,
        lesson="Replay protection is a runtime property. Proof alone verifies intent, but only the protected endpoint with replay state prevents duplicate execution.",
        details={
            "first_execution_receipt": first.receipt.receipt_id if first.receipt is not None else None,
            "intent_record_path": intent_record_path,
        },
    )


def export_local_runtime_bundle(
    runtime_dir: str | Path | None = None,
    *,
    output_path: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    paths = resolve_local_runtime_paths(runtime_dir)
    if not paths.runtime_manifest_path.exists():
        raise ValueError("local runtime manifest is missing; run `actenon up` before exporting a bundle")

    target = (
        Path(output_path).resolve()
        if output_path is not None
        else (paths.bundles_root / f"actenon-local-runtime{LOCAL_RUNTIME_BUNDLE_EXTENSION}").resolve()
    )
    if target.exists():
        if not force:
            raise ValueError(f"bundle output already exists at {target}; pass --force to replace it")
        _ensure_removed(target)

    bundle_manifest = _build_bundle_manifest(paths)

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix.lower() in {".zip", LOCAL_RUNTIME_BUNDLE_EXTENSION}:
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bundle_manifest.json", json.dumps(bundle_manifest, indent=2, sort_keys=True) + "\n")
            for relative in bundle_manifest["entries"]:
                source = paths.root / relative
                if source.is_file():
                    archive.write(source, relative)
                elif source.is_dir():
                    for child in sorted(source.rglob("*")):
                        if child.is_file():
                            archive.write(child, child.relative_to(paths.root).as_posix())
        kind = "zip"
    else:
        target.mkdir(parents=True, exist_ok=True)
        _write_json(target / "bundle_manifest.json", bundle_manifest)
        for relative in bundle_manifest["entries"]:
            source = paths.root / relative
            destination = target / relative
            if source.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            elif source.is_dir():
                shutil.copytree(source, destination, dirs_exist_ok=True)
        kind = "directory"

    return {
        "ok": True,
        "kind": kind,
        "output": str(target),
        "bundle_manifest": bundle_manifest,
    }


def verify_local_runtime_bundle(bundle_path: str | Path) -> dict[str, Any]:
    target = Path(bundle_path).resolve()
    if not target.exists():
        raise ValueError(f"bundle path does not exist: {target}")

    if target.is_dir():
        return _verify_local_runtime_bundle_root(target, bundle_path=target, bundle_kind="directory")

    if target.suffix.lower() not in {".zip", LOCAL_RUNTIME_BUNDLE_EXTENSION} or not zipfile.is_zipfile(target):
        raise ValueError("bundle path must be a directory, .zip archive, or .actenon archive")

    with TemporaryDirectory() as tempdir:
        extraction_root = Path(tempdir) / "bundle"
        with zipfile.ZipFile(target) as archive:
            archive.extractall(extraction_root)
        return _verify_local_runtime_bundle_root(extraction_root, bundle_path=target, bundle_kind="archive")


def _bundle_entries(paths: LocalRuntimePaths) -> list[str]:
    entries = ["runtime_manifest.json", "SUMMARY.txt"]
    if paths.runtime_service_manifest_path.exists():
        entries.append(paths.runtime_service_manifest_path.relative_to(paths.root).as_posix())
    for relative in ("labs", "artifacts", "state", "simulations", "keys"):
        path = paths.root / relative
        if path.exists():
            entries.append(relative)
    return entries


def _build_bundle_manifest(paths: LocalRuntimePaths) -> dict[str, Any]:
    entries = _bundle_entries(paths)
    file_hashes = _bundle_file_hashes(paths, entries)
    evidence_chains = _bundle_evidence_chains(paths)
    decision_records = _bundle_decision_records(paths)
    return {
        "format": LOCAL_RUNTIME_BUNDLE_FORMAT,
        "artifact_class": "portable_execution_evidence_bundle",
        "file_extension": LOCAL_RUNTIME_BUNDLE_EXTENSION,
        "exported_at": format_timestamp(_utc_now()),
        "runtime_format": LOCAL_RUNTIME_FORMAT,
        "runtime_root": str(paths.root),
        "entries": entries,
        "file_hashes": file_hashes,
        "evidence_chains": evidence_chains,
        "decision_records": decision_records,
        "summary": {
            "entry_count": len(entries),
            "file_count": len(file_hashes),
            "proof_chain_count": len(evidence_chains),
            "executed_chain_count": sum(1 for item in evidence_chains if item["outcome"]["outcome"] == "executed"),
            "refused_chain_count": sum(1 for item in evidence_chains if item["outcome"]["type"] == "refusal"),
            "decision_record_count": len(decision_records),
        },
        "integrity_model": {
            "file_hashes": True,
            "canonical_artifact_digests": True,
            "attestation_of_origin": False,
            "notes": [
                "This bundle is portable execution evidence with internal digest checks.",
                "In v1 it is tamper-evident relative to the bundle manifest, not a cryptographic attestation of origin.",
                "A malicious party that rewrites both artifacts and manifest can still produce a different internally consistent bundle.",
            ],
        },
    }


def _bundle_file_hashes(paths: LocalRuntimePaths, entries: list[str]) -> dict[str, dict[str, str]]:
    file_hashes: dict[str, dict[str, str]] = {}
    for relative in _bundle_file_entries(paths, entries):
        file_hashes[relative] = {
            "algorithm": "sha-256",
            "canonicalization": BUNDLE_FILE_HASH_CANONICALIZATION,
            "value": _sha256_file_hex(paths.root / relative),
        }
    return file_hashes


def _bundle_file_entries(paths: LocalRuntimePaths, entries: list[str]) -> list[str]:
    """Collect the list of files to hash for the bundle manifest.

    SQLite WAL/SHM files (``*.sqlite3-wal``, ``*.sqlite3-shm``) are
    excluded because they are ephemeral and may be checkpointed/deleted
    between export and verify, causing false hash mismatches. The
    authoritative integrity surface is the SQLite database file itself
    (``*.sqlite3``), which is stable once checkpointed.
    """
    resolved: list[str] = []
    seen: set[str] = set()
    for relative in entries:
        source = paths.root / relative
        if source.is_file():
            normalized = source.relative_to(paths.root).as_posix()
            if normalized not in seen and not _is_ephemeral_sqlite_file(normalized):
                seen.add(normalized)
                resolved.append(normalized)
            continue
        if source.is_dir():
            for child in sorted(source.rglob("*")):
                if not child.is_file():
                    continue
                normalized = child.relative_to(paths.root).as_posix()
                if normalized in seen:
                    continue
                if _is_ephemeral_sqlite_file(normalized):
                    continue
                seen.add(normalized)
                resolved.append(normalized)
    return resolved


def _is_ephemeral_sqlite_file(relative_path: str) -> bool:
    """Return True for SQLite WAL/SHM/journal files that are ephemeral
    and may not exist or may have different content between export and
    verify. These files are excluded from the bundle hash manifest.
    """
    lower = relative_path.lower()
    return (
        lower.endswith(".sqlite3-wal")
        or lower.endswith(".sqlite3-shm")
        or lower.endswith(".sqlite3-journal")
        or lower.endswith(".db-wal")
        or lower.endswith(".db-shm")
        or lower.endswith(".db-journal")
    )


def _bundle_evidence_chains(paths: LocalRuntimePaths) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    for scenario_dir in _bundle_candidate_chain_dirs(paths):
        action_intent_path = scenario_dir / "action_intent.json"
        pccb_path = scenario_dir / "pccb.json"
        execution_receipt_path = scenario_dir / "execution_receipt.json"
        receipt_path = scenario_dir / "receipt.json"
        decision_receipt_path = scenario_dir / "decision_receipt.json"
        refusal_path = scenario_dir / "refusal.json"
        if not action_intent_path.exists() or not pccb_path.exists():
            continue

        intent = ActionIntentIntakeService().parse(_load_json(action_intent_path))
        pccb = PCCB.from_dict(_load_json(pccb_path))
        outcome_path: Path | None = None
        outcome_payload: dict[str, Any] | None = None
        outcome_type: str | None = None
        outcome_id: str | None = None
        outcome_value: str | None = None
        supporting_receipt: dict[str, Any] | None = None

        if refusal_path.exists():
            refusal = Refusal.from_dict(_load_json(refusal_path))
            outcome_path = refusal_path
            outcome_payload = refusal.to_dict()
            outcome_type = "refusal"
            outcome_id = refusal.refusal_id
            outcome_value = refusal.reason_code
            if receipt_path.exists():
                receipt = Receipt.from_dict(_load_json(receipt_path))
                supporting_receipt = {
                    "path": receipt_path.relative_to(paths.root).as_posix(),
                    "receipt_id": receipt.receipt_id,
                    "outcome": receipt.outcome,
                    "digest": build_artifact_digest(receipt).to_dict(),
                }
            elif decision_receipt_path.exists():
                decision_receipt = Receipt.from_dict(_load_json(decision_receipt_path))
                supporting_receipt = {
                    "path": decision_receipt_path.relative_to(paths.root).as_posix(),
                    "receipt_id": decision_receipt.receipt_id,
                    "outcome": decision_receipt.outcome,
                    "digest": build_artifact_digest(decision_receipt).to_dict(),
                }
        elif execution_receipt_path.exists():
            receipt = Receipt.from_dict(_load_json(execution_receipt_path))
            outcome_path = execution_receipt_path
            outcome_payload = receipt.to_dict()
            outcome_type = "receipt"
            outcome_id = receipt.receipt_id
            outcome_value = receipt.outcome
        elif receipt_path.exists():
            receipt = Receipt.from_dict(_load_json(receipt_path))
            if receipt.outcome == "executed":
                outcome_path = receipt_path
                outcome_payload = receipt.to_dict()
                outcome_type = "receipt"
                outcome_id = receipt.receipt_id
                outcome_value = receipt.outcome

        if outcome_path is None or outcome_payload is None or outcome_type is None or outcome_id is None or outcome_value is None:
            continue

        chain_entry: dict[str, Any] = {
            "chain_id": f"pccb:{pccb.pccb_id}",
            "directory": scenario_dir.relative_to(paths.root).as_posix(),
            "intent": {
                "path": action_intent_path.relative_to(paths.root).as_posix(),
                "intent_id": intent.intent_id,
                "digest": build_artifact_digest(intent).to_dict(),
            },
            "pccb": {
                "path": pccb_path.relative_to(paths.root).as_posix(),
                "pccb_id": pccb.pccb_id,
                "digest": build_artifact_digest(pccb).to_dict(),
            },
            "outcome": {
                "type": outcome_type,
                "path": outcome_path.relative_to(paths.root).as_posix(),
                "id": outcome_id,
                "outcome": outcome_value,
                "digest": build_artifact_digest(outcome_payload).to_dict(),
            },
            "action_hash": pccb.action_hash.to_dict(),
        }
        if supporting_receipt is not None:
            chain_entry["supporting_receipt"] = supporting_receipt
        intent_record_path = scenario_dir / "intent_record.json"
        if intent_record_path.exists():
            chain_entry["intent_record"] = {
                "path": intent_record_path.relative_to(paths.root).as_posix(),
                "sha256": _sha256_file_hex(intent_record_path),
            }
        chains.append(chain_entry)
    return chains


def _bundle_decision_records(paths: LocalRuntimePaths) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for scenario_dir in _bundle_candidate_chain_dirs(paths):
        action_intent_path = scenario_dir / "action_intent.json"
        pccb_path = scenario_dir / "pccb.json"
        intent_record_path = scenario_dir / "intent_record.json"
        decision_receipt_path = scenario_dir / "decision_receipt.json"
        if not action_intent_path.exists() or pccb_path.exists() or not decision_receipt_path.exists():
            continue
        intent = ActionIntentIntakeService().parse(_load_json(action_intent_path))
        receipt = Receipt.from_dict(_load_json(decision_receipt_path))
        record: dict[str, Any] = {
            "directory": scenario_dir.relative_to(paths.root).as_posix(),
            "intent": {
                "path": action_intent_path.relative_to(paths.root).as_posix(),
                "intent_id": intent.intent_id,
                "digest": build_artifact_digest(intent).to_dict(),
            },
            "decision_receipt": {
                "path": decision_receipt_path.relative_to(paths.root).as_posix(),
                "receipt_id": receipt.receipt_id,
                "outcome": receipt.outcome,
                "digest": build_artifact_digest(receipt).to_dict(),
            },
        }
        if intent_record_path.exists():
            record["intent_record"] = {
                "path": intent_record_path.relative_to(paths.root).as_posix(),
                "sha256": _sha256_file_hex(intent_record_path),
            }
        records.append(record)
    return records


def _bundle_candidate_chain_dirs(paths: LocalRuntimePaths) -> tuple[Path, ...]:
    roots = (
        paths.labs_root,
        paths.runtime_requests_root,
        paths.simulations_root,
    )
    directories: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for action_intent_path in sorted(root.rglob("action_intent.json")):
            scenario_dir = action_intent_path.parent
            if scenario_dir in seen:
                continue
            seen.add(scenario_dir)
            directories.append(scenario_dir)
    return tuple(directories)


def _verify_local_runtime_bundle_root(root: Path, *, bundle_path: Path, bundle_kind: str) -> dict[str, Any]:
    manifest_path = root / "bundle_manifest.json"
    if not manifest_path.exists():
        raise ValueError("bundle_manifest.json is missing from the bundle")
    manifest = _load_json(manifest_path)
    if manifest.get("format") != LOCAL_RUNTIME_BUNDLE_FORMAT:
        raise ValueError(f"unsupported bundle format: {manifest.get('format')!r}")

    file_hashes = manifest.get("file_hashes", {})
    if not isinstance(file_hashes, dict):
        raise ValueError("bundle manifest file_hashes must be an object")
    errors: list[str] = []
    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("bundle manifest entries must be a list")
    for relative in entries:
        if not isinstance(relative, str):
            errors.append("bundle manifest contains a non-string entry path")
            continue
        path = root / relative
        if path.exists():
            continue
        # Zip archives do not reliably preserve empty directory roots.
        # File hashes and declared chain paths are the authoritative integrity surface.
        continue

    if not file_hashes:
        errors.append("Bundle manifest does not declare any file hashes.")
    verified_file_count = 0
    for relative, digest_payload in sorted(file_hashes.items()):
        if not isinstance(relative, str):
            errors.append("bundle manifest file_hashes contains a non-string path")
            continue
        target = root / relative
        if not target.exists() or not target.is_file():
            errors.append(f"Missing hashed file: {relative}")
            continue
        expected = digest_payload.get("value")
        actual = _sha256_file_hex(target)
        if expected != actual:
            errors.append(f"File hash mismatch: {relative}")
            continue
        verified_file_count += 1

    verified_chain_count = 0
    evidence_chains = manifest.get("evidence_chains", [])
    if not isinstance(evidence_chains, list):
        raise ValueError("bundle manifest evidence_chains must be a list")
    for chain in evidence_chains:
        chain_errors = _verify_bundle_chain(root, chain)
        if chain_errors:
            errors.extend(chain_errors)
            continue
        verified_chain_count += 1

    verified_decision_count = 0
    decision_records = manifest.get("decision_records", [])
    if not isinstance(decision_records, list):
        raise ValueError("bundle manifest decision_records must be a list")
    if not evidence_chains and not decision_records:
        errors.append("Bundle manifest does not declare any proof chains or decision records.")
    for record in decision_records:
        record_errors = _verify_bundle_decision_record(root, record)
        if record_errors:
            errors.extend(record_errors)
            continue
        verified_decision_count += 1

    ok = not errors
    return {
        "ok": ok,
        "bundle": str(bundle_path),
        "kind": bundle_kind,
        "format": manifest["format"],
        "artifact_class": manifest.get("artifact_class", "portable_execution_evidence_bundle"),
        "summary": {
            "verified_file_count": verified_file_count,
            "declared_file_count": len(file_hashes),
            "verified_proof_chain_count": verified_chain_count,
            "declared_proof_chain_count": len(evidence_chains),
            "verified_decision_record_count": verified_decision_count,
            "declared_decision_record_count": len(decision_records),
        },
        "integrity_model": manifest.get("integrity_model", {}),
        "errors": errors,
    }


def _verify_bundle_chain(root: Path, chain: Any) -> list[str]:
    if not isinstance(chain, dict):
        return ["bundle chain entry is not an object"]

    errors: list[str] = []
    intent = _verify_bundle_artifact(
        root,
        chain.get("intent"),
        expected_type="intent",
        loader=lambda path: ActionIntentIntakeService().parse(_load_json(path)),
        identifier_field="intent_id",
    )
    if isinstance(intent, list):
        return intent
    pccb = _verify_bundle_artifact(
        root,
        chain.get("pccb"),
        expected_type="pccb",
        loader=lambda path: PCCB.from_dict(_load_json(path)),
        identifier_field="pccb_id",
    )
    if isinstance(pccb, list):
        return pccb

    outcome = chain.get("outcome")
    if not isinstance(outcome, dict):
        return ["bundle chain outcome is missing or not an object"]
    outcome_type = outcome.get("type")
    if outcome_type == "receipt":
        receipt = _verify_bundle_artifact(
            root,
            outcome,
            expected_type="receipt",
            loader=lambda path: Receipt.from_dict(_load_json(path)),
            identifier_field="id",
        )
        if isinstance(receipt, list):
            return receipt
        _bundle_verify_pccb_matches_intent(errors, intent, pccb)
        _bundle_verify_receipt_links(errors, receipt, intent=intent, pccb=pccb)
    elif outcome_type == "refusal":
        refusal = _verify_bundle_artifact(
            root,
            outcome,
            expected_type="refusal",
            loader=lambda path: Refusal.from_dict(_load_json(path)),
            identifier_field="id",
        )
        if isinstance(refusal, list):
            return refusal
        supporting_receipt = None
        if isinstance(chain.get("supporting_receipt"), dict):
            supporting_receipt_result = _verify_bundle_artifact(
                root,
                chain.get("supporting_receipt"),
                expected_type="supporting_receipt",
                loader=lambda path: Receipt.from_dict(_load_json(path)),
                identifier_field="receipt_id",
            )
            if isinstance(supporting_receipt_result, list):
                errors.extend(supporting_receipt_result)
            else:
                supporting_receipt = supporting_receipt_result
        _bundle_verify_refusal_links(errors, refusal, intent=intent, pccb=pccb, receipt=supporting_receipt)
    else:
        errors.append(f"unsupported bundle chain outcome type: {outcome_type!r}")
        return errors

    declared_action_hash = chain.get("action_hash", {})
    if not isinstance(declared_action_hash, dict) or declared_action_hash.get("value") != pccb.action_hash.value:
        errors.append(f"Action hash mismatch in chain {chain.get('chain_id', '<unknown>')}")
    return errors


def _verify_bundle_decision_record(root: Path, record: Any) -> list[str]:
    if not isinstance(record, dict):
        return ["bundle decision record entry is not an object"]
    intent = _verify_bundle_artifact(
        root,
        record.get("intent"),
        expected_type="intent",
        loader=lambda path: ActionIntentIntakeService().parse(_load_json(path)),
        identifier_field="intent_id",
    )
    if isinstance(intent, list):
        return intent
    receipt = _verify_bundle_artifact(
        root,
        record.get("decision_receipt"),
        expected_type="decision_receipt",
        loader=lambda path: Receipt.from_dict(_load_json(path)),
        identifier_field="receipt_id",
    )
    if isinstance(receipt, list):
        return receipt
    errors: list[str] = []
    if receipt.intent_id != intent.intent_id:
        errors.append(f"Decision receipt intent_id does not match Action Intent in {record.get('directory', '<unknown>')}")
    return errors


def _verify_bundle_artifact(
    root: Path,
    payload: Any,
    *,
    expected_type: str,
    loader,
    identifier_field: str,
) -> Any | list[str]:
    if not isinstance(payload, dict):
        return [f"bundle {expected_type} entry is missing or not an object"]
    path_value = payload.get("path")
    if not isinstance(path_value, str):
        return [f"bundle {expected_type} entry is missing a path"]
    target = root / path_value
    if not target.exists():
        return [f"bundle {expected_type} artifact is missing: {path_value}"]
    artifact = loader(target)
    declared_identifier = payload.get(identifier_field)
    actual_identifier = _bundle_artifact_identifier(artifact, identifier_field)
    if declared_identifier != actual_identifier:
        return [f"bundle {expected_type} identifier mismatch for {path_value}"]
    declared_digest = payload.get("digest")
    if not isinstance(declared_digest, dict):
        return [f"bundle {expected_type} entry is missing a digest"]
    actual_digest = build_artifact_digest(artifact).to_dict()
    if declared_digest != actual_digest:
        return [f"bundle {expected_type} digest mismatch for {path_value}"]
    return artifact


def _bundle_artifact_identifier(artifact: Any, identifier_field: str) -> str | None:
    if identifier_field == "intent_id":
        return getattr(artifact, "intent_id", None)
    if identifier_field == "pccb_id":
        return getattr(artifact, "pccb_id", None)
    if identifier_field == "receipt_id":
        return getattr(artifact, "receipt_id", None)
    if identifier_field == "id":
        if isinstance(artifact, Refusal):
            return artifact.refusal_id
        if isinstance(artifact, Receipt):
            return artifact.receipt_id
    return None


def _bundle_verify_pccb_matches_intent(errors: list[str], intent: Any, pccb: PCCB) -> None:
    if pccb.intent_id is not None and pccb.intent_id != intent.intent_id:
        errors.append(f"PCCB intent_id does not match Action Intent for {pccb.pccb_id}")
    if pccb.tenant != intent.tenant:
        errors.append(f"PCCB tenant does not match Action Intent for {pccb.pccb_id}")
    if pccb.subject != intent.requester:
        errors.append(f"PCCB subject does not match Action Intent for {pccb.pccb_id}")
    if pccb.action != intent.action:
        errors.append(f"PCCB action does not match Action Intent for {pccb.pccb_id}")
    if pccb.target != intent.target:
        errors.append(f"PCCB target does not match Action Intent for {pccb.pccb_id}")
    expected_action_hash = sha256_hex(build_action_hash_input(intent))
    if pccb.action_hash.value != expected_action_hash:
        errors.append(f"PCCB action hash does not match the canonical Action Intent for {pccb.pccb_id}")


def _bundle_verify_receipt_links(errors: list[str], receipt: Receipt, *, intent: Any, pccb: PCCB) -> None:
    if receipt.intent_id != intent.intent_id:
        errors.append(f"Receipt intent_id does not match Action Intent for {receipt.receipt_id}")
    if receipt.tenant != intent.tenant:
        errors.append(f"Receipt tenant does not match Action Intent for {receipt.receipt_id}")
    if receipt.subject != intent.requester:
        errors.append(f"Receipt subject does not match Action Intent for {receipt.receipt_id}")
    if receipt.action != intent.action:
        errors.append(f"Receipt action does not match Action Intent for {receipt.receipt_id}")
    if receipt.target != intent.target:
        errors.append(f"Receipt target does not match Action Intent for {receipt.receipt_id}")
    if receipt.correlation is None or receipt.correlation.pccb_id != pccb.pccb_id:
        errors.append(f"Receipt correlation.pccb_id does not match PCCB for {receipt.receipt_id}")


def _bundle_verify_refusal_links(
    errors: list[str],
    refusal: Refusal,
    *,
    intent: Any,
    pccb: PCCB,
    receipt: Receipt | None,
) -> None:
    if refusal.intent_id != intent.intent_id:
        errors.append(f"Refusal intent_id does not match Action Intent for {refusal.refusal_id}")
    if refusal.correlation is None or refusal.correlation.pccb_id != pccb.pccb_id:
        errors.append(f"Refusal correlation.pccb_id does not match PCCB for {refusal.refusal_id}")
    if receipt is not None and receipt.correlation is not None and receipt.correlation.refusal_id is not None:
        if receipt.correlation.refusal_id != refusal.refusal_id:
            errors.append(f"Supporting receipt refusal link does not match refusal for {refusal.refusal_id}")


def generate_local_hmac_key_material(
    *,
    output_path: str | Path,
    key_id: str,
    secret_bytes: int = 32,
) -> dict[str, Any]:
    if secret_bytes < 16:
        raise ValueError("secret_bytes must be at least 16")
    payload = {
        "format": LOCAL_HMAC_KEY_FORMAT,
        "generated_at": format_timestamp(_utc_now()),
        "mode": "single-node-local-proof",
        "algorithm": "HS256",
        "key_id": key_id,
        "secret_encoding": "base64url",
        "secret": _b64url_encode(token_bytes(secret_bytes)),
        "publishable": False,
        "supports": ["proof_sign", "proof_verify"],
        "notes": [
            "This file is for local single-node issuer and verifier use.",
            "It is not publishable through key discovery because symmetric secrets are not public verification material.",
        ],
    }
    target = Path(output_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_json(target, payload)
    return payload


def _load_json(path: Path) -> dict[str, Any]:
    payload = loads_no_duplicate_keys(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return payload


def _load_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return _load_json(path)


def _http_json_status(url: str) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            payload = loads_no_duplicate_keys(response.read())
            if not isinstance(payload, dict):
                raise ValueError("HTTP JSON response must contain an object")
            return response.status, payload
    except urllib.error.HTTPError as exc:
        payload = loads_no_duplicate_keys(exc.read())
        if not isinstance(payload, dict):
            raise ValueError("HTTP JSON response must contain an object")
        return exc.code, payload
