from __future__ import annotations

import argparse
import json
import sys
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Sequence

from actenon.api.intake import ActionIntentIntakeService
from actenon.core import ContractValidationError, RefusalException
from actenon.core.json import loads_no_duplicate_keys
from actenon.coverage_matrix import DEFAULT_EVIDENCE_PATH, render_coverage_matrix_text, run_consequential_action_matrix
from actenon.evidence import (
    EvidenceQuery,
    EvidenceQueryService,
    EvidenceResult,
    EvidenceVerdict,
    JsonArtifactActionIntentStore,
    JsonArtifactPCCBStore,
)
from actenon.execution_graph import (
    HttpExecutionGraphClient,
    build_execution_anchor_hash,
    create_execution_anchor_from_receipt,
    create_execution_anchor_from_refusal,
)
from actenon.local_runtime import (
    DEFAULT_LOCAL_RUNTIME_DIR,
    bootstrap_local_runtime,
    doctor_local_runtime,
    export_local_runtime_bundle,
    generate_local_hmac_key_material,
    simulate_local_runtime,
    verify_local_runtime_bundle,
)
from actenon.local_runtime_server import start_local_runtime_services
from actenon.models import ActionIntent, ActionSpec, PCCB, Receipt, Refusal, TargetRef, TenantRef
from actenon.models.contracts import AudienceRef, PartyRef, format_timestamp, parse_timestamp
from actenon.preflight import PreflightDecision, PreflightEngine
from actenon.proof import (
    ALLOWED_DISCOVERY_KEY_STATUSES,
    ALLOWED_DISCOVERY_KEY_USES,
    LOCAL_PROOF_KEY_ID,
    SignatureVerifier,
    build_key_discovery_document,
    build_local_proof_signer,
)
from actenon.receipts import (
    JsonArtifactReceiptStore,
    JsonArtifactRefusalStore,
    OutcomeAttestationService,
    OutcomeAttestationVerificationError,
    ReceiptAttestationV2Alpha1,
    RefusalAttestationV2Alpha1,
    RefusalFactory,
)
from actenon.scanner import (
    ScanReport,
    ScannerOptions,
    render_badge_markdown,
    render_markdown_report,
    scan_artifact_pair,
    scan_local,
    scan_replay_harness,
    scan_repository,
)
from actenon.verifier import VerifierSDK


def _load_json(path: str) -> dict[str, Any]:
    target = Path(path)
    payload = loads_no_duplicate_keys(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON artifact must be a JSON object")
    return payload


def _load_intent(path: str) -> ActionIntent:
    return ActionIntentIntakeService().parse(_load_json(path))


def _load_pccb(path: str) -> PCCB:
    return PCCB.from_dict(_load_json(path))


def _load_receipt(path: str) -> Receipt:
    return Receipt.from_dict(_load_json(path))


def _load_refusal(path: str) -> Refusal:
    return Refusal.from_dict(_load_json(path))


def _load_preflight_decision(path: str) -> PreflightDecision:
    return PreflightDecision.from_dict(_load_json(path))


def _load_receipt_attestation(path: str) -> ReceiptAttestationV2Alpha1:
    return ReceiptAttestationV2Alpha1.from_dict(_load_json(path))


def _load_refusal_attestation(path: str) -> RefusalAttestationV2Alpha1:
    return RefusalAttestationV2Alpha1.from_dict(_load_json(path))


def _write_json(path: str, payload: dict[str, Any]) -> Path:
    output_path = Path(path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path


def _resolve_verification_time(raw: str, pccb: PCCB) -> datetime:
    if raw == "now":
        return datetime.now(timezone.utc)
    if raw == "pccb-issued-at":
        return pccb.issued_at
    if raw == "pccb-not-before":
        return pccb.not_before
    return parse_timestamp(raw, "verification_time")


def _resolve_signature_verifier(pccb: PCCB, verifier_name: str) -> SignatureVerifier:
    if verifier_name == "local":
        signature_verifier = build_local_proof_signer()
        if pccb.signature.key_id != signature_verifier.key_id:
            raise ValueError(
                f"local verifier selected but proof key_id is {pccb.signature.key_id!r}, expected {signature_verifier.key_id!r}"
            )
        return signature_verifier
    if verifier_name == "auto":
        if pccb.signature.key_id == LOCAL_PROOF_KEY_ID:
            return build_local_proof_signer()
        raise ValueError(
            "no local verifier is available for this proof key_id; use an environment-specific verifier outside the OSS CLI"
        )
    raise ValueError(f"unsupported verifier mode: {verifier_name}")


def _resolve_attestation_signer(signer_name: str):
    if signer_name == "local":
        return build_local_proof_signer()
    raise ValueError(f"unsupported outcome-attestation signer mode: {signer_name}")


def _resolve_attestation_verifier(key_id: str, verifier_name: str) -> SignatureVerifier:
    if verifier_name == "local":
        signature_verifier = build_local_proof_signer()
        if key_id != signature_verifier.key_id:
            raise ValueError(
                f"local verifier selected but attestation key_id is {key_id!r}, expected {signature_verifier.key_id!r}"
            )
        return signature_verifier
    if verifier_name == "auto":
        if key_id == LOCAL_PROOF_KEY_ID:
            return build_local_proof_signer()
        raise ValueError(
            "no local verifier is available for this attestation key_id; use an environment-specific verifier outside the OSS CLI"
        )
    raise ValueError(f"unsupported outcome-attestation verifier mode: {verifier_name}")


def _resolve_audience(raw: str | None, *, audience_type: str) -> AudienceRef:
    if raw is None:
        raise ContractValidationError("audience is required for verifier context; use --audience '<type>:<id>' or a bare id with --audience-type.")
    if ":" in raw:
        parsed_type, parsed_id = raw.split(":", 1)
    else:
        parsed_type, parsed_id = audience_type, raw
    if not parsed_type or not parsed_id:
        raise ContractValidationError("audience must be '<type>:<id>' or a non-empty id with --audience-type.")
    return AudienceRef(type=parsed_type, id=parsed_id)


def _resolve_party(raw: str, *, default_type: str = "service") -> PartyRef:
    if ":" in raw:
        parsed_type, parsed_id = raw.split(":", 1)
    else:
        parsed_type, parsed_id = default_type, raw
    if not parsed_type or not parsed_id:
        raise ContractValidationError("party reference must be '<type>:<id>' or a non-empty id.")
    return PartyRef(type=parsed_type, id=parsed_id)


def _resolve_optional_timestamp(raw: str | None, field_name: str) -> datetime | None:
    if raw is None or raw == "now":
        return None
    return parse_timestamp(raw, field_name)


def _build_cli_refusal(
    *,
    request_id: str,
    occurred_at: datetime,
    exc: RefusalException,
    intent: ActionIntent | None,
    context,
    pccb: PCCB | None,
) -> Refusal:
    return RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}").create_from_exception(
        exc,
        occurred_at=occurred_at,
        intent=intent,
        context=context,
        pccb_id=pccb.pccb_id if pccb is not None else None,
    )


def _emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


def _print_runtime_up_result(*, args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if args.json:
        _emit_json({"ok": True, "mode": "bootstrap-only" if args.bootstrap_only else "serve", "runtime": payload})
        return
    if args.bootstrap_only:
        print("Local runtime bootstrapped.")
        print(f"Runtime root: {payload['runtime_root']}")
        print(
            f"Trust mode: {payload['trust_mode']['type']} "
            f"({payload['trust_mode']['algorithm']}, key_id={payload['trust_mode']['key_id']})"
        )
        print(f"Local proof lab: {payload['paths']['local_proof']}")
        print(f"Portable verifier lab: {payload['paths']['portable_local_proof']}")
        print("Next commands:")
        print(f"- actenon up --runtime-dir {payload['runtime_root']}")
        print(f"- actenon doctor --runtime-dir {payload['runtime_root']}")
        print(f"- actenon simulate --runtime-dir {payload['runtime_root']} --scenario all")
        print(f"- actenon bundle export --runtime-dir {payload['runtime_root']}")
        sys.stdout.flush()
        return

    print("Actenon local runtime is serving.")
    print(f"Runtime root: {payload['runtime_root']}")
    print(f"Issuer URL: {payload['issuer_url']}")
    print(f"POST intents: {payload['intents_url']}")
    print(f"Issuer id: {payload['issuer']['type']}:{payload['issuer']['id']}")
    print("Supported capabilities: " + ", ".join(payload["supported_capabilities"]))
    print(f"Health: {payload['health_url']}")
    print(f"Key discovery: {payload['key_discovery_url']}")
    print(f"Key discovery alias: {payload['key_discovery_alias_url']}")
    print(f"Key publication file: {payload['key_discovery_document_path']}")
    if payload["trace_viewer_url"] is not None:
        print(f"Trace viewer: {payload['trace_viewer_url']}")
    else:
        print(f"Trace viewer: {payload['trace_viewer_status']}")
    print(f"Artifact directory: {payload['artifact_dir']}")
    print(f"Replay store: {payload['replay_store_path']}")
    print(f"Escrow store: {payload['escrow_store_path']}")
    print(f"Key discovery status: {'available' if payload['key_discovery_available'] else 'unavailable'}")
    print(f"Key discovery note: {payload['key_discovery_summary']}")
    print(f"Next step: {payload['next_step_example']}")
    print("Press Ctrl-C to stop.")
    sys.stdout.flush()


def _print_doctor_report(*, args: argparse.Namespace, report) -> None:
    payload = report.to_dict()
    if args.json:
        _emit_json(payload)
        return
    print("Local runtime doctor.")
    print(f"Runtime root: {payload['runtime_root']}")
    print(f"Mode: {payload['mode']}")
    print(f"Overall status: {payload['overall_status']}")
    print(
        "Summary: "
        f"{payload['summary']['ok']} ok, "
        f"{payload['summary']['fail']} fail, "
        f"{payload['summary']['total']} total"
    )
    print("Checks:")
    for check in payload["checks"]:
        print(f"- [{check['status'].upper()}] {check['name']}")
        print(f"  {check['summary']}")
        if check["details"]:
            print(f"  Details: {json.dumps(check['details'], sort_keys=True)}")
        if check.get("remediation"):
            print(f"  Remediation: {check['remediation']}")
    if payload["action_items"]:
        print("Action items:")
        for item in payload["action_items"]:
            print(f"- {item['name']}: {item['remediation']}")


def _print_simulation_report(*, args: argparse.Namespace, report) -> None:
    payload = report.to_dict()
    if args.json:
        _emit_json(payload)
        return
    print("Local incident simulation.")
    print(f"Runtime root: {payload['runtime_root']}")
    print(f"Mode: {payload['mode']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Succeeded: {'yes' if payload['succeeded'] else 'no'}")
    if payload.get("framing_note"):
        print(f"Framing: {payload['framing_note']}")
    if payload["takeaways"]:
        print("Takeaways:")
        for item in payload["takeaways"]:
            print(f"- {item}")
    print("Results:")
    for result in payload["results"]:
        label = result.get("title") or result["name"]
        print(f"- {label}: {result['status'].upper()}")
        print(f"  {result['summary']}")
        if result.get("lesson"):
            print(f"  Lesson: {result['lesson']}")
        print(f"  Artifacts: {result['artifact_dir']}")
        if result.get("summary_path") is not None:
            print(f"  Incident summary: {result['summary_path']}")
        if result["refusal_code"] is not None:
            print(f"  Refusal code: {result['refusal_code']}")
        if result["receipt_id"] is not None:
            print(f"  Receipt: {result['receipt_id']}")
        if result.get("perspectives"):
            print("  Perspectives:")
            for perspective in result["perspectives"]:
                print(
                    f"  - {perspective['key']} [{perspective['basis']}]: "
                    f"{perspective['status'].upper()}"
                )
                print(f"    {perspective['summary']}")
        if result.get("details", {}).get("trace_viewer_follow_up"):
            trace = result["details"]["trace_viewer_follow_up"]
            print(f"  Trace viewer: {trace['summary']}")
            if trace.get("url"):
                print(f"  Trace viewer URL: {trace['url']}")


def _print_bundle_export_result(*, args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if args.json:
        _emit_json(payload)
        return
    print("Portable execution evidence bundle exported.")
    print(f"Output: {payload['output']}")
    print(f"Kind: {payload['kind']}")
    print(f"Class: {payload['bundle_manifest']['artifact_class']}")
    print(f"Format: {payload['bundle_manifest']['format']}")
    print(
        "Summary: "
        f"{payload['bundle_manifest']['summary']['proof_chain_count']} proof chain(s), "
        f"{payload['bundle_manifest']['summary']['decision_record_count']} decision record(s), "
        f"{payload['bundle_manifest']['summary']['file_count']} hashed file(s)"
    )
    print("Integrity:")
    print("- portable execution evidence with manifest-linked file hashes")
    print("- canonical artifact digests for Action Intent, PCCB, and Receipt or Refusal")
    print("- not an attestation of origin in v1")
    print("Next step:")
    print(f"- actenon bundle verify {payload['output']}")


def _print_bundle_verify_result(*, args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if args.json:
        _emit_json(payload)
        return
    if payload["ok"]:
        print("Portable execution evidence bundle verified.")
    else:
        print("Portable execution evidence bundle verification failed.")
    print(f"Bundle: {payload['bundle']}")
    print(f"Kind: {payload['kind']}")
    print(f"Format: {payload['format']}")
    print(f"Class: {payload['artifact_class']}")
    print(
        "Summary: "
        f"{payload['summary']['verified_file_count']}/{payload['summary']['declared_file_count']} hashed file(s) verified, "
        f"{payload['summary']['verified_proof_chain_count']}/{payload['summary']['declared_proof_chain_count']} proof chain(s) verified, "
        f"{payload['summary']['verified_decision_record_count']}/{payload['summary']['declared_decision_record_count']} decision record(s) verified"
    )
    print("Trust limits:")
    print("- portable execution evidence and internal tamper checks are present")
    print("- v1 bundles are not cryptographic attestations of origin")
    if payload["errors"]:
        print("Errors:")
        for error in payload["errors"]:
            print(f"- {error}")


def _print_keys_generate_result(*, args: argparse.Namespace, output_path: str, payload: dict[str, Any]) -> None:
    if args.json:
        _emit_json({"ok": True, "output": output_path, "key": payload})
        return
    print("Local key material written.")
    print(f"Output: {output_path}")
    print(f"Mode: {payload['mode']}")
    print(f"Algorithm: {payload['algorithm']}")
    print(f"Key id: {payload['key_id']}")
    print("This key is for single-node local issuer/verifier use and is not publishable through key discovery.")


def _print_verify_proof_success(*, args: argparse.Namespace, verified, verification_time: datetime) -> None:
    if args.json:
        _emit_json(
            {
                "ok": True,
                "intent_id": verified.intent.intent_id,
                "pccb_id": verified.pccb.pccb_id,
                "request_id": verified.context.request_id,
                "audience": verified.context.audience.to_dict(),
                "verified_at": format_timestamp(verification_time),
            }
        )
        return
    print("Proof verified.")
    print(f"Intent: {verified.intent.intent_id}")
    print(f"PCCB: {verified.pccb.pccb_id}")
    print(f"Audience: {verified.context.audience.type}:{verified.context.audience.id}")
    print(f"Verified at: {format_timestamp(verification_time)}")


def _print_verify_proof_failure(*, args: argparse.Namespace, refusal: Refusal) -> None:
    if args.json:
        _emit_json({"ok": False, "refusal": refusal.to_dict()})
        return
    print("Proof verification failed.")
    print(f"Category: {refusal.category}")
    print(f"Code: {refusal.reason_code}")
    print(f"Message: {refusal.message}")
    if refusal.intent_id is not None:
        print(f"Intent: {refusal.intent_id}")
    if refusal.correlation is not None and refusal.correlation.pccb_id is not None:
        print(f"PCCB: {refusal.correlation.pccb_id}")
    if refusal.audience is not None:
        print(f"Audience: {refusal.audience.type}:{refusal.audience.id}")
    print(f"Refused at: {format_timestamp(refusal.refused_at)}")
    if refusal.details:
        print("Details:")
        print(json.dumps(refusal.details, indent=2, sort_keys=True))


def _print_attestation_written(
    *,
    args: argparse.Namespace,
    artifact_kind: str,
    artifact_id: str,
    output_path: Path,
    attestation: ReceiptAttestationV2Alpha1 | RefusalAttestationV2Alpha1,
) -> None:
    if args.json:
        _emit_json(
            {
                "ok": True,
                "artifact_kind": artifact_kind,
                "artifact_id": artifact_id,
                "attestation_id": attestation.attestation_id,
                "output": str(output_path),
                "signature": attestation.signature.to_dict(),
            }
        )
        return
    print(f"{artifact_kind.title()} attested.")
    print(f"{artifact_kind.title()}: {artifact_id}")
    print(f"Attestation: {attestation.attestation_id}")
    print(f"Output: {output_path}")
    print(f"Signature key: {attestation.signature.key_id}")


def _print_attestation_verification_success(
    *,
    args: argparse.Namespace,
    artifact_kind: str,
    artifact_id: str,
    attestation: ReceiptAttestationV2Alpha1 | RefusalAttestationV2Alpha1,
) -> None:
    if args.json:
        _emit_json(
            {
                "ok": True,
                "artifact_kind": artifact_kind,
                "artifact_id": artifact_id,
                "attestation_id": attestation.attestation_id,
                "signature": attestation.signature.to_dict(),
            }
        )
        return
    print(f"{artifact_kind.title()} attestation verified.")
    print(f"{artifact_kind.title()}: {artifact_id}")
    print(f"Attestation: {attestation.attestation_id}")
    print(f"Signature key: {attestation.signature.key_id}")


def _print_attestation_verification_failure(
    *,
    args: argparse.Namespace,
    artifact_kind: str,
    attestation_id: str,
    error: Exception,
) -> None:
    if args.json:
        _emit_json(
            {
                "ok": False,
                "artifact_kind": artifact_kind,
                "attestation_id": attestation_id,
                "error": str(error),
            }
        )
        return
    print(f"{artifact_kind.title()} attestation verification failed.")
    print(f"Attestation: {attestation_id}")
    print(f"Error: {error}")


def _print_scan_report(*, args: argparse.Namespace, report: ScanReport) -> None:
    report_mode = getattr(args, "report_mode", "executive")
    if getattr(args, "report_json", None):
        Path(args.report_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_json).write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if getattr(args, "report_markdown", None):
        Path(args.report_markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_markdown).write_text(render_markdown_report(report, mode=report_mode), encoding="utf-8")
    if getattr(args, "badge_output", None):
        Path(args.badge_output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.badge_output).write_text(render_badge_markdown(report) + "\n", encoding="utf-8")

    if args.json:
        _emit_json(report.to_dict())
        return
    if getattr(args, "markdown", False):
        print(render_markdown_report(report, mode=report_mode), end="")
        return

    print("Actenon Agentic Action Scan.")
    print(f"Mode: {report.mode}")
    print(f"Target: {report.target}")
    print(f"Overall status: {report.overall_status}")
    payload = report.to_dict()
    print(f"Runtime-source candidate paths: {payload['runtime_source_candidate_paths']}")
    print(f"Additional test/example/context findings: {payload['additional_test_example_context_findings']} (downgraded by context)")
    print(f"Consequence class: {payload['consequence_class_label']}")
    print(f"Gating status: {payload['gating_status']}")
    print(f"Runtime reachability: {payload['runtime_reachability']}")
    print(f"Vulnerability claim: {'yes' if payload['vulnerability_claim'] else 'no'}")
    print(f"Manual review required: {'yes' if payload['manual_review_required'] else 'no'}")
    print(f"Confidence: {payload['confidence']}")
    print(f"Categories detected: {', '.join(payload['categories_detected']) or 'none'}")
    print("Actenon Scanner maps agent authority. It does not accuse your repo of being vulnerable.")
    print("This is not a vulnerability severity rating. It is a consequence-class map of candidate action surfaces found by static analysis.")
    print("Runtime reachability, exploitability, production exposure and business impact are not proven by this scan.")
    print(f"Scanner version: {report.scanner_version}")
    print(f"Registry version: {report.registry_version}")
    print(f"Summary: {report.summary}")
    print("Checks:")
    for check in report.checks:
        print(f"- {check.label}: {check.status.upper()}")
        print(f"  {check.summary}")
        if check.reason_code is not None:
            print(f"  Reason code: {check.reason_code}")
    if report.findings:
        print("Findings:")
        for finding in report.findings:
            location = ""
            if finding.path is not None:
                location = f" ({finding.path}"
                if finding.line is not None:
                    location += f":{finding.line}"
                location += ")"
            finding_payload = finding.to_dict()
            print(f"- [{finding_payload['consequence_class_label']}] {finding.title}{location}")
            print(f"  {finding.summary}")
            print(
                "  "
                f"Category: {finding.category}; "
                f"surface: {finding.surface_id or finding.category}; "
                f"path-type: {finding.path_type}; "
                f"primitive: {finding.primitive or 'unknown'}; "
                f"agent-control: {finding.agent_control_context}; "
                f"confidence: {finding.confidence}; "
                f"gating: {finding_payload['gating_status']}; "
                f"runtime reachability: {finding_payload['runtime_reachability']}; "
                "vulnerability claim: no"
            )
            if finding.control_gaps:
                print(f"  Control gaps: {', '.join(finding.control_gaps)}")
    if report.remediation_steps:
        print("Remediation:")
        for step in report.remediation_steps:
            print(f"- {step}")
    if getattr(args, "badge", False):
        print("Badge:")
        print(render_badge_markdown(report))


def _print_preflight_decision(*, args: argparse.Namespace, decision: PreflightDecision) -> None:
    if args.json:
        _emit_json(decision.to_dict())
        return
    print("Actenon Preflight decision.")
    print(f"Decision: {decision.decision_id}")
    print(f"Outcome: {decision.outcome}")
    print(f"Reason code: {decision.reason_code}")
    print(f"Risk: {decision.risk_level}")
    print(f"Summary: {decision.summary}")
    if decision.required_evidence:
        print("Required evidence:")
        for item in decision.required_evidence:
            print(f"- {item}")
    if decision.required_approvals:
        print("Required approvals:")
        for item in decision.required_approvals:
            print(f"- {item}")
    if decision.unmet_requirements:
        print("Unmet requirements:")
        for requirement in decision.unmet_requirements:
            print(f"- {requirement.reason_code}: {requirement.summary}")
            for evidence_key in requirement.evidence_keys:
                example = json.dumps(evidence_key.example, sort_keys=True)
                print(
                    "  "
                    f"evidence.{evidence_key.key} ({evidence_key.value_type}), "
                    f"example: {example}"
                )
    if decision.matched_rules:
        print("Matched rules:")
        for item in decision.matched_rules:
            print(f"- {item}")


MCP_HERO_TOOL_CAPABILITIES: dict[str, str] = {
    "filesystem.delete": "infrastructure.delete",
    "database.migrate": "migration.apply",
    "iam.grant": "iam.permission.grant",
    "data.export": "data.export",
    "payment.release": "payment.release",
}


def _mcp_wrapper_function_name(tool_name: str) -> str:
    return tool_name.replace(".", "_").replace("-", "_").replace(":", "_").replace("/", "_")


def _mcp_wrap_payload(*, args: argparse.Namespace) -> dict[str, Any]:
    capability = args.capability or MCP_HERO_TOOL_CAPABILITIES[args.tool]
    function_name = _mcp_wrapper_function_name(args.tool)
    wrapper = "\n".join(
        [
            "from mcp.server.fastmcp import Context",
            "from actenon.adapters.mcp import protected_mcp_tool",
            "",
            "",
            f"@mcp.tool(name={args.tool!r})",
            "@protected_mcp_tool(",
            "    gate,",
            "    action_builder=build_action_intent,",
            f"    audience={args.audience!r},",
            ")",
            f"def {function_name}(target: str, ctx: Context):",
            '    """Domain fields only; proof arrives in MCP request metadata."""',
            "    return simulated_or_real_domain_operation(target)",
        ]
    )
    return {
        "ok": True,
        "tool_name": args.tool,
        "capability": capability,
        "audience": args.audience,
        "flow": [
            "agent",
            "MCP tool call",
            "Actenon proof gate",
            "tool executes/refuses",
            "VAR emitted",
        ],
        "required_inputs": ["domain fields only"],
        "runtime_injected": [
            "proof via request metadata key 'actenon'",
            "optional Preflight evidence via the same request metadata",
            "FastMCP Context, hidden from the model-facing schema",
        ],
        "proof_gate_steps": [
            "build the exact Action Intent from validated domain arguments",
            "read PCCB from out-of-band MCP request metadata",
            "verify exact proof binding for the MCP tool audience",
            "run Preflight or endpoint policy",
            "acquire a Credential Broker reference only after allow",
            "execute or refuse",
            "emit a canonical Receipt, and a Refusal linked by a refused Receipt when blocked",
        ],
        "python_wrapper": wrapper,
        "local_demo": f"python3 -m examples.mcp_server_protected_tool.demo --tool {args.tool} --scenario allow",
        "hosted_dependency": False,
        "cloud_dependency": False,
    }


def _print_mcp_wrap_result(*, args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if args.json:
        _emit_json(payload)
        return
    print("Actenon MCP wrapper.")
    print(f"Tool: {payload['tool_name']}")
    print(f"Capability: {payload['capability']}")
    print(f"Audience: {payload['audience']}")
    print("Flow: " + " -> ".join(payload["flow"]))
    print("Required tool inputs:")
    for item in payload["required_inputs"]:
        print(f"- {item}")
    print("Runtime-injected inputs:")
    for item in payload["runtime_injected"]:
        print(f"- {item}")
    print("Proof gate steps:")
    for item in payload["proof_gate_steps"]:
        print(f"- {item}")
    print("Python wrapper:")
    print(payload["python_wrapper"])
    print("Local demo:")
    print(payload["local_demo"])


def _load_preflight_evidence(args: argparse.Namespace) -> dict[str, Any]:
    raw_json = getattr(args, "evidence_json", None)
    raw_file = getattr(args, "evidence_file", None)
    if raw_json is None and raw_file is None:
        return {}
    payload = loads_no_duplicate_keys(raw_json) if raw_json is not None else _load_json(raw_file)
    if not isinstance(payload, dict):
        raise ValueError("preflight evidence context must be a JSON object")
    return payload


def _build_preflight_simulation_intent() -> ActionIntent:
    issued_at = parse_timestamp("2026-01-01T12:00:00Z", "issued_at")
    return ActionIntent(
        intent_id="intent_preflight_infra_delete_demo",
        issued_at=issued_at,
        expires_at=parse_timestamp("2026-01-01T12:10:00Z", "expires_at"),
        tenant=TenantRef(tenant_id="tenant_demo"),
        requester=PartyRef(type="agent", id="infra-agent"),
        action=ActionSpec(
            name="database.delete",
            capability="database.delete",
            parameters={"environment": "production", "resource_id": "prod-db-primary"},
        ),
        target=TargetRef(resource_type="database", resource_id="prod-db-primary", selectors={"environment": "production"}),
        justification="Simulate a production database delete preflight check.",
    )


def _resolve_outcomes_root(artifact_root: Path) -> Path | None:
    if (artifact_root / "receipts").is_dir() or (artifact_root / "refusals").is_dir():
        return artifact_root
    if (artifact_root / "outcomes").is_dir():
        return artifact_root / "outcomes"
    return None


def _build_evidence_query_service(artifacts_dir: str) -> EvidenceQueryService:
    artifact_root = Path(artifacts_dir).resolve()
    intent_store = JsonArtifactActionIntentStore(artifact_root)
    pccb_store = JsonArtifactPCCBStore(artifact_root)
    outcomes_root = _resolve_outcomes_root(artifact_root)
    receipt_store = JsonArtifactReceiptStore(outcomes_root) if outcomes_root is not None else None
    refusal_store = JsonArtifactRefusalStore(outcomes_root) if outcomes_root is not None else None
    return EvidenceQueryService(
        intent_store=intent_store,
        pccb_store=pccb_store,
        receipt_store=receipt_store,
        refusal_store=refusal_store,
    )


def _build_evidence_query_from_args(args: argparse.Namespace) -> EvidenceQuery:
    return EvidenceQuery(
        receipt_id=args.receipt_id,
        pccb_id=args.pccb_id,
        intent_id=args.intent_id,
        action_hash=args.action_hash,
    )


def _evidence_query_selector(args: argparse.Namespace) -> tuple[str, str]:
    for key in ("receipt_id", "pccb_id", "intent_id", "action_hash"):
        value = getattr(args, key)
        if value is not None:
            return key, value
    raise AssertionError("evidence query selector is required")


def _hash_verification_status(result: EvidenceResult) -> str:
    if result.verdict == EvidenceVerdict.HASH_MISMATCH:
        return "failed"
    if result.verdict in (EvidenceVerdict.VERIFIED_EXECUTION, EvidenceVerdict.VERIFIED_REFUSAL):
        return "passed"
    return "not_confirmed"


def _evidence_result_payload(*, args: argparse.Namespace, result: EvidenceResult) -> dict[str, Any]:
    query_kind, query_value = _evidence_query_selector(args)
    return {
        "ok": result.verdict in (EvidenceVerdict.VERIFIED_EXECUTION, EvidenceVerdict.VERIFIED_REFUSAL),
        "verdict": result.verdict.value,
        "summary": result.summary,
        "query": {"kind": query_kind, "value": query_value},
        "artifacts_dir": str(Path(args.artifacts_dir).resolve()),
        "receipt_id": result.receipt_id,
        "refusal_id": result.refusal_id,
        "pccb_id": result.pccb_id,
        "intent_id": result.intent_id,
        "action_hash": result.action_hash,
        "chain_length": result.chain_depth,
        "hash_verification": _hash_verification_status(result),
        "details": result.details,
    }


def _print_evidence_query_result(*, args: argparse.Namespace, result: EvidenceResult) -> None:
    payload = _evidence_result_payload(args=args, result=result)
    if args.json:
        _emit_json(payload)
        return

    print("Execution evidence query.")
    print(f"Source: {payload['artifacts_dir']}")
    print(f"Query: {payload['query']['kind']}={payload['query']['value']}")
    print(f"Verdict: {payload['verdict']}")
    print(f"Summary: {payload['summary']}")
    print(f"Chain length: {payload['chain_length']}")
    print(f"Hash verification: {payload['hash_verification']}")
    if payload["receipt_id"] is not None:
        print(f"Receipt: {payload['receipt_id']}")
    if payload["refusal_id"] is not None:
        print(f"Refusal: {payload['refusal_id']}")
    if payload["pccb_id"] is not None:
        print(f"PCCB: {payload['pccb_id']}")
    if payload["intent_id"] is not None:
        print(f"Intent: {payload['intent_id']}")
    if payload["action_hash"] is not None:
        print(f"Action hash: {payload['action_hash']}")
    if payload["details"]:
        print("Details:")
        print(json.dumps(payload["details"], indent=2, sort_keys=True))


def _load_public_jwk(*, path: str | None, raw_json: str | None) -> dict[str, Any]:
    if path is not None:
        return _load_json(path)
    if raw_json is None:
        raise ValueError("either --public-jwk-file or --public-jwk-json is required")
    parsed = loads_no_duplicate_keys(raw_json)
    if not isinstance(parsed, dict):
        raise ValueError("public JWK input must be a JSON object")
    return parsed


def _build_key_discovery_document_from_args(args: argparse.Namespace) -> dict[str, Any]:
    public_key_jwk = _load_public_jwk(path=args.public_jwk_file, raw_json=args.public_jwk_json)
    issuer = PartyRef(
        type=args.issuer_type,
        id=args.issuer_id,
        display_name=args.issuer_display_name,
    )
    published_at = parse_timestamp(args.published_at, "published_at") if args.published_at else datetime.now(timezone.utc)
    not_before = parse_timestamp(args.not_before, "not_before") if args.not_before else None
    expires_at = parse_timestamp(args.expires_at, "expires_at") if args.expires_at else None
    revoked_at = parse_timestamp(args.revoked_at, "revoked_at") if args.revoked_at else None
    return build_key_discovery_document(
        issuer=issuer,
        origin=args.issuer_origin,
        key_id=args.key_id,
        algorithm=args.algorithm,
        public_key_jwk=public_key_jwk,
        published_at=published_at,
        status=args.status,
        use=args.use or "proof_issuance",
        cache_max_age_seconds=args.cache_max_age_seconds,
        not_before=not_before,
        expires_at=expires_at,
        revoked_at=revoked_at,
        replaced_by=args.replaced_by,
        revocation_reason=args.revocation_reason,
    )


def _parse_cli_metadata(items: Sequence[str] | None) -> dict[str, str]:
    if not items:
        return {}
    metadata: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"metadata entry {item!r} must use key=value form")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("metadata key must be non-empty")
        metadata[key] = value
    return metadata


def _resolve_anchor_pccb(*, args: argparse.Namespace, correlation_pccb_id: str | None, artifact_path: str) -> PCCB:
    if args.pccb:
        pccb = _load_pccb(args.pccb)
        if correlation_pccb_id is not None and pccb.pccb_id != correlation_pccb_id:
            raise ValueError(f"--pccb artifact has id {pccb.pccb_id!r}, expected {correlation_pccb_id!r}")
        return pccb

    sibling_pccb = Path(artifact_path).resolve().parent / "pccb.json"
    if sibling_pccb.exists():
        pccb = _load_pccb(str(sibling_pccb))
        if correlation_pccb_id is None or pccb.pccb_id == correlation_pccb_id:
            return pccb

    if args.artifacts_dir and correlation_pccb_id is not None:
        pccb = JsonArtifactPCCBStore(Path(args.artifacts_dir).resolve()).get_pccb(correlation_pccb_id)
        if pccb is not None:
            return pccb

    if correlation_pccb_id is None:
        raise ValueError("artifact does not include correlation.pccb_id; supply --pccb explicitly")
    raise ValueError(
        f"could not resolve PCCB {correlation_pccb_id!r}; pass --pccb explicitly or point --artifacts-dir at a local artifact root"
    )


def _graph_anchor_payload(*, args: argparse.Namespace, anchor, anchor_hash: str, source_kind: str, source_path: str) -> dict[str, Any]:
    publish_requested = bool(args.publish_url and not args.dry_run)
    return {
        "ok": True,
        "source": {"kind": source_kind, "path": str(Path(source_path).resolve())},
        "anchor_hash": anchor_hash,
        "anchor": anchor.to_dict(),
        "publication": {
            "requested": publish_requested,
            "mode": "http" if publish_requested else "none",
            "endpoint_url": args.publish_url if publish_requested else None,
        },
    }


def _print_graph_anchor_result(*, args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if args.json:
        _emit_json(payload)
        return
    print("Execution anchor created.")
    print(f"Source: {payload['source']['kind']} {payload['source']['path']}")
    print(f"Outcome: {payload['anchor']['outcome']}")
    print(f"Anchor hash: {payload['anchor_hash']}")
    if payload["publication"]["requested"]:
        print(f"Publication: requested (fire-and-forget) via {payload['publication']['endpoint_url']}")
    else:
        print("Publication: not requested")
    print("Anchor:")
    print(json.dumps(payload["anchor"], indent=2, sort_keys=True))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _compare_intent_fields(*, artifact_name: str, intent_id: str, tenant, subject, action, target, other_name: str, other_intent_id: str, other_tenant, other_subject, other_action, other_target) -> None:
    _require(intent_id == other_intent_id, f"{artifact_name} intent_id does not match {other_name}")
    _require(tenant == other_tenant, f"{artifact_name} tenant does not match {other_name}")
    _require(subject == other_subject, f"{artifact_name} subject does not match {other_name}")
    _require(action == other_action, f"{artifact_name} action does not match {other_name}")
    _require(target == other_target, f"{artifact_name} target does not match {other_name}")


def _verify_receipt_links(receipt: Receipt, *, intent: ActionIntent | None, pccb: PCCB | None, refusal: Refusal | None) -> None:
    if intent is not None:
        _compare_intent_fields(
            artifact_name="receipt",
            intent_id=receipt.intent_id,
            tenant=receipt.tenant,
            subject=receipt.subject,
            action=receipt.action,
            target=receipt.target,
            other_name="action intent",
            other_intent_id=intent.intent_id,
            other_tenant=intent.tenant,
            other_subject=intent.requester,
            other_action=intent.action,
            other_target=intent.target,
        )
    if pccb is not None:
        if pccb.intent_id is not None:
            _require(receipt.intent_id == pccb.intent_id, "receipt intent_id does not match PCCB intent_id")
        _require(receipt.correlation is not None and receipt.correlation.pccb_id == pccb.pccb_id, "receipt correlation.pccb_id does not match PCCB")
        _compare_intent_fields(
            artifact_name="receipt",
            intent_id=receipt.intent_id,
            tenant=receipt.tenant,
            subject=receipt.subject,
            action=receipt.action,
            target=receipt.target,
            other_name="PCCB",
            other_intent_id=pccb.intent_id or receipt.intent_id,
            other_tenant=pccb.tenant,
            other_subject=pccb.subject,
            other_action=pccb.action,
            other_target=pccb.target,
        )
    if refusal is not None:
        if receipt.correlation is not None and receipt.correlation.refusal_id is not None:
            _require(receipt.correlation.refusal_id == refusal.refusal_id, "receipt correlation.refusal_id does not match refusal")
        else:
            _require(
                receipt.correlation is not None
                and refusal.correlation is not None
                and receipt.correlation.request_id == refusal.correlation.request_id,
                "receipt request_id does not match refusal request_id",
            )
        _require(receipt.intent_id == (refusal.intent_id or receipt.intent_id), "receipt intent_id does not match refusal")
        if receipt.reason_codes:
            _require(refusal.reason_code in receipt.reason_codes, "receipt reason_codes do not include reason_code")


def _verify_refusal_links(refusal: Refusal, *, intent: ActionIntent | None, pccb: PCCB | None, receipt: Receipt | None) -> None:
    if intent is not None:
        _require(refusal.intent_id == intent.intent_id, "refusal intent_id does not match action intent")
        if refusal.tenant is not None:
            _require(refusal.tenant == intent.tenant, "refusal tenant does not match action intent")
        if refusal.subject is not None:
            _require(refusal.subject == intent.requester, "refusal subject does not match action intent")
        if refusal.action is not None:
            _require(refusal.action == intent.action, "refusal action does not match action intent")
        if refusal.target is not None:
            _require(refusal.target == intent.target, "refusal target does not match action intent")
    if pccb is not None:
        _require(refusal.correlation is not None and refusal.correlation.pccb_id == pccb.pccb_id, "refusal correlation.pccb_id does not match PCCB")
        if refusal.intent_id is not None and pccb.intent_id is not None:
            _require(refusal.intent_id == pccb.intent_id, "refusal intent_id does not match PCCB intent_id")
    if receipt is not None:
        if receipt.correlation is not None and receipt.correlation.refusal_id is not None:
            _require(receipt.correlation.refusal_id == refusal.refusal_id, "receipt correlation.refusal_id does not match refusal")
        else:
            _require(
                receipt.correlation is not None
                and refusal.correlation is not None
                and receipt.correlation.request_id == refusal.correlation.request_id,
                "receipt request_id does not match refusal request_id",
            )
        _require(receipt.intent_id == (refusal.intent_id or receipt.intent_id), "receipt intent_id does not match refusal")
        if receipt.reason_codes:
            _require(refusal.reason_code in receipt.reason_codes, "receipt reason_codes do not include reason_code")


def _cmd_verify_proof(args: argparse.Namespace) -> int:
    intent: ActionIntent | None = None
    pccb: PCCB | None = None
    context = None
    verification_time = datetime.now(timezone.utc)

    try:
        intent = _load_intent(args.intent)
        pccb = _load_pccb(args.pccb)
        signature_verifier = _resolve_signature_verifier(pccb, args.signer)
        sdk = VerifierSDK(signature_verifier)
        verification_time = _resolve_verification_time(args.verification_time, pccb)
        context = sdk.build_context(
            request_id=args.request_id,
            audience=_resolve_audience(args.audience, audience_type=args.audience_type),
            now=verification_time,
            scope_capabilities=pccb.scope.capabilities,
            parameter_constraints=pccb.scope.parameter_constraints,
            resource_selectors=pccb.scope.resource_selectors,
        )
        verified = sdk.verify(intent=intent, pccb=pccb, context=context)
    except RefusalException as exc:
        refusal = _build_cli_refusal(
            request_id=args.request_id,
            occurred_at=verification_time,
            exc=exc,
            intent=intent,
            context=context,
            pccb=pccb,
        )
        _print_verify_proof_failure(args=args, refusal=refusal)
        return 1
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        refusal = _build_cli_refusal(
            request_id=args.request_id,
            occurred_at=verification_time,
            exc=ContractValidationError(str(exc)),
            intent=intent,
            context=context,
            pccb=pccb,
        )
        _print_verify_proof_failure(args=args, refusal=refusal)
        return 1

    _print_verify_proof_success(args=args, verified=verified, verification_time=verification_time)
    return 0


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    receipt = _load_receipt(args.receipt)
    intent = _load_intent(args.intent) if args.intent else None
    pccb = _load_pccb(args.pccb) if args.pccb else None
    refusal = _load_refusal(args.refusal) if args.refusal else None
    _verify_receipt_links(receipt, intent=intent, pccb=pccb, refusal=refusal)
    print("Receipt verified.")
    print(f"Receipt: {receipt.receipt_id}")
    print(f"Outcome: {receipt.outcome}")
    print(f"Intent: {receipt.intent_id}")
    if receipt.phase is not None:
        print(f"Phase: {receipt.phase}")
    return 0


def _cmd_verify_refusal(args: argparse.Namespace) -> int:
    refusal = _load_refusal(args.refusal)
    intent = _load_intent(args.intent) if args.intent else None
    pccb = _load_pccb(args.pccb) if args.pccb else None
    receipt = _load_receipt(args.receipt) if args.receipt else None
    _verify_refusal_links(refusal, intent=intent, pccb=pccb, receipt=receipt)
    print("Refusal verified.")
    print(f"Refusal: {refusal.refusal_id}")
    print(f"Category: {refusal.category}")
    print(f"Code: {refusal.reason_code}")
    return 0


def _cmd_attest_receipt(args: argparse.Namespace) -> int:
    receipt = _load_receipt(args.receipt)
    service = OutcomeAttestationService(
        signer=_resolve_attestation_signer(args.signer),
        issuer=_resolve_party(args.issuer),
    )
    attestation = service.attest_receipt(
        receipt,
        issued_at=_resolve_optional_timestamp(args.issued_at, "issued_at"),
    )
    output_path = _write_json(args.output, attestation.to_dict())
    _print_attestation_written(
        args=args,
        artifact_kind="receipt",
        artifact_id=receipt.receipt_id,
        output_path=output_path,
        attestation=attestation,
    )
    return 0


def _cmd_attest_refusal(args: argparse.Namespace) -> int:
    refusal = _load_refusal(args.refusal)
    service = OutcomeAttestationService(
        signer=_resolve_attestation_signer(args.signer),
        issuer=_resolve_party(args.issuer),
    )
    attestation = service.attest_refusal(
        refusal,
        issued_at=_resolve_optional_timestamp(args.issued_at, "issued_at"),
    )
    output_path = _write_json(args.output, attestation.to_dict())
    _print_attestation_written(
        args=args,
        artifact_kind="refusal",
        artifact_id=refusal.refusal_id,
        output_path=output_path,
        attestation=attestation,
    )
    return 0


def _cmd_verify_receipt_attestation(args: argparse.Namespace) -> int:
    attestation = _load_receipt_attestation(args.attestation)
    verifier = _resolve_attestation_verifier(attestation.signature.key_id, args.signer)
    service = OutcomeAttestationService(signer=verifier, issuer=attestation.issuer)
    try:
        receipt = service.verify_receipt_attestation(attestation, verifier=verifier)
    except OutcomeAttestationVerificationError as exc:
        _print_attestation_verification_failure(
            args=args,
            artifact_kind="receipt",
            attestation_id=attestation.attestation_id,
            error=exc,
        )
        return 1
    receipt_id = receipt.receipt_id if hasattr(receipt, "receipt_id") else str(receipt.get("receipt_id", "unknown-receipt"))
    _print_attestation_verification_success(
        args=args,
        artifact_kind="receipt",
        artifact_id=receipt_id,
        attestation=attestation,
    )
    return 0


def _cmd_verify_refusal_attestation(args: argparse.Namespace) -> int:
    attestation = _load_refusal_attestation(args.attestation)
    verifier = _resolve_attestation_verifier(attestation.signature.key_id, args.signer)
    service = OutcomeAttestationService(signer=verifier, issuer=attestation.issuer)
    try:
        refusal = service.verify_refusal_attestation(attestation, verifier=verifier)
    except OutcomeAttestationVerificationError as exc:
        _print_attestation_verification_failure(
            args=args,
            artifact_kind="refusal",
            attestation_id=attestation.attestation_id,
            error=exc,
        )
        return 1
    refusal_id = refusal.refusal_id if hasattr(refusal, "refusal_id") else str(refusal.get("refusal_id", "unknown-refusal"))
    _print_attestation_verification_success(
        args=args,
        artifact_kind="refusal",
        artifact_id=refusal_id,
        attestation=attestation,
    )
    return 0


def _cmd_conformance_run(args: argparse.Namespace) -> int:
    from actenon.conformance import CONFORMANCE_VERSION, VERIFIED_MARK

    package_root = Path(__file__).resolve().parent
    conformance_dir = package_root / "conformance"
    if not conformance_dir.exists():
        raise ValueError(f"conformance directory not found at {conformance_dir}")
    suite = unittest.defaultTestLoader.discover(
        str(conformance_dir),
        pattern="test_*.py",
        top_level_dir=str(package_root.parent),
    )
    print(f"Conformance version: {CONFORMANCE_VERSION}")
    stream = sys.stdout if args.verbose else StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2 if args.verbose else 1).run(suite)
    skipped = len(result.skipped)
    complete = result.wasSuccessful() and skipped == 0
    if not args.verbose:
        print(f"Conformance tests {'passed' if result.wasSuccessful() else 'failed'}.")
        print(f"Ran {result.testsRun} test(s).")
    print(f"Skipped: {skipped}.")
    if complete:
        print(f"Mark eligibility: {VERIFIED_MARK}")
    elif skipped:
        print(
            "Mark eligibility: INCOMPLETE "
            "(install required extras and run with no skipped checks)."
        )
    if args.require_complete and skipped:
        return 1
    return 0 if result.wasSuccessful() else 1


def _cmd_coverage_run(args: argparse.Namespace) -> int:
    result = run_consequential_action_matrix(evidence_path=args.output)
    if args.json:
        _emit_json(result.to_dict())
    else:
        print(render_coverage_matrix_text(result))
    return 0 if result.result == "PASS" else 1


def _scan_target_from_args(args: argparse.Namespace) -> str:
    scan_command = getattr(args, "scan_command", None)
    if scan_command is not None:
        return scan_command
    if args.target is not None:
        return args.target
    if args.intent or args.pccb or args.audience:
        return "artifact-pair"
    return "replay-harness"


def _cmd_scan(args: argparse.Namespace) -> int:
    if getattr(args, "json", False) and getattr(args, "markdown", False):
        raise ValueError("use either --json or --markdown, not both")
    target = _scan_target_from_args(args)

    if target in {"repo", "mcp", "endpoint"}:
        extensions: list[str] | None = None
        if getattr(args, "extensions", None):
            extensions = []
            for raw in args.extensions:
                extensions.extend(item.strip() for item in raw.split(",") if item.strip())
        progress_callback = (
            (lambda message: print(message, file=sys.stderr))
            if getattr(args, "progress", False)
            else None
        )
        options = ScannerOptions(
            exclude=tuple(getattr(args, "exclude", ()) or ()),
            include=tuple(getattr(args, "include", ()) or ()),
            extensions=tuple(extensions) if extensions else None,
            max_files=getattr(args, "max_files", None),
            max_file_size=getattr(args, "max_file_size", 1_000_000),
            timeout_seconds=getattr(args, "timeout_seconds", None),
            partial_report_on_timeout=getattr(args, "partial_report_on_timeout", False),
            progress_callback=progress_callback,
        )
        report = scan_repository(args.path, mode=target, options=options)
    elif target == "local":
        report = scan_local()
    elif target == "artifact-pair":
        missing = [flag for flag, value in (("--intent", args.intent), ("--pccb", args.pccb), ("--audience", args.audience)) if not value]
        if missing:
            raise ValueError("artifact-pair scan requires " + ", ".join(missing))

        intent = _load_intent(args.intent)
        pccb = _load_pccb(args.pccb)
        signature_verifier = _resolve_signature_verifier(pccb, args.signer)
        sdk = VerifierSDK(signature_verifier)
        verification_time = _resolve_verification_time(args.verification_time, pccb)
        audience = _resolve_audience(args.audience, audience_type=args.audience_type)
        report = scan_artifact_pair(
            intent=intent,
            pccb=pccb,
            sdk=sdk,
            audience=audience,
            verification_time=verification_time,
            request_id=args.request_id,
        )
    else:
        ignored_flags = [flag for flag, value in (("--intent", args.intent), ("--pccb", args.pccb), ("--audience", args.audience)) if value]
        if ignored_flags:
            raise ValueError("replay-harness scan does not accept " + ", ".join(ignored_flags) + "; omit them or use --target artifact-pair")
        report = scan_replay_harness()

    _print_scan_report(args=args, report=report)
    return 1 if report.overall_status == "EXECUTION_GAP_PRESENT" else 0


def _cmd_preflight_check(args: argparse.Namespace) -> int:
    intent = _load_intent(args.intent)
    decision = PreflightEngine().check(intent, evidence_context=_load_preflight_evidence(args))
    _print_preflight_decision(args=args, decision=decision)
    return 0


def _cmd_preflight_explain(args: argparse.Namespace) -> int:
    decision = _load_preflight_decision(args.decision)
    _print_preflight_decision(args=args, decision=decision)
    return 0


def _cmd_preflight_simulate(args: argparse.Namespace) -> int:
    if args.wedge != "infra_delete":
        raise ValueError(f"unsupported preflight simulation wedge: {args.wedge!r}")
    decision = PreflightEngine().check(
        _build_preflight_simulation_intent(),
        evidence_context={
            "environment": "production",
            "change_ticket": "CHG-PREFLIGHT-DEMO",
            "backup_verified": True,
        },
    )
    _print_preflight_decision(args=args, decision=decision)
    return 0


def _cmd_mcp_wrap(args: argparse.Namespace) -> int:
    _print_mcp_wrap_result(args=args, payload=_mcp_wrap_payload(args=args))
    return 0


def _cmd_evidence_query(args: argparse.Namespace) -> int:
    service = _build_evidence_query_service(args.artifacts_dir)
    result = service.query(_build_evidence_query_from_args(args))
    _print_evidence_query_result(args=args, result=result)
    return 0 if result.verdict in (EvidenceVerdict.VERIFIED_EXECUTION, EvidenceVerdict.VERIFIED_REFUSAL) else 1


def _cmd_keys_publish(args: argparse.Namespace) -> int:
    document = _build_key_discovery_document_from_args(args)
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Key-discovery document written.")
    print(f"Output: {output_path}")
    print(f"Origin: {document['origin']}")
    print(f"Issuer: {document['issuer']['type']}:{document['issuer']['id']}")
    print(f"Key: {args.key_id}")
    print(f"Algorithm: {args.algorithm}")
    return 0


def _cmd_graph_anchor(args: argparse.Namespace) -> int:
    published_at = parse_timestamp(args.published_at, "published_at") if args.published_at else datetime.now(timezone.utc)
    metadata = _parse_cli_metadata(args.metadata)

    if args.receipt is not None:
        receipt = _load_receipt(args.receipt)
        correlation_pccb_id = receipt.correlation.pccb_id if receipt.correlation is not None else None
        pccb = _resolve_anchor_pccb(args=args, correlation_pccb_id=correlation_pccb_id, artifact_path=args.receipt)
        anchor = create_execution_anchor_from_receipt(
            receipt,
            pccb,
            published_at=published_at,
            metadata=metadata,
        )
        payload = _graph_anchor_payload(
            args=args,
            anchor=anchor,
            anchor_hash=build_execution_anchor_hash(anchor),
            source_kind="receipt",
            source_path=args.receipt,
        )
    else:
        refusal = _load_refusal(args.refusal)
        correlation_pccb_id = refusal.correlation.pccb_id if refusal.correlation is not None else None
        pccb = _resolve_anchor_pccb(args=args, correlation_pccb_id=correlation_pccb_id, artifact_path=args.refusal)
        anchor = create_execution_anchor_from_refusal(
            refusal,
            pccb,
            published_at=published_at,
            metadata=metadata,
        )
        payload = _graph_anchor_payload(
            args=args,
            anchor=anchor,
            anchor_hash=build_execution_anchor_hash(anchor),
            source_kind="refusal",
            source_path=args.refusal,
        )

    if args.publish_url and not args.dry_run:
        HttpExecutionGraphClient(endpoint_url=args.publish_url).publish(anchor)

    _print_graph_anchor_result(args=args, payload=payload)
    return 0


def _cmd_up(args: argparse.Namespace) -> int:
    if args.bootstrap_only:
        manifest = bootstrap_local_runtime(args.runtime_dir)
        _print_runtime_up_result(args=args, payload=manifest)
        return 0

    session = start_local_runtime_services(
        runtime_dir=args.runtime_dir,
        host=args.host,
        port=args.port,
        enable_trace_viewer=not args.no_trace_viewer,
        trace_viewer_port=args.trace_viewer_port,
    )
    try:
        _print_runtime_up_result(args=args, payload=session.startup_info.to_dict())
        session.runtime_server.thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = doctor_local_runtime(args.runtime_dir, deep=args.deep)
    _print_doctor_report(args=args, report=report)
    return 0 if report.overall_status == "ready" else 1


def _cmd_simulate(args: argparse.Namespace) -> int:
    if args.incident is not None and args.scenario is not None:
        raise ValueError("use either --incident or --scenario, not both")
    report = simulate_local_runtime(args.runtime_dir, scenario=args.scenario or "all", incident=args.incident)
    _print_simulation_report(args=args, report=report)
    return 0 if report.succeeded else 1


def _cmd_bundle_export(args: argparse.Namespace) -> int:
    payload = export_local_runtime_bundle(
        args.runtime_dir,
        output_path=args.output,
        force=args.force,
    )
    _print_bundle_export_result(args=args, payload=payload)
    return 0


def _cmd_bundle_verify(args: argparse.Namespace) -> int:
    payload = verify_local_runtime_bundle(args.bundle)
    _print_bundle_verify_result(args=args, payload=payload)
    return 0 if payload["ok"] else 1


def _cmd_keys_generate(args: argparse.Namespace) -> int:
    payload = generate_local_hmac_key_material(
        output_path=args.output,
        key_id=args.key_id,
        secret_bytes=args.secret_bytes,
    )
    _print_keys_generate_result(args=args, output_path=str(Path(args.output).resolve()), payload=payload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="actenon-kernel",
        description="Kernel CLI for bootstrapping the single-node trust runtime, verifying proof, generating local key material, creating execution anchors, publishing key-discovery documents, querying execution evidence, scanning execution gaps, running coverage matrices, validating artifacts, and running conformance. The unified developer CLI `actenon` is provided by the actenon-permit package.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    up = subparsers.add_parser(
        "up",
        help="Start the local single-node trust runtime server and local trace viewer.",
    )
    up.add_argument(
        "--runtime-dir",
        default=str(DEFAULT_LOCAL_RUNTIME_DIR),
        help="Local runtime root. Defaults to artifacts/local_runtime.",
    )
    up.add_argument("--host", default="127.0.0.1", help="Host interface to bind for the local runtime server.")
    up.add_argument("--port", default=8787, type=int, help="Port to bind for the local runtime server.")
    up.add_argument(
        "--trace-viewer-port",
        default=8421,
        type=int,
        help="Port to bind for the local read-only trace viewer. Defaults to 8421.",
    )
    up.add_argument(
        "--no-trace-viewer",
        action="store_true",
        help="Disable the local read-only trace viewer.",
    )
    up.add_argument(
        "--bootstrap-only",
        action="store_true",
        help="Prepare the runtime files and labs without starting the local HTTP services.",
    )
    up.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    up.set_defaults(func=_cmd_up)

    doctor = subparsers.add_parser(
        "doctor",
        help="Check whether the local single-node trust runtime is healthy and complete.",
    )
    doctor.add_argument(
        "--runtime-dir",
        default=str(DEFAULT_LOCAL_RUNTIME_DIR),
        help="Local runtime root to inspect. Defaults to artifacts/local_runtime.",
    )
    doctor.add_argument(
        "--deep",
        action="store_true",
        help="Run slower lab and scanner checks in addition to the fast local runtime diagnostic.",
    )
    doctor.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    doctor.set_defaults(func=_cmd_doctor)

    simulate = subparsers.add_parser(
        "simulate",
        help="Run local incident simulations that contrast unprotected execution, proof checks, and protected-endpoint runtime behavior.",
    )
    simulate.add_argument(
        "--runtime-dir",
        default=str(DEFAULT_LOCAL_RUNTIME_DIR),
        help="Local runtime root where simulation artifacts should be written. Defaults to artifacts/local_runtime.",
    )
    simulate.add_argument(
        "--scenario",
        default=None,
        choices=(
            "all",
            "valid-proof",
            "audience-mismatch",
            "action-hash-mismatch",
            "expired-proof",
            "replay-refused",
            "mcp-tool-proof-laundering",
            "iam-escalation",
            "data-export",
        ),
        help="Lower-level technical scenario to run. Defaults to 'all' when --incident is not used.",
    )
    simulate.add_argument(
        "--incident",
        choices=("all", "prod-delete", "replit", "openai-eggs", "amazon-kiro"),
        help="Educational incident or pattern simulation. Use prod-delete for the generic hero pattern.",
    )
    simulate.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    simulate.set_defaults(func=_cmd_simulate)

    verify_proof = subparsers.add_parser(
        "verify-proof",
        help="Verify an Action Intent and PCCB pair against explicit verifier context.",
    )
    verify_proof.add_argument("--intent", required=True, help="Path to the Action Intent JSON payload.")
    verify_proof.add_argument("--pccb", required=True, help="Path to the PCCB JSON payload.")
    verify_proof.add_argument(
        "--audience",
        required=True,
        help="Protected endpoint audience to enforce. Use '<type>:<id>' or a bare id with --audience-type.",
    )
    verify_proof.add_argument(
        "--audience-type",
        default="service",
        help="Audience type to use when --audience is provided as a bare id. Defaults to 'service'.",
    )
    verify_proof.add_argument(
        "--verification-time",
        default="now",
        help="Verification time to use: 'now', 'pccb-issued-at', 'pccb-not-before', or an RFC3339 timestamp.",
    )
    verify_proof.add_argument("--request-id", default="cli_verify_proof", help="Request identifier used for local verification context.")
    verify_proof.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    verify_proof.add_argument(
        "--signer",
        default="auto",
        choices=("auto", "local"),
        help="Signature verifier to use. 'auto' currently supports the open-source local trust root only.",
    )
    verify_proof.set_defaults(func=_cmd_verify_proof)

    verify_receipt = subparsers.add_parser("verify-receipt", help="Validate a receipt artifact and optional linked artifacts.")
    verify_receipt.add_argument("--receipt", required=True, help="Path to the receipt JSON payload.")
    verify_receipt.add_argument("--intent", help="Optional Action Intent JSON to cross-check against the receipt.")
    verify_receipt.add_argument("--pccb", help="Optional PCCB JSON to cross-check against the receipt.")
    verify_receipt.add_argument("--refusal", help="Optional refusal JSON to cross-check against the receipt.")
    verify_receipt.set_defaults(func=_cmd_verify_receipt)

    verify_refusal = subparsers.add_parser("verify-refusal", help="Validate a refusal artifact and optional linked artifacts.")
    verify_refusal.add_argument("--refusal", required=True, help="Path to the refusal JSON payload.")
    verify_refusal.add_argument("--intent", help="Optional Action Intent JSON to cross-check against the refusal.")
    verify_refusal.add_argument("--pccb", help="Optional PCCB JSON to cross-check against the refusal.")
    verify_refusal.add_argument("--receipt", help="Optional receipt JSON to cross-check against the refusal.")
    verify_refusal.set_defaults(func=_cmd_verify_refusal)

    attest_receipt = subparsers.add_parser("attest-receipt", help="Create an opt-in signed attestation envelope for a receipt.")
    attest_receipt.add_argument("--receipt", required=True, help="Path to the v1 receipt JSON payload.")
    attest_receipt.add_argument("--output", required=True, help="Path to write the receipt attestation JSON payload.")
    attest_receipt.add_argument(
        "--issuer",
        default="service:actenon-local-outcome-attestor",
        help="Attestation issuer as '<type>:<id>' or a bare service id.",
    )
    attest_receipt.add_argument("--issued-at", help="Optional RFC3339 attestation timestamp. Defaults to current UTC time.")
    attest_receipt.add_argument(
        "--signer",
        default="local",
        choices=("local",),
        help="Signer to use. The OSS CLI currently supports local proof signing only.",
    )
    attest_receipt.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    attest_receipt.set_defaults(func=_cmd_attest_receipt)

    attest_refusal = subparsers.add_parser("attest-refusal", help="Create an opt-in signed attestation envelope for a refusal.")
    attest_refusal.add_argument("--refusal", required=True, help="Path to the v1 refusal JSON payload.")
    attest_refusal.add_argument("--output", required=True, help="Path to write the refusal attestation JSON payload.")
    attest_refusal.add_argument(
        "--issuer",
        default="service:actenon-local-outcome-attestor",
        help="Attestation issuer as '<type>:<id>' or a bare service id.",
    )
    attest_refusal.add_argument("--issued-at", help="Optional RFC3339 attestation timestamp. Defaults to current UTC time.")
    attest_refusal.add_argument(
        "--signer",
        default="local",
        choices=("local",),
        help="Signer to use. The OSS CLI currently supports local proof signing only.",
    )
    attest_refusal.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    attest_refusal.set_defaults(func=_cmd_attest_refusal)

    verify_receipt_attestation = subparsers.add_parser(
        "verify-receipt-attestation",
        help="Verify a signed receipt attestation envelope.",
    )
    verify_receipt_attestation.add_argument("--attestation", required=True, help="Path to the receipt attestation JSON payload.")
    verify_receipt_attestation.add_argument(
        "--signer",
        default="auto",
        choices=("auto", "local"),
        help="Signature verifier to use. 'auto' currently supports the OSS local trust root only.",
    )
    verify_receipt_attestation.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    verify_receipt_attestation.set_defaults(func=_cmd_verify_receipt_attestation)

    verify_refusal_attestation = subparsers.add_parser(
        "verify-refusal-attestation",
        help="Verify a signed refusal attestation envelope.",
    )
    verify_refusal_attestation.add_argument("--attestation", required=True, help="Path to the refusal attestation JSON payload.")
    verify_refusal_attestation.add_argument(
        "--signer",
        default="auto",
        choices=("auto", "local"),
        help="Signature verifier to use. 'auto' currently supports the OSS local trust root only.",
    )
    verify_refusal_attestation.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    verify_refusal_attestation.set_defaults(func=_cmd_verify_refusal_attestation)

    evidence = subparsers.add_parser(
        "evidence",
        help="Query local execution evidence artifacts and receipt chains.",
    )
    evidence_subparsers = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_query = evidence_subparsers.add_parser(
        "query",
        help="Query local execution evidence by receipt id, PCCB id, intent id, or action hash.",
    )
    evidence_selector = evidence_query.add_mutually_exclusive_group(required=True)
    evidence_selector.add_argument("--receipt-id", help="Receipt id to resolve from the local artifact source.")
    evidence_selector.add_argument("--pccb-id", help="PCCB id to resolve from the local artifact source.")
    evidence_selector.add_argument("--intent-id", help="Action Intent id to resolve from the local artifact source.")
    evidence_selector.add_argument("--action-hash", help="Canonical action hash to resolve from the local artifact source.")
    evidence_query.add_argument(
        "--artifacts-dir",
        required=True,
        help="Local artifact root to scan. Point this at a portable-local-proof root, a local-proof demo root, or an outcomes root.",
    )
    evidence_query.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    evidence_query.set_defaults(func=_cmd_evidence_query)

    keys = subparsers.add_parser(
        "keys",
        help="Generate local key material or publishable key-discovery documents.",
    )
    keys_subparsers = keys.add_subparsers(dest="keys_command", required=True)
    keys_generate = keys_subparsers.add_parser(
        "generate",
        help="Generate local single-node HS256 key material for issuer and verifier experiments.",
    )
    keys_generate.add_argument("--key-id", required=True, help="Exact key identifier to embed in the local key material.")
    keys_generate.add_argument(
        "--secret-bytes",
        type=int,
        default=32,
        help="Secret size in bytes. Defaults to 32.",
    )
    keys_generate.add_argument("--output", required=True, help="Path to write the generated local key file.")
    keys_generate.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    keys_generate.set_defaults(func=_cmd_keys_generate)

    keys_publish = keys_subparsers.add_parser(
        "publish",
        help="Generate a conformant key-discovery JSON document for one verification key.",
    )
    keys_publish.add_argument("--issuer-origin", required=True, help="HTTPS origin that will serve the discovery document.")
    keys_publish.add_argument("--issuer-id", required=True, help="Portable issuer identifier for the discovery document.")
    keys_publish.add_argument(
        "--issuer-type",
        default="service",
        help="Portable issuer type. Defaults to 'service'.",
    )
    keys_publish.add_argument("--issuer-display-name", help="Optional human-readable issuer display name.")
    keys_publish.add_argument("--key-id", required=True, help="Exact key identifier verifiers will match against signature.key_id.")
    keys_publish.add_argument("--algorithm", required=True, help="Signature algorithm for this verification key, for example 'EdDSA' or 'RS256'.")
    public_jwk_group = keys_publish.add_mutually_exclusive_group(required=True)
    public_jwk_group.add_argument("--public-jwk-file", help="Path to a public JWK JSON object for the verification key.")
    public_jwk_group.add_argument("--public-jwk-json", help="Inline public JWK JSON object for the verification key.")
    keys_publish.add_argument(
        "--status",
        default="active",
        choices=ALLOWED_DISCOVERY_KEY_STATUSES,
        help="Published key status. Defaults to 'active'.",
    )
    keys_publish.add_argument(
        "--use",
        action="append",
        choices=ALLOWED_DISCOVERY_KEY_USES,
        default=None,
        help="Verification purpose for the key. May be repeated. Defaults to 'proof_issuance'.",
    )
    keys_publish.add_argument("--published-at", help="RFC3339 publication timestamp. Defaults to the current UTC time.")
    keys_publish.add_argument("--not-before", help="Optional RFC3339 timestamp before which the key should not be used.")
    keys_publish.add_argument("--expires-at", help="Optional RFC3339 timestamp after which the key is expired.")
    keys_publish.add_argument("--revoked-at", help="Optional RFC3339 timestamp recording when the key was revoked.")
    keys_publish.add_argument("--replaced-by", help="Optional replacement key_id for operator guidance.")
    keys_publish.add_argument("--revocation-reason", help="Optional revocation reason string.")
    keys_publish.add_argument(
        "--cache-max-age-seconds",
        type=int,
        default=300,
        help="Advisory cache lifetime to include in the document. Defaults to 300.",
    )
    keys_publish.add_argument("--output", required=True, help="Path to write the generated key-discovery JSON document.")
    keys_publish.set_defaults(func=_cmd_keys_publish)

    graph = subparsers.add_parser(
        "graph",
        help="Create local execution anchors and optionally request publication.",
    )
    graph_subparsers = graph.add_subparsers(dest="graph_command", required=True)
    graph_anchor = graph_subparsers.add_parser(
        "anchor",
        help="Create an execution anchor from a local receipt or refusal artifact.",
    )
    graph_selector = graph_anchor.add_mutually_exclusive_group(required=True)
    graph_selector.add_argument("--receipt", help="Path to an executed receipt JSON artifact.")
    graph_selector.add_argument("--refusal", help="Path to a refusal JSON artifact.")
    graph_anchor.add_argument(
        "--pccb",
        help="Optional PCCB JSON artifact. If omitted, the CLI first looks for a sibling pccb.json and then tries --artifacts-dir.",
    )
    graph_anchor.add_argument(
        "--artifacts-dir",
        help="Optional local artifact root used to resolve the governing PCCB by correlation.pccb_id when --pccb is omitted.",
    )
    graph_anchor.add_argument(
        "--publish-url",
        help="Optional HTTP endpoint for fire-and-forget execution-anchor publication.",
    )
    graph_anchor.add_argument(
        "--dry-run",
        action="store_true",
        help="Create and print the anchor without requesting publication.",
    )
    graph_anchor.add_argument(
        "--published-at",
        help="Optional RFC3339 timestamp to embed in the anchor. Defaults to the current UTC time.",
    )
    graph_anchor.add_argument(
        "--metadata",
        action="append",
        help="Optional public metadata entry in key=value form. Repeat to add multiple entries.",
    )
    graph_anchor.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    graph_anchor.set_defaults(func=_cmd_graph_anchor)

    bundle = subparsers.add_parser(
        "bundle",
        help="Export the local single-node runtime as a portable local bundle.",
    )
    bundle_subparsers = bundle.add_subparsers(dest="bundle_command", required=True)
    bundle_export = bundle_subparsers.add_parser(
        "export",
        help="Export the local runtime as a portable execution evidence bundle.",
    )
    bundle_export.add_argument(
        "--runtime-dir",
        default=str(DEFAULT_LOCAL_RUNTIME_DIR),
        help="Local runtime root to export. Defaults to artifacts/local_runtime.",
    )
    bundle_export.add_argument(
        "--output",
        help="Bundle output path. Defaults to <runtime-dir>/bundles/actenon-local-runtime.actenon. Use a .actenon or .zip path for an archive or any other path for a directory export.",
    )
    bundle_export.add_argument("--force", action="store_true", help="Replace an existing output path.")
    bundle_export.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    bundle_export.set_defaults(func=_cmd_bundle_export)
    bundle_verify = bundle_subparsers.add_parser(
        "verify",
        help="Verify a portable execution evidence bundle and its declared proof chains.",
    )
    bundle_verify.add_argument(
        "bundle",
        help="Path to a .actenon archive, .zip archive, or directory bundle export.",
    )
    bundle_verify.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    bundle_verify.set_defaults(func=_cmd_bundle_verify)

    preflight = subparsers.add_parser(
        "preflight",
        help="Ask Actenon before a consequential action executes.",
    )
    preflight_subparsers = preflight.add_subparsers(dest="preflight_command", required=True)
    preflight_check = preflight_subparsers.add_parser(
        "check",
        help="Evaluate an Action Intent with the local preflight policy pack.",
    )
    preflight_check.add_argument("--intent", required=True, help="Path to the Action Intent JSON payload.")
    evidence_group = preflight_check.add_mutually_exclusive_group()
    evidence_group.add_argument("--evidence-json", help="Inline preflight evidence/context JSON object.")
    evidence_group.add_argument("--evidence-file", help="Path to a preflight evidence/context JSON object.")
    preflight_check.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    preflight_check.set_defaults(func=_cmd_preflight_check)

    preflight_explain = preflight_subparsers.add_parser(
        "explain",
        help="Explain a saved preflight decision JSON artifact.",
    )
    preflight_explain.add_argument("--decision", required=True, help="Path to the PreflightDecision JSON payload.")
    preflight_explain.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    preflight_explain.set_defaults(func=_cmd_preflight_explain)

    preflight_simulate = preflight_subparsers.add_parser(
        "simulate",
        help="Run a deterministic local preflight simulation.",
    )
    preflight_simulate.add_argument(
        "--wedge",
        required=True,
        choices=("infra_delete",),
        help="Preflight wedge to simulate. Currently supports infra_delete.",
    )
    preflight_simulate.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    preflight_simulate.set_defaults(func=_cmd_preflight_simulate)

    mcp = subparsers.add_parser(
        "mcp",
        help="Inspect local MCP proof-gate wrapper patterns.",
    )
    mcp_subparsers = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_wrap = mcp_subparsers.add_parser(
        "wrap",
        help="Print a local proof-gate wrapper pattern for a consequential MCP tool.",
    )
    mcp_wrap.add_argument(
        "--tool",
        default="filesystem.delete",
        choices=tuple(MCP_HERO_TOOL_CAPABILITIES),
        help="Consequential MCP tool to wrap. Defaults to filesystem.delete.",
    )
    mcp_wrap.add_argument(
        "--capability",
        help="Optional capability override. Defaults to the hero-path capability for --tool.",
    )
    mcp_wrap.add_argument(
        "--audience",
        default="service:actenon-mcp-consequential-tools",
        help="Protected MCP tool audience to document for the wrapper.",
    )
    mcp_wrap.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    mcp_wrap.set_defaults(func=_cmd_mcp_wrap)

    scan = subparsers.add_parser(
        "scan",
        help="Run the local execution-gap scanner against a repo, MCP tools, endpoints, artifacts, or the built-in local harness.",
    )
    scan.add_argument(
        "scan_command",
        nargs="?",
        choices=("repo", "mcp", "endpoint", "local"),
        help="Scanner mode. Use repo, mcp, endpoint, or local. Omit for legacy --target behavior.",
    )
    scan.add_argument(
        "--path",
        default=".",
        help="Path to scan for repo, MCP, or endpoint modes. Defaults to the current directory.",
    )
    scan.add_argument(
        "--target",
        choices=("artifact-pair", "replay-harness"),
        help="Scanner target. Defaults to 'replay-harness' unless --intent/--pccb inputs are supplied.",
    )
    scan.add_argument("--intent", help="Path to the Action Intent JSON payload for artifact-pair scans.")
    scan.add_argument("--pccb", help="Path to the PCCB JSON payload for artifact-pair scans.")
    scan.add_argument(
        "--audience",
        help="Protected endpoint audience for artifact-pair scans. Use '<type>:<id>' or a bare id with --audience-type.",
    )
    scan.add_argument(
        "--audience-type",
        default="service",
        help="Audience type to use when --audience is provided as a bare id. Defaults to 'service'.",
    )
    scan.add_argument(
        "--verification-time",
        default="pccb-issued-at",
        help="Artifact-pair scan time: 'now', 'pccb-issued-at', 'pccb-not-before', or an RFC3339 timestamp.",
    )
    scan.add_argument("--request-id", default="cli_scan", help="Request identifier used for artifact-pair scan context.")
    scan.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    scan.add_argument("--markdown", action="store_true", help="Emit a Markdown scan report to stdout.")
    scan.add_argument(
        "--report-mode",
        choices=("executive", "developer"),
        default="executive",
        help="Markdown/text report mode. Executive leads with a plain-English action-risk summary; developer includes full finding details.",
    )
    scan.add_argument("--report-json", help="Write the JSON scan report to this path.")
    scan.add_argument("--report-markdown", help="Write the Markdown scan report to this path.")
    scan.add_argument("--badge", action="store_true", help="Print local badge Markdown in text mode.")
    scan.add_argument("--badge-output", help="Write local badge Markdown to this path.")
    scan.add_argument("--exclude", action="append", help="Exclude a path, glob, or substring from repo scanning. Repeatable.")
    scan.add_argument("--include", action="append", help="Only include matching paths/globs during repo scanning. Repeatable.")
    scan.add_argument(
        "--extensions",
        action="append",
        help="Comma-separated source extensions to scan, for example py,ts,tsx,js,go,rs,java. Repeatable.",
    )
    scan.add_argument("--max-files", type=int, help="Stop discovery after this many scan-eligible files and emit a partial report.")
    scan.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        help="Skip files larger than this many bytes. Defaults to 1000000.",
    )
    scan.add_argument("--timeout-seconds", type=float, help="Stop scanning after this many seconds.")
    scan.add_argument("--progress", action="store_true", help="Emit scan progress to stderr.")
    scan.add_argument(
        "--partial-report-on-timeout",
        action="store_true",
        help="Emit a partial advisory report instead of failing when --timeout-seconds is reached.",
    )
    scan.add_argument(
        "--signer",
        default="auto",
        choices=("auto", "local"),
        help="Signature verifier to use for artifact-pair scans. 'auto' currently supports the OSS local trust root only.",
    )
    scan.set_defaults(func=_cmd_scan)

    conformance = subparsers.add_parser("conformance", help="Run local open-source conformance checks.")
    conformance_subparsers = conformance.add_subparsers(dest="conformance_command", required=True)
    conformance_run = conformance_subparsers.add_parser("run", help="Run the repository conformance suite.")
    conformance_run.add_argument("--verbose", action="store_true", help="Show full unittest output.")
    conformance_run.add_argument(
        "--require-complete",
        action="store_true",
        help="Fail when any conformance check is skipped; required for the Actenon Verified mark.",
    )
    conformance_run.set_defaults(func=_cmd_conformance_run)

    coverage = subparsers.add_parser(
        "coverage",
        help="Run local deterministic coverage matrices for proof-bound consequential actions.",
    )
    coverage_subparsers = coverage.add_subparsers(dest="coverage_command", required=True)
    coverage_run = coverage_subparsers.add_parser(
        "run",
        help="Run the Consequential Action Coverage Matrix.",
    )
    coverage_run.add_argument(
        "--output",
        default=str(DEFAULT_EVIDENCE_PATH),
        help=f"Evidence JSON path. Defaults to {DEFAULT_EVIDENCE_PATH}.",
    )
    coverage_run.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    coverage_run.set_defaults(func=_cmd_coverage_run)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
