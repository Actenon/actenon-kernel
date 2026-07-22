from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_ARTIFACT_ROOTS = (
    Path("artifacts/local_proof"),
    Path("artifacts/portable_local_proof"),
)

ARTIFACT_ORDER = (
    "framing",
    "intent_record",
    "action_intent",
    "pccb",
    "decision_receipt",
    "execution_receipt",
    "refusal",
    "verification_result",
    "counterfactual_execution",
    "weak_control_path",
    "proof_bound_path",
    "proof_only_gap",
    "bounded_intent_change",
    "trace_viewer_follow_up",
    "incident_story",
    "protected_response",
    "execution_payload",
    "scenario_summary",
    "protected_endpoint_state",
    "replay_entries",
)

KNOWN_FILE_ARTIFACTS = {
    "framing.json": ("framing", "Incident Framing"),
    "intent_record.json": ("intent_record", "Intent Record"),
    "action_intent.json": ("action_intent", "Action Intent"),
    "pccb.json": ("pccb", "PCCB"),
    "decision_receipt.json": ("decision_receipt", "Decision Receipt"),
    "execution_receipt.json": ("execution_receipt", "Execution Receipt"),
    "refusal.json": ("refusal", "Refusal"),
    "verification_result.json": ("verification_result", "Verification Result"),
    "counterfactual_unprotected_execution.json": ("counterfactual_execution", "Weak Control Path"),
    "weak_control_path.json": ("weak_control_path", "Weak Control Path"),
    "proof_bound_path.json": ("proof_bound_path", "Proof-Bound Path"),
    "proof_only_gap.json": ("proof_only_gap", "Proof-Only Gap"),
    "bounded_intent_change.json": ("bounded_intent_change", "Bounded Intent Change"),
    "trace_viewer_follow_up.json": ("trace_viewer_follow_up", "Trace Viewer Follow-Up"),
    "incident_story.json": ("incident_story", "Incident Story"),
    "protected_resource_response.json": ("protected_response", "Protected Response"),
    "execution_payload.json": ("execution_payload", "Execution Payload"),
    "summary.json": ("scenario_summary", "Scenario Summary"),
}


@dataclass(frozen=True)
class ArtifactRootConfig:
    repo_root: Path
    roots: tuple[Path, ...]


def repo_root_from_viewer() -> Path:
    return Path.cwd().resolve()


def resolve_artifact_roots(repo_root: Path, raw_roots: Iterable[str | Path] | None = None) -> ArtifactRootConfig:
    candidates = tuple(raw_roots) if raw_roots is not None else DEFAULT_ARTIFACT_ROOTS
    resolved: list[Path] = []
    seen: set[Path] = set()

    for raw_root in candidates:
        path = Path(raw_root)
        resolved_path = (repo_root / path).resolve() if not path.is_absolute() else path.resolve()
        if not resolved_path.exists() or not resolved_path.is_dir():
            continue
        if resolved_path in seen:
            continue
        seen.add(resolved_path)
        resolved.append(resolved_path)

    return ArtifactRootConfig(repo_root=repo_root.resolve(), roots=tuple(resolved))


def load_trace_index(config: ArtifactRootConfig) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []

    for root in config.roots:
        manifest_path = root / "manifest.json"
        if not manifest_path.exists():
            continue

        manifest = _load_json(manifest_path)
        if "refund" in manifest or "invoice_payment" in manifest or manifest.get("wedge") in {"refund", "invoice_payment"}:
            runs.extend(_load_local_proof_runs(config.repo_root, root, manifest))
        elif "results" in manifest and "scenario" in manifest:
            runs.append(_load_simulation_run(config.repo_root, root, manifest))
        elif {"action_intent", "pccb", "verification_result"} <= set(manifest):
            runs.append(_load_portable_run(config.repo_root, root, manifest))

    runs.sort(key=lambda run: (run["sort_key"], run["title"]))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "artifact_roots": [_display_path(root, config.repo_root) for root in config.roots],
        "runs": runs,
    }


def run_summaries(index: dict[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for run in index["runs"]:
        summaries.append(
            {
                "id": run["id"],
                "title": run["title"],
                "kind": run["kind"],
                "wedge": run["wedge"],
                "artifact_root": run["artifact_root"],
                "summary_lines": run["summary_lines"],
                "stats": run["stats"],
                "scenario_count": len(run["scenarios"]),
            }
        )
    return summaries


def find_run(index: dict[str, Any], run_id: str) -> dict[str, Any] | None:
    for run in index["runs"]:
        if run["id"] == run_id:
            return run
    return None


def _load_local_proof_runs(repo_root: Path, root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []

    wedge_name = manifest.get("wedge")
    if wedge_name in {"refund", "invoice_payment"}:
        title = "Local Proof: Refund" if wedge_name == "refund" else "Local Proof: Invoice Payment"
        sort_key = "0-refund" if wedge_name == "refund" else "1-invoice-payment"
        runs.append(
            _load_local_proof_run_section(
                repo_root=repo_root,
                root=root,
                section=manifest,
                wedge=str(wedge_name),
                title=title,
                sort_key=sort_key,
            )
        )
        return runs

    for wedge, title in (("refund", "Local Proof: Refund"), ("invoice_payment", "Local Proof: Invoice Payment")):
        section = manifest.get(wedge)
        if not isinstance(section, dict):
            continue
        runs.append(
            _load_local_proof_run_section(
                repo_root=repo_root,
                root=root,
                section=section,
                wedge=wedge,
                title=title,
                sort_key="0-refund" if wedge == "refund" else "1-invoice-payment",
            )
        )

    return runs


def _load_local_proof_run_section(
    *,
    repo_root: Path,
    root: Path,
    section: dict[str, Any],
    wedge: str,
    title: str,
    sort_key: str,
) -> dict[str, Any]:
    section_root = Path(section.get("artifact_root", root)).resolve()
    state_path = _path_or_none(section.get("protected_endpoint_state"))
    replay_path = section_root / "state" / "replay.sqlite3"
    run_manifest_path = section_root / "manifest.json"
    run_manifest = _load_json(run_manifest_path) if run_manifest_path.exists() else section
    replay_entries = _load_replay_entries(replay_path)
    protected_state = _load_json(state_path) if state_path and state_path.exists() else None

    scenarios = [
        _load_local_proof_scenario(
            repo_root=repo_root,
            section_root=section_root,
            wedge=wedge,
            scenario_summary=scenario_summary,
            replay_entries=replay_entries,
            protected_state=protected_state,
            state_path=state_path,
        )
        for scenario_summary in section.get("scenarios", ())
    ]
    run_summary_lines = _build_local_run_summary_lines(
        title=title,
        section_root=section_root,
        state_path=state_path,
        scenarios=section.get("scenarios", ()),
    )

    run_id = _slug(_display_path(section_root, repo_root) + f"-{wedge}")
    run_artifacts = []
    if protected_state is not None and state_path is not None:
        run_artifacts.append(_artifact_from_payload("protected_endpoint_state", "Protected Endpoint State", state_path, protected_state, repo_root))
    if replay_entries:
        run_artifacts.append(
            _artifact_from_payload(
                "replay_entries",
                "Replay Entries",
                replay_path,
                replay_entries,
                repo_root,
            )
        )

    return {
        "id": run_id,
        "title": title,
        "kind": "local_proof",
        "wedge": wedge,
        "sort_key": sort_key,
        "artifact_root": _display_path(section_root, repo_root),
        "manifest": run_manifest,
        "summary_lines": run_summary_lines,
        "stats": _build_run_stats(scenarios),
        "run_artifacts": run_artifacts,
        "scenarios": scenarios,
    }


def _load_local_proof_scenario(
    *,
    repo_root: Path,
    section_root: Path,
    wedge: str,
    scenario_summary: dict[str, Any],
    replay_entries: list[dict[str, Any]],
    protected_state: dict[str, Any] | None,
    state_path: Path | None,
) -> dict[str, Any]:
    scenario_name = scenario_summary["scenario"]
    scenario_dir = section_root / "scenarios" / scenario_name
    artifact_map = _load_known_scenario_artifacts(repo_root, scenario_dir)

    intent_payload = _payload_for(artifact_map, "action_intent")
    pccb_payload = _payload_for(artifact_map, "pccb")
    decision_receipt = _payload_for(artifact_map, "decision_receipt")
    execution_receipt = _payload_for(artifact_map, "execution_receipt")
    refusal_payload = _payload_for(artifact_map, "refusal")

    intent_id = _first_non_empty(
        scenario_summary.get("intent_id"),
        _nested_get(intent_payload, "intent_id"),
        _nested_get(decision_receipt, "intent_id"),
        _nested_get(execution_receipt, "intent_id"),
        _nested_get(refusal_payload, "intent_id"),
    )
    pccb_id = _first_non_empty(
        _nested_get(pccb_payload, "pccb_id"),
        _nested_get(decision_receipt, "correlation", "pccb_id"),
        _nested_get(execution_receipt, "correlation", "pccb_id"),
    )
    request_id = _first_non_empty(
        scenario_summary.get("request_id"),
        _nested_get(decision_receipt, "correlation", "request_id"),
        _nested_get(execution_receipt, "correlation", "request_id"),
        _nested_get(refusal_payload, "correlation", "request_id"),
    )

    matching_replay_entries = [
        entry
        for entry in replay_entries
        if entry.get("intent_id") == intent_id
        or entry.get("pccb_id") == pccb_id
        or _nested_get(entry, "metadata", "request_id") == request_id
    ]
    if matching_replay_entries:
        artifact_map["replay_entries"] = _artifact_from_payload(
            "replay_entries",
            "Replay Entries",
            section_root / "state" / "replay.sqlite3",
            matching_replay_entries,
            repo_root,
        )

    protected_state_matches = _find_state_matches(protected_state, intent_id=intent_id, pccb_id=pccb_id, request_id=request_id)
    if protected_state_matches and state_path is not None:
        artifact_map["protected_endpoint_state"] = _artifact_from_payload(
            "protected_endpoint_state",
            "Protected Endpoint State",
            state_path,
            {"matches": protected_state_matches},
            repo_root,
        )

    artifacts = _ordered_artifacts(artifact_map)
    flow = _build_local_proof_flow(
        scenario_summary=scenario_summary,
        decision_receipt=decision_receipt,
        execution_receipt=execution_receipt,
        refusal_payload=refusal_payload,
        pccb_payload=pccb_payload,
        replay_entries=matching_replay_entries,
        protected_state_matches=protected_state_matches,
    )

    return {
        "id": _slug(f"{wedge}-{scenario_name}"),
        "name": scenario_name,
        "label": _humanize(scenario_name),
        "wedge": wedge,
        "description": scenario_summary.get("description", ""),
        "request_id": request_id,
        "intent_id": intent_id,
        "pccb_id": pccb_id,
        "decision_outcome": scenario_summary.get("decision_outcome"),
        "final_outcome": scenario_summary.get("final_outcome", scenario_summary.get("expected_outcome")),
        "reason_code": scenario_summary.get("reason_code") or scenario_summary.get("refusal_code"),
        "what_happened": _build_what_happened(execution_receipt, refusal_payload, decision_receipt),
        "why_result": _build_why_result(execution_receipt, refusal_payload, decision_receipt),
        "verification_checks": _build_verification_checks(intent_payload, pccb_payload, execution_receipt, refusal_payload),
        "artifacts": artifacts,
        "flow": flow,
    }


def _load_portable_run(repo_root: Path, root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    summary_lines = _load_summary_lines(root / "SUMMARY.txt")
    artifact_map = _load_known_root_artifacts(repo_root, root)
    intent_payload = _payload_for(artifact_map, "action_intent")
    pccb_payload = _payload_for(artifact_map, "pccb")
    verification_result = _payload_for(artifact_map, "verification_result")
    protected_response = _payload_for(artifact_map, "protected_response")

    scenario = {
        "id": "portable-local-proof",
        "name": "portable_local_proof",
        "label": "Portable Local Proof",
        "wedge": "portable_local_proof",
        "description": "Portable verifier-first protected resource demo.",
        "request_id": _nested_get(verification_result, "request_id"),
        "intent_id": _nested_get(intent_payload, "intent_id"),
        "pccb_id": _nested_get(pccb_payload, "pccb_id"),
        "decision_outcome": "allow",
        "final_outcome": "executed",
        "reason_code": None,
        "what_happened": "A portable Action Intent and PCCB were generated locally, verified at the protected endpoint, and the protected resource returned a response.",
        "why_result": _portable_why_result(protected_response),
        "verification_checks": _build_portable_verification_checks(intent_payload, pccb_payload, verification_result),
        "artifacts": _ordered_artifacts(artifact_map),
        "flow": _build_portable_flow(intent_payload, pccb_payload, verification_result, protected_response),
    }

    return {
        "id": _slug(_display_path(root, repo_root)),
        "title": "Portable Local Proof",
        "kind": "portable_local_proof",
        "wedge": "portable_local_proof",
        "sort_key": "2-portable",
        "artifact_root": _display_path(root, repo_root),
        "manifest": manifest,
        "summary_lines": summary_lines,
        "stats": _build_run_stats([scenario]),
        "run_artifacts": [],
        "scenarios": [scenario],
    }


def _load_simulation_run(repo_root: Path, root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    scenarios = [
        _load_simulation_scenario(repo_root, Path(result.get("artifact_dir", root)).resolve(), result)
        for result in manifest.get("results", ())
        if isinstance(result, dict)
    ]
    summary_lines: list[str] = []
    framing_note = manifest.get("framing_note")
    if isinstance(framing_note, str) and framing_note:
        summary_lines.append(framing_note)
    for item in manifest.get("takeaways", ()):
        if isinstance(item, str):
            summary_lines.append(item)
    mode = str(manifest.get("mode", "technical"))
    title = "Incident Simulator" if mode == "incident" else "Technical Simulator"
    sort_key = "3-incident-simulator" if mode == "incident" else "4-technical-simulator"
    return {
        "id": _slug(_display_path(root, repo_root) + f"-{mode}"),
        "title": title,
        "kind": f"{mode}_simulation",
        "wedge": mode,
        "sort_key": sort_key,
        "artifact_root": _display_path(root, repo_root),
        "manifest": manifest,
        "summary_lines": summary_lines,
        "stats": _build_run_stats(scenarios),
        "run_artifacts": [],
        "scenarios": scenarios,
    }


def _load_simulation_scenario(repo_root: Path, scenario_dir: Path, result: dict[str, Any]) -> dict[str, Any]:
    artifact_map = _load_known_scenario_artifacts(repo_root, scenario_dir)
    perspectives = [
        item
        for item in result.get("perspectives", ())
        if isinstance(item, dict)
    ]
    flow = [
        {
            "title": _humanize(str(item.get("key", "step"))),
            "status": str(item.get("status", "observed")),
            "detail": str(item.get("summary", "")),
        }
        for item in perspectives
    ]
    verification_checks = [
        {
            "label": _humanize(str(item.get("key", "check"))),
            "value": f"{item.get('basis', 'observed')}: {item.get('status', 'observed')}",
        }
        for item in perspectives
    ]
    details = result.get("details", {})
    description = ""
    if isinstance(details, dict):
        framing = details.get("framing")
        if isinstance(framing, dict):
            description = str(framing.get("inspired_by", ""))
    return {
        "id": _slug(f"simulation-{result.get('name', scenario_dir.name)}"),
        "name": result.get("name", scenario_dir.name),
        "label": result.get("title") or _humanize(str(result.get("name", scenario_dir.name))),
        "wedge": "incident_simulation",
        "description": description,
        "request_id": None,
        "intent_id": _nested_get(_payload_for(artifact_map, "action_intent"), "intent_id"),
        "pccb_id": _nested_get(_payload_for(artifact_map, "pccb"), "pccb_id"),
        "decision_outcome": result.get("status"),
        "final_outcome": result.get("status", "simulated"),
        "reason_code": result.get("reason_code") or result.get("refusal_code"),
        "what_happened": result.get("summary", "Simulation completed."),
        "why_result": result.get("lesson", result.get("summary", "Simulation completed.")),
        "verification_checks": verification_checks,
        "artifacts": _ordered_artifacts(artifact_map),
        "flow": flow,
    }


def _load_known_root_artifacts(repo_root: Path, root: Path) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    for filename, (kind, label) in KNOWN_FILE_ARTIFACTS.items():
        path = root / filename
        if path.exists():
            artifacts[kind] = _artifact_from_file(kind, label, path, repo_root)
    return artifacts


def _load_known_scenario_artifacts(repo_root: Path, scenario_dir: Path) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    for filename, (kind, label) in KNOWN_FILE_ARTIFACTS.items():
        path = scenario_dir / filename
        if path.exists():
            artifacts[kind] = _artifact_from_file(kind, label, path, repo_root)
    return artifacts


def _artifact_from_file(kind: str, label: str, path: Path, repo_root: Path) -> dict[str, Any]:
    return _artifact_from_payload(kind, label, path, _load_json(path), repo_root)


def _artifact_from_payload(kind: str, label: str, path: Path, payload: Any, repo_root: Path) -> dict[str, Any]:
    artifact_id = _slug(f"{_display_path(path, repo_root)}-{kind}")
    return {
        "id": artifact_id,
        "kind": kind,
        "label": label,
        "path": _display_path(path, repo_root),
        "payload": payload,
    }


def _ordered_artifacts(artifact_map: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = [artifact_map[kind] for kind in ARTIFACT_ORDER if kind in artifact_map]
    remaining = [artifact for kind, artifact in artifact_map.items() if kind not in ARTIFACT_ORDER]
    remaining.sort(key=lambda artifact: artifact["label"])
    return ordered + remaining


def _build_run_stats(scenarios: list[dict[str, Any]]) -> dict[str, int]:
    stats: dict[str, int] = {}
    for scenario in scenarios:
        outcome = scenario["final_outcome"]
        stats[outcome] = stats.get(outcome, 0) + 1
    return stats


def _build_what_happened(execution_receipt: dict[str, Any] | None, refusal_payload: dict[str, Any] | None, decision_receipt: dict[str, Any] | None) -> str:
    if execution_receipt is not None:
        return execution_receipt.get("summary", "Execution completed.")
    if refusal_payload is not None:
        return refusal_payload.get("message", "The action was refused.")
    if decision_receipt is not None:
        return decision_receipt.get("summary", "The action stopped before proof minting.")
    return "No outcome artifact was found for this scenario."


def _build_why_result(execution_receipt: dict[str, Any] | None, refusal_payload: dict[str, Any] | None, decision_receipt: dict[str, Any] | None) -> str:
    if refusal_payload is not None:
        reason_code = refusal_payload.get("reason_code") or refusal_payload.get("refusal_code") or "REFUSED"
        return f"{reason_code}: {refusal_payload.get('message', 'The request was refused.')}"
    if execution_receipt is not None:
        side_effects = execution_receipt.get("side_effects", {})
        state = side_effects.get("state")
        if state:
            return f"Protected execution completed and emitted an execution receipt with side effect state {state!r}."
        return "Protected execution completed and emitted an execution receipt."
    if decision_receipt is not None:
        outcome = decision_receipt.get("outcome", "stopped")
        follow_up = decision_receipt.get("follow_up", {})
        instructions = follow_up.get("instructions")
        if instructions:
            return f"{outcome}: {instructions}"
        return decision_receipt.get("summary", f"The scenario stopped with outcome {outcome}.")
    return "No explanation is available."


def _portable_why_result(protected_response: dict[str, Any] | None) -> str:
    if protected_response is None:
        return "The protected resource did not return a response."
    message = protected_response.get("message")
    if message:
        return f"Verifier-side checks succeeded and the protected resource returned {message!r}."
    return "Verifier-side checks succeeded and the protected resource returned a response."


def _build_verification_checks(
    intent_payload: dict[str, Any] | None,
    pccb_payload: dict[str, Any] | None,
    execution_receipt: dict[str, Any] | None,
    refusal_payload: dict[str, Any] | None,
) -> list[dict[str, str]]:
    if pccb_payload is None:
        outcome = (
            _nested_get(execution_receipt, "outcome")
            or _nested_get(refusal_payload, "reason_code")
            or _nested_get(refusal_payload, "refusal_code")
            or "none"
        )
        return [
            {
                "label": "Proof Status",
                "value": f"No PCCB was minted for this path. The flow stopped before protected-endpoint verification with outcome {outcome}.",
            }
        ]

    checks = [
        {"label": "Audience", "value": _party_ref_text(pccb_payload.get("audience"))},
        {"label": "Subject", "value": _party_ref_text(pccb_payload.get("subject"))},
        {"label": "Tenant", "value": _tenant_text(pccb_payload.get("tenant"))},
        {"label": "Capability", "value": _nested_get(pccb_payload, "action", "capability") or "unknown"},
        {"label": "Target", "value": _target_text(pccb_payload.get("target"))},
        {"label": "Expiry Window", "value": f"{pccb_payload.get('not_before')} to {pccb_payload.get('expires_at')}"},
        {"label": "Single Use", "value": str(_nested_get(pccb_payload, "scope", "single_use") or False).lower()},
        {"label": "Action Hash", "value": _nested_get(pccb_payload, "action_hash", "value") or "missing"},
    ]

    if intent_payload is not None:
        checks.append({"label": "Action Name", "value": _nested_get(intent_payload, "action", "name") or "unknown"})
    return checks


def _build_portable_verification_checks(
    intent_payload: dict[str, Any] | None,
    pccb_payload: dict[str, Any] | None,
    verification_result: dict[str, Any] | None,
) -> list[dict[str, str]]:
    checks = _build_verification_checks(intent_payload, pccb_payload, execution_receipt=None, refusal_payload=None)
    if verification_result is not None:
        checks.append({"label": "Request Id", "value": verification_result.get("request_id", "unknown")})
        checks.append(
            {
                "label": "Verified Capabilities",
                "value": ", ".join(verification_result.get("scope_capabilities", ())) or "none",
            }
        )
    return checks


def _build_local_proof_flow(
    *,
    scenario_summary: dict[str, Any],
    decision_receipt: dict[str, Any] | None,
    execution_receipt: dict[str, Any] | None,
    refusal_payload: dict[str, Any] | None,
    pccb_payload: dict[str, Any] | None,
    replay_entries: list[dict[str, Any]],
    protected_state_matches: list[dict[str, Any]],
) -> list[dict[str, str]]:
    flow = [
        {
            "title": "Action Intent Received",
            "status": "received",
            "detail": scenario_summary.get("description", "The action intent entered the local proof flow."),
        }
    ]
    if decision_receipt is not None:
        flow.append(
            {
                "title": "Decision Receipt Emitted",
                "status": decision_receipt.get("outcome", "decision"),
                "detail": decision_receipt.get("summary", "A decision receipt was written."),
            }
        )
    if pccb_payload is not None:
        flow.append(
            {
                "title": "PCCB Minted",
                "status": "proof_minted",
                "detail": f"PCCB {pccb_payload.get('pccb_id')} bound the action to audience {_party_ref_text(pccb_payload.get('audience'))}.",
            }
        )
    if replay_entries:
        first_entry = replay_entries[0]
        flow.append(
            {
                "title": "Replay Entry Recorded",
                "status": first_entry.get("status", "recorded"),
                "detail": f"Replay key {first_entry.get('replay_key')} was written with status {first_entry.get('status')}.",
            }
        )
    if protected_state_matches:
        flow.append(
            {
                "title": "Protected Endpoint State Updated",
                "status": "state_updated",
                "detail": f"{len(protected_state_matches)} protected-endpoint state match(es) reference this request.",
            }
        )
    if execution_receipt is not None:
        flow.append(
            {
                "title": "Execution Receipt Emitted",
                "status": execution_receipt.get("outcome", "executed"),
                "detail": execution_receipt.get("summary", "Execution completed."),
            }
        )
    elif refusal_payload is not None:
        flow.append(
            {
                "title": "Refusal Emitted",
                "status": refusal_payload.get("reason_code") or refusal_payload.get("refusal_code", "refused"),
                "detail": refusal_payload.get("message", "The action was refused."),
            }
        )
    elif decision_receipt is not None and decision_receipt.get("outcome") != "allow":
        flow.append(
            {
                "title": "Execution Stopped",
                "status": decision_receipt.get("outcome", "stopped"),
                "detail": decision_receipt.get("summary", "The scenario stopped before protected execution."),
            }
        )
    return flow


def _build_portable_flow(
    intent_payload: dict[str, Any] | None,
    pccb_payload: dict[str, Any] | None,
    verification_result: dict[str, Any] | None,
    protected_response: dict[str, Any] | None,
) -> list[dict[str, str]]:
    flow = [
        {
            "title": "Action Intent Built",
            "status": "received",
            "detail": _nested_get(intent_payload, "action", "name") or "Portable action intent created.",
        }
    ]
    if pccb_payload is not None:
        flow.append(
            {
                "title": "PCCB Minted",
                "status": "proof_minted",
                "detail": f"PCCB {pccb_payload.get('pccb_id')} was generated for the protected resource demo.",
            }
        )
    if verification_result is not None:
        flow.append(
            {
                "title": "Protected Endpoint Verified Proof",
                "status": "verified",
                "detail": f"Audience {_party_ref_text(verification_result.get('audience'))} accepted request {verification_result.get('request_id')}.",
            }
        )
    if protected_response is not None:
        flow.append(
            {
                "title": "Protected Resource Returned",
                "status": "executed",
                "detail": protected_response.get("message", "Protected resource response emitted."),
            }
        )
    return flow


def _find_state_matches(payload: Any, *, intent_id: str | None, pccb_id: str | None, request_id: str | None, path: str = "state") -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []

    if isinstance(payload, dict):
        if any(
            (
                intent_id and payload.get("intent_id") == intent_id,
                pccb_id and payload.get("pccb_id") == pccb_id,
                request_id and payload.get("request_id") == request_id,
            )
        ):
            matches.append({"path": path, "payload": payload})
        for key, value in payload.items():
            matches.extend(_find_state_matches(value, intent_id=intent_id, pccb_id=pccb_id, request_id=request_id, path=f"{path}.{key}"))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            matches.extend(_find_state_matches(value, intent_id=intent_id, pccb_id=pccb_id, request_id=request_id, path=f"{path}[{index}]"))

    return matches


def _load_replay_entries(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    connection = sqlite3.connect(path, timeout=30.0)
    connection.execute("PRAGMA busy_timeout=30000")
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT replay_key, intent_id, pccb_id, nonce, action_hash, audience, capability,
                   tenant_id, subject_id, status, created_at, updated_at, expires_at, consumed_at,
                   metadata_json
            FROM action_consumption
            ORDER BY created_at ASC
            """
        ).fetchall()
    finally:
        connection.close()

    entries: list[dict[str, Any]] = []
    for row in rows:
        metadata: Any
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except json.JSONDecodeError:
            metadata = {"raw": row["metadata_json"]}
        entries.append(
            {
                "replay_key": row["replay_key"],
                "intent_id": row["intent_id"],
                "pccb_id": row["pccb_id"],
                "nonce": row["nonce"],
                "action_hash": row["action_hash"],
                "audience": row["audience"],
                "capability": row["capability"],
                "tenant_id": row["tenant_id"],
                "subject_id": row["subject_id"],
                "status": row["status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "expires_at": row["expires_at"],
                "consumed_at": row["consumed_at"],
                "metadata": metadata,
            }
        )
    return entries


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_summary_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _build_local_run_summary_lines(*, title: str, section_root: Path, state_path: Path | None, scenarios: Iterable[dict[str, Any]]) -> list[str]:
    lines = [
        f"{title} artifacts loaded.",
        f"Artifact root: {section_root}",
    ]
    if state_path is not None:
        lines.append(f"Protected endpoint state: {state_path}")
    lines.append("Scenario outcomes:")
    for scenario in scenarios:
        receipts = ",".join(scenario.get("receipt_ids", ())) or "none"
        refusals = ",".join(scenario.get("refusal_ids", ())) or "none"
        lines.append(f"- {scenario['scenario']}: {scenario['final_outcome']} (receipts={receipts}; refusals={refusals})")
    return lines


def _payload_for(artifact_map: dict[str, dict[str, Any]], kind: str) -> dict[str, Any] | None:
    artifact = artifact_map.get(kind)
    if artifact is None:
        return None
    payload = artifact.get("payload")
    return payload if isinstance(payload, dict) else payload


def _display_path(path: Path, repo_root: Path) -> str:
    resolved_path = path.resolve()
    try:
        return resolved_path.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return resolved_path.as_posix()


def _path_or_none(raw_path: Any) -> Path | None:
    if not raw_path:
        return None
    return Path(raw_path).resolve()


def _nested_get(payload: Any, *path: str) -> Any:
    current = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _humanize(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _party_ref_text(payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    ref_type = payload.get("type", "unknown")
    ref_id = payload.get("id", "unknown")
    return f"{ref_type}:{ref_id}"


def _tenant_text(payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    return payload.get("tenant_id", "unknown")


def _target_text(payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    return f"{payload.get('resource_type', 'unknown')}:{payload.get('resource_id', 'unknown')}"
