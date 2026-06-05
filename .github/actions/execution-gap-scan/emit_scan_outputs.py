#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


OUTPUT_KEYS = (
    "status",
    "grade",
    "consequence_class",
    "consequence_class_label",
    "gating_status",
    "runtime_reachability",
    "vulnerability_claim",
    "runtime_source_candidate_paths",
    "additional_test_example_context_findings",
    "candidate_consequential_action_paths",
)


def _github_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def _output_value(value: Any) -> str:
    if isinstance(value, bool):
        return _github_bool(value)
    if value is None:
        return ""
    return str(value).replace("\n", " ").replace("\r", " ")


def _check_status(payload: dict[str, Any], key: str) -> str:
    checks = payload.get("checks")
    if not isinstance(checks, dict):
        return "not_assessed"
    check = checks.get(key)
    if not isinstance(check, dict):
        return "not_assessed"
    return _output_value(check.get("status") or "not_assessed")


def _write_outputs(payload: dict[str, Any], output_path: Path) -> None:
    lines = []
    for key in OUTPUT_KEYS:
        lines.append(f"{key}={_output_value(payload.get(key))}")
    for key in sorted(payload.get("checks") or {}):
        lines.append(f"{key}={_check_status(payload, key)}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _render_summary(payload: dict[str, Any]) -> str:
    checks = payload.get("checks") if isinstance(payload.get("checks"), dict) else {}
    lines = [
        "## Actenon Agentic Action Scan",
        "",
        f"- Status: `{_output_value(payload.get('status'))}`",
        f"- Consequence Class: {_output_value(payload.get('consequence_class_label'))}",
        f"- Gating Status: {_output_value(payload.get('gating_status'))}",
        f"- Runtime Reachability: {_output_value(payload.get('runtime_reachability'))}",
        f"- Vulnerability Claim: {_output_value(payload.get('vulnerability_claim'))}",
        f"- Runtime-source candidate paths: {_output_value(payload.get('runtime_source_candidate_paths'))}",
        (
            "- Additional test/example/context findings: "
            f"{_output_value(payload.get('additional_test_example_context_findings'))}"
        ),
        "",
        "This is not a vulnerability severity rating. It is a consequence-class map of candidate action surfaces found by static analysis.",
        "",
        "### Checks",
        "",
    ]
    if checks:
        for key in sorted(checks):
            check = checks[key] if isinstance(checks[key], dict) else {}
            label = _output_value(check.get("label") or key)
            status = _output_value(check.get("status") or "not_assessed")
            summary = _output_value(check.get("summary"))
            lines.append(f"- {label}: `{status}`")
            if summary:
                lines.append(f"  {summary}")
    else:
        lines.append("- No checks were present in the scan report.")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: emit_scan_outputs.py <scan-report.json>", file=sys.stderr)
        return 64

    report_path = Path(argv[1])
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("scan report must be a JSON object")

    output_target = os.environ.get("GITHUB_OUTPUT")
    if output_target:
        _write_outputs(payload, Path(output_target))

    summary_target = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_target:
        summary_path = Path(summary_target)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(_render_summary(payload), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
