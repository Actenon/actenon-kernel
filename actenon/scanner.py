from __future__ import annotations

import json
import re
import time
from fnmatch import fnmatch
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Literal, Mapping, Sequence

from actenon.api import ActionIntentIntakeService
from actenon.core import ProtectedExecutionKernel, RefusalException
from actenon.demo.portable_local_proof import FIXED_BASE_TIME
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.models import ActionIntent, AudienceRef, DynamicContextInput, PCCB, PartyRef, Refusal
from actenon.policy import (
    CapabilityScopeHardRule,
    HardRuleEngine,
    IntentChronologyHardRule,
    IntentTtlHardRule,
    PolicyEngine,
    TenantWorkflowRule,
    TenantWorkflowRuleLayer,
)
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier, VerifierDisclosureMode
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.verifier import ProtectedEndpointMiddleware, VerifierSDK


CheckStatus = Literal["present", "missing", "not_assessed"]
OverallStatus = Literal["NO_OBVIOUS_EXECUTION_GAP_FOUND", "EXECUTION_GAP_PRESENT", "PARTIAL_SCAN_ONLY"]
SCANNER_VERSION = "2.1.0"
REGISTRY_RESOURCE = "scanner_capability_registry.v1.json"

CHECK_SPECS: tuple[tuple[str, str], ...] = (
    ("proof_binding", "Proof check before action"),
    ("replay_protection", "Reused proof cannot be replayed"),
    ("audience_enforcement", "Action intended for this system"),
    ("expiry_enforcement", "Expired proof rejected"),
    ("structured_refusals", "Blocked actions produce refusals"),
    ("credential_broker", "Credentials brokered after approval"),
    ("approval_or_evidence_policy", "High-impact actions require approval/evidence"),
    ("standing_credentials", "Standing credentials visible to agent runtime"),
    ("mcp_tool_boundary", "Tool execution boundary protected"),
)

ScanGrade = Literal["A", "B", "C", "D", "F"]
MarkdownReportMode = Literal["executive", "developer"]
FindingSeverity = Literal["info", "low", "medium", "high", "critical_candidate"]
FindingConfidence = Literal["low", "medium", "high"]
AgentControlContext = Literal["yes", "no", "unknown"]
ProgressCallback = Callable[[str], None]

SCAN_EXCLUDED_DIRS = {
    ".actenon",
    ".git",
    ".github",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__MACOSX",
    "__pycache__",
    "AI Agent Execution Control Layer",
    "actenon_kernel.egg-info",
    "build",
    "dist",
    "node_modules",
    ".cache",
    ".next",
    "coverage",
    "turbo",
    "venv",
}
SCAN_FILE_SUFFIXES = {
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".json",
    ".kt",
    ".mjs",
    ".py",
    ".rb",
    ".rs",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
SCAN_EXCLUDED_FILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
SCAN_EXCLUDED_SUFFIXES = (".min.js",)

DETECTOR_CATEGORY_BY_SURFACE = {
    "S1": "FILE_MUTATION_SIDE_EFFECT",
    "S2": "CLOUD_INFRASTRUCTURE_SIDE_EFFECT",
    "S3": "CREDENTIAL_AUTHORITY_SIGNAL",
    "S4": "EXTERNAL_API_SIDE_EFFECT",
    "S5": "EXTERNAL_API_SIDE_EFFECT",
    "S6": "BROWSER_AGENT_SIDE_EFFECT",
    "S7": "CODING_AGENT_SIDE_EFFECT",
    "S8": "EXTERNAL_API_SIDE_EFFECT",
    "S9": "COMPUTER_USE_AGENT_SIDE_EFFECT",
    "S10": "AGENT_TOOL_REGISTRY_SIGNAL",
    "S11": "DATABASE_MUTATION_SIDE_EFFECT",
    "S12": "WORKFLOW_AUTOMATION_SIDE_EFFECT",
    "S13": "WORKFLOW_AUTOMATION_SIDE_EFFECT",
    "S14": "WORKFLOW_AUTOMATION_SIDE_EFFECT",
    "S15": "WORKFLOW_AUTOMATION_SIDE_EFFECT",
}

CATEGORY_DISPLAY_NAMES = {
    "BROWSER_AGENT_SIDE_EFFECT": "Browser-agent side effect",
    "COMPUTER_USE_AGENT_SIDE_EFFECT": "Computer-use agent side effect",
    "CODING_AGENT_SIDE_EFFECT": "Coding-agent side effect",
    "SHELL_EXECUTION_SIDE_EFFECT": "Shell execution side effect",
    "FILE_MUTATION_SIDE_EFFECT": "File mutation side effect",
    "DATABASE_MUTATION_SIDE_EFFECT": "Database mutation side effect",
    "CLOUD_INFRASTRUCTURE_SIDE_EFFECT": "Cloud/infrastructure side effect",
    "EXTERNAL_API_SIDE_EFFECT": "External API side effect",
    "MCP_TOOL_SIDE_EFFECT": "MCP tool side effect",
    "WORKFLOW_AUTOMATION_SIDE_EFFECT": "Workflow automation side effect",
    "CREDENTIAL_AUTHORITY_SIGNAL": "Credential authority",
    "AGENT_TOOL_REGISTRY_SIGNAL": "Agent tool registry signal",
}

CATEGORY_CONTROL_HINTS = {
    "BROWSER_AGENT_SIDE_EFFECT": "Proof gate + Preflight before high-impact browser actions",
    "COMPUTER_USE_AGENT_SIDE_EFFECT": "Proof gate + session-scoped credential broker",
    "CODING_AGENT_SIDE_EFFECT": "Proof gate + repo/write approval policy",
    "SHELL_EXECUTION_SIDE_EFFECT": "Protected executor + command policy",
    "FILE_MUTATION_SIDE_EFFECT": "Proof gate + Receipt/Refusal",
    "DATABASE_MUTATION_SIDE_EFFECT": "Preflight + brokered database credentials",
    "CLOUD_INFRASTRUCTURE_SIDE_EFFECT": "Preflight + human approval + brokered cloud credentials",
    "EXTERNAL_API_SIDE_EFFECT": "Protected endpoint + credential broker",
    "MCP_TOOL_SIDE_EFFECT": "Protected MCP tool boundary",
    "WORKFLOW_AUTOMATION_SIDE_EFFECT": "Preflight + Receipt/Refusal",
    "CREDENTIAL_AUTHORITY_SIGNAL": "Credential broker",
    "AGENT_TOOL_REGISTRY_SIGNAL": "Proof-bound tool execution boundary",
}

NON_RUNTIME_CONTEXTS = frozenset(
    {
        "TEST_OR_EXAMPLE",
        "DOCS_OR_GENERATED",
        "OFFLINE_MIGRATION",
        "CONFIG",
        "COMMENT_OR_DOC",
        "ENUM_CONSTANT_OR_TYPE_CONTEXT",
    }
)

TEST_OR_EXAMPLE_DIRS = frozenset({"__tests__", "test", "tests", "fixtures", "mocks", "samples", "sample", "demo", "examples", "docs"})

DIRECT_FINANCE_PATTERNS = (
    r"\bpayment\b",
    r"\bpayments\b",
    r"\bcheckout\b",
    r"\binvoice\b",
    r"\binvoices\b",
    r"\brefund\b",
    r"\brefunds\b",
    r"\bsubscription\b",
    r"\bsubscriptions\b",
    r"\bcharge\b",
    r"\bcharges\b",
    r"\bbanking\b",
    r"\bbank_account\b",
    r"\bfinancial[_ -]?commitment\b",
    r"\bbilling\b",
    r"\bpayout\b",
    r"\bpayroll\b",
    r"\brelease_payment\b",
    r"\bpayment\.release\b",
    r"\bpayment[_\-.]?release\b",
    r"\bcreate_charge\b",
    r"\bsubmit_order\b",
    r"\bapprove_invoice\b",
    r"\bissue_refund\b",
    r"\bPaymentIntent\b",
    r"\brefunds\.create\b",
    r"\btransfers\.create\b",
    r"\bpayouts\.create\b",
    r"\bcharges\.create\b",
    r"\bcheckout\.sessions\.create\b",
)

DESTRUCTIVE_PATTERNS = (
    r"\bdatabase\.delete\b",
    r"\bdatabase\.schema\.apply\b",
    r"\binfrastructure\.delete\b",
    r"\bbackup\.delete\b",
    r"\bvolume\.delete\b",
    r"\bmigration\.apply\b",
    r"\bdeployment\.execute\b",
    r"\bdrop\s+database\b",
    r"\bdrop\s+table\b",
    r"\bterraform\s+destroy\b",
    r"\bkubectl\s+delete\b",
    r"\bdelete_?(database|volume|backup|bucket|cluster|deployment)\b",
)
DATA_EXPORT_PATTERNS = (
    r"\bdata\.export\b",
    r"\bcustomer\.export\b",
    r"\bbulk_?export\b",
    r"\bwarehouse\.extract\b",
    r"\bcrm\.bulk_export\b",
)
IAM_PATTERNS = (
    r"\biam\.permission\.grant\b",
    r"\biam\.role\.attach\b",
    r"\bgrant\s+(admin|owner|root)\b",
    r"\battach_?role\b",
)
PROOF_PATTERNS = (
    r"\bPCCBVerifier\b",
    r"\bProtectedEndpointMiddleware\b",
    r"\bProtectedExecutor\b",
    r"\bverify_proof\b",
    r"\bactenon\b",
    r"\bpccb\b",
)
RECEIPT_PATTERNS = (
    r"\bReceiptFactory\b",
    r"\bRefusalFactory\b",
    r"\bReceipt\b",
    r"\bRefusal\b",
    r"\breceipt\b",
    r"\brefusal\b",
)
REPLAY_ESCROW_PATTERNS = (
    r"\bReplayProtector\b",
    r"\bSqliteReplayStore\b",
    r"\bCapabilityEscrow\b",
    r"\bescrow\b",
    r"\breplay\b",
)
CREDENTIAL_BROKER_PATTERNS = (
    r"\bCredentialBroker\b",
    r"\bInMemoryCredentialBroker\b",
    r"\bProtectedExecutor\b",
    r"\bbrokered_credential\b",
    r"\bsecret_reference\b",
)
APPROVAL_EVIDENCE_PATTERNS = (
    r"\bapproval_required\b",
    r"\bapproval-required\b",
    r"\bneeds_evidence\b",
    r"\bneeds-evidence\b",
    r"\brequired_approvals\b",
    r"\brequired_evidence\b",
    r"\bPreflightEngine\b",
)
STANDING_CREDENTIAL_PATTERNS = (
    r"\bAWS_SECRET_ACCESS_KEY\b",
    r"\bGOOGLE_APPLICATION_CREDENTIALS\b",
    r"\bDATABASE_URL\b",
    r"\bSTRIPE_SECRET_KEY\b",
    r"\bPRIVATE_KEY\b",
    r"\bAPI_KEY\b",
    r"\bos\.environ\[[\"'][A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)",
)
MCP_PATTERNS = (
    r"\bFastMCP\b",
    r"\bMCP\b",
    r"\bmcp_server\b",
    r"\bmodelcontextprotocol\b",
    r"@mcp\.tool",
    r"\bmcp\.tool\(",
    r"\bserver\.tool\(",
)
STRONG_MCP_PATTERNS = (
    r"\bFastMCP\b",
    r"\bmodelcontextprotocol\b",
    r"@mcp\.tool",
    r"\bmcp\.tool\(",
    r"\bserver\.tool\(",
    r"\bfrom\s+mcp\b",
    r"\bimport\s+mcp\b",
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(sk_(?:live|test)_[A-Za-z0-9_=-]{8,})"),
    re.compile(r"(?i)\b(xox[baprs]-[A-Za-z0-9-]{8,})"),
    re.compile(r"(?i)\b((?:AKIA|ASIA)[A-Z0-9]{12,})"),
    re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)"),
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?key|secret|token|password|authorization|credential)\b"
        r"(\s*[:=]\s*)"
        r"([\"'])([^\"']{8,})([\"'])"
    ),
)


@dataclass(frozen=True)
class ScanCheck:
    key: str
    label: str
    status: CheckStatus
    summary: str
    reason_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "label": self.label,
            "status": self.status,
            "summary": self.summary,
        }
        if self.reason_code is not None:
            payload["reason_code"] = self.reason_code
        return payload


@dataclass(frozen=True)
class ScanFinding:
    finding_id: str
    category: str
    severity: FindingSeverity
    title: str
    summary: str
    path: str | None = None
    line: int | None = None
    snippet: str | None = None
    remediation: str | None = None
    surface_id: str | None = None
    primitive: str | None = None
    agent_control_context: AgentControlContext = "unknown"
    side_effect_type: str | None = None
    confidence: FindingConfidence = "medium"
    evidence_lines: tuple[int, ...] = ()
    rationale: str | None = None
    recommended_actenon_control: str | None = None
    caveat: str | None = None
    context_classification: str = "RUNTIME_CODE"
    path_type: str = "runtime agent loop"
    surface_name: str | None = None
    credential_signal_kind: str | None = None
    control_gaps: tuple[str, ...] = ()
    controls_present: tuple[str, ...] = ()
    function_name: str | None = None
    generic_control: str | None = None
    actenon_implementation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        consequence_class = _consequence_class(self.severity)
        consequence_label = _consequence_label(self.severity)
        source_context = _source_context_label(self)
        why_this_matters = _why_this_matters(self)
        payload: dict[str, Any] = {
            "finding_id": self.finding_id,
            "category": self.category,
            "surface_id": self.surface_id or self.category,
            "primitive": self.primitive,
            "agent_control_context": self.agent_control_context,
            "side_effect_type": self.side_effect_type,
            "severity": self.severity,
            "consequence_class": consequence_class,
            "consequence_class_label": consequence_label,
            "vulnerability_severity": None,
            "vulnerability_claim": False,
            "finding_type": "Static advisory execution-surface finding",
            "gating_status": _finding_gating_status(self),
            "runtime_reachability": "Not proven",
            "confidence": self.confidence,
            "title": self.title,
            "summary": self.summary,
            "rationale": why_this_matters,
            "why_this_matters": why_this_matters,
            "recommended_generic_control": self.generic_control or _generic_control(self),
            "generic_control": self.generic_control or _generic_control(self),
            "recommended_actenon_control": self.recommended_actenon_control or self.remediation,
            "actenon_implementation": self.actenon_implementation or _actenon_implementation(self),
            "caveat": self.caveat
            or "Static advisory execution-surface finding; runtime reachability, exploitability, production exposure, and business impact are not proven.",
            "context_classification": self.context_classification,
            "source_context": source_context,
            "path_type": self.path_type,
            "surface_name": self.surface_name or self.category,
            "control_gaps": list(self.control_gaps),
            "missing_controls": list(self.control_gaps),
            "nearby_controls_found": list(self.controls_present),
            "evidence_lines": list(self.evidence_lines),
            "function_name": self.function_name,
        }
        if self.credential_signal_kind is not None:
            payload["credential_signal_kind"] = self.credential_signal_kind
        if self.path is not None:
            payload["path"] = self.path
        if self.line is not None:
            payload["line"] = self.line
        if self.snippet is not None:
            payload["snippet"] = self.snippet
        if self.remediation is not None:
            payload["remediation"] = self.remediation
        return payload


@dataclass(frozen=True)
class ScanReport:
    mode: str
    target: str
    overall_status: OverallStatus
    summary: str
    checks: tuple[ScanCheck, ...]
    grade: ScanGrade = "C"
    remediation_steps: tuple[str, ...] = ()
    findings: tuple[ScanFinding, ...] = ()
    badge_markdown: str = ""
    scanner_version: str = SCANNER_VERSION
    registry_version: str = "unknown"
    metadata: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        metadata = dict(self.metadata or {})
        consequence_label = str(metadata.get("consequence_class_label") or _report_consequence_label(self.findings))
        consequence_class = str(metadata.get("consequence_class") or _report_consequence_class(self.findings))
        overall_consequence_label = str(
            metadata.get("highest_overall_consequence_class") or _report_consequence_label(self.findings, include_context=True)
        )
        runtime_proof_status = str(metadata.get("runtime_proof_status") or _runtime_proof_status(self))
        manual_review_required = bool(
            metadata.get("manual_review_required")
            if "manual_review_required" in metadata
            else self.overall_status == "EXECUTION_GAP_PRESENT" or bool(self.findings)
        )
        confidence = str(metadata.get("confidence") or _report_confidence(self.findings))
        categories = tuple(metadata.get("consequential_action_categories_detected") or _detected_categories(self.findings))
        runtime_source_count = int(metadata.get("runtime_source_finding_count") or len(_runtime_source_findings(self.findings)))
        test_context_count = int(
            metadata.get("additional_test_example_context_finding_count") or len(_non_runtime_findings(self.findings))
        )
        return {
            "mode": self.mode,
            "target": self.target,
            "status": self.overall_status,
            "grade": self.grade,
            "consequence_class": consequence_class,
            "consequence_class_label": consequence_label,
            "highest_runtime_source_consequence_class": consequence_label,
            "highest_overall_consequence_class": overall_consequence_label,
            "gating_status": _report_gating_status(self.findings, self.checks),
            "runtime_proof_status": runtime_proof_status,
            "runtime_reachability": "Not proven",
            "vulnerability_claim": False,
            "vulnerability_severity": None,
            "finding_type": "Static advisory execution-surface finding",
            "manual_review_required": manual_review_required,
            "confidence": confidence,
            "candidate_consequential_action_paths": len(self.findings),
            "runtime_source_candidate_paths": runtime_source_count,
            "runtime_source_count": runtime_source_count,
            "test_context_count": test_context_count,
            "additional_test_example_context_findings": test_context_count,
            "categories_detected": list(categories),
            "consequential_action_categories_detected": list(categories),
            "badge_labels": _badge_labels(self),
            "not_vulnerability_severity_explanation": (
                "This is not a vulnerability severity rating. It is a consequence-class map of "
                "candidate action surfaces found by static analysis."
            ),
            "scanner_version": self.scanner_version,
            "registry_version": self.registry_version,
            "summary": self.summary,
            "checks": {check.key: check.to_dict() for check in self.checks},
            "findings": [finding.to_dict() for finding in self.findings],
            "remediation_steps": list(self.remediation_steps),
            "badge_markdown": self.badge_markdown or render_badge_markdown(self),
            "metadata": metadata,
        }


@dataclass(frozen=True)
class ScannerOptions:
    exclude: tuple[str, ...] = ()
    include: tuple[str, ...] = ()
    extensions: tuple[str, ...] | None = None
    max_files: int | None = None
    max_file_size: int = 1_000_000
    timeout_seconds: float | None = None
    partial_report_on_timeout: bool = False
    progress_callback: ProgressCallback | None = None


@dataclass(frozen=True)
class _ScanInventory:
    files: tuple[Path, ...]
    files_discovered: int
    files_scanned: int
    skipped_files: int
    skipped_dirs: int
    partial: bool = False
    timed_out: bool = False
    timeout_reason: str | None = None


def _build_check(key: str, status: CheckStatus, summary: str, *, reason_code: str | None = None) -> ScanCheck:
    label = dict(CHECK_SPECS)[key]
    return ScanCheck(key=key, label=label, status=status, summary=summary, reason_code=reason_code)


def _build_report(
    *,
    mode: str,
    target: str,
    checks: list[ScanCheck],
    findings: list[ScanFinding] | None = None,
    summary_override: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ScanReport:
    findings = list(findings or [])
    missing = [check.label for check in checks if check.status == "missing"]
    not_assessed = [check.label for check in checks if check.status == "not_assessed"]
    if missing:
        overall_status: OverallStatus = "EXECUTION_GAP_PRESENT"
        summary = "One or more execution-edge checks were missing: " + ", ".join(missing) + "."
    elif not_assessed:
        overall_status = "PARTIAL_SCAN_ONLY"
        summary = "No missing checks were observed, but some checks were not assessed in this scan mode: " + ", ".join(not_assessed) + "."
    else:
        overall_status = "NO_OBVIOUS_EXECUTION_GAP_FOUND"
        summary = "All assessed execution-gap checks were observed on the scanned local target."
    if summary_override is not None:
        summary = summary_override
    remediation_steps = _build_remediation_steps(checks=checks, findings=findings)
    grade = _grade_report(checks=checks, findings=findings, overall_status=overall_status)
    report = ScanReport(
        mode=mode,
        target=target,
        overall_status=overall_status,
        summary=summary,
        checks=tuple(checks),
        grade=grade,
        remediation_steps=tuple(remediation_steps),
        findings=tuple(findings),
        registry_version=_registry_version(),
        metadata=metadata,
    )
    return ScanReport(
        mode=report.mode,
        target=report.target,
        overall_status=report.overall_status,
        summary=report.summary,
        checks=report.checks,
        grade=report.grade,
        remediation_steps=report.remediation_steps,
        findings=report.findings,
        badge_markdown=render_badge_markdown(report),
        scanner_version=report.scanner_version,
        registry_version=report.registry_version,
        metadata=report.metadata,
    )


def _build_remediation_steps(*, checks: list[ScanCheck], findings: list[ScanFinding]) -> list[str]:
    steps: list[str] = []
    missing_keys = {check.key for check in checks if check.status == "missing"}
    if "proof_binding" in missing_keys:
        steps.append("Add an Actenon proof gate at the protected endpoint and verify the exact ActionIntent/PCCB before side effects.")
    if "credential_broker" in missing_keys:
        steps.append("Remove standing agent credentials and broker short-lived execution authority inside the protected endpoint.")
    if "structured_refusals" in missing_keys:
        steps.append("Emit structured Receipt/Refusal artifacts for allowed and blocked consequential actions.")
    if "replay_protection" in missing_keys:
        steps.append("Add replay protection and single-use escrow for proof-bearing execution requests.")
    if "approval_or_evidence_policy" in missing_keys:
        steps.append("Add Preflight policy requiring approvals or evidence for production destructive actions, data exports, and privileged grants.")
    if "standing_credentials" in missing_keys:
        steps.append("Move production secrets out of agent runtime paths and into protected endpoint or vault-brokered execution.")
    for finding in findings:
        if finding.remediation and finding.remediation not in steps:
            steps.append(finding.remediation)
    if not steps:
        steps.append("Keep scanner reports private by default and re-run after changing protected endpoints or tool handlers.")
    return steps


def _grade_report(*, checks: list[ScanCheck], findings: list[ScanFinding], overall_status: OverallStatus) -> ScanGrade:
    statuses = {check.key: check.status for check in checks}
    runtime_findings = _runtime_source_findings(tuple(findings))
    severities = {finding.severity for finding in runtime_findings}
    agent_controlled_high = any(
        finding.agent_control_context == "yes"
        and finding.severity in {"high", "critical_candidate"}
        and finding.confidence == "high"
        and "missing proof gate" in finding.control_gaps
        and "missing credential broker" in finding.control_gaps
        and "missing Receipt/Refusal emission" in finding.control_gaps
        and _is_runtime_source_finding(finding)
        for finding in findings
    )
    well_controlled = (
        statuses.get("proof_binding") == "present"
        and statuses.get("structured_refusals") == "present"
        and statuses.get("credential_broker") == "present"
        and statuses.get("replay_protection") == "present"
    )
    if well_controlled and statuses.get("approval_or_evidence_policy") == "present":
        return "A"
    if well_controlled:
        return "B"
    if agent_controlled_high:
        return "F"
    if "critical_candidate" in severities or agent_controlled_high:
        return "D"
    if overall_status == "EXECUTION_GAP_PRESENT":
        if findings:
            return "D"
        return "C"
    if statuses.get("proof_binding") == "present" and statuses.get("structured_refusals") == "present":
        if statuses.get("credential_broker") == "present" and statuses.get("replay_protection") == "present":
            return "A"
        return "B"
    if statuses.get("approval_or_evidence_policy") == "present":
        return "C"
    return "C"


def _consequence_class(severity: FindingSeverity | str) -> str:
    if severity == "critical_candidate":
        return "critical_impact_candidate"
    if severity == "high":
        return "high_impact_candidate"
    if severity == "medium":
        return "medium_impact_candidate"
    return "low_impact_candidate"


def _consequence_label(severity: FindingSeverity | str) -> str:
    return {
        "critical_candidate": "Critical-impact candidate, if reachable and ungated",
        "high": "High-impact candidate, if reachable and ungated",
        "medium": "Medium-impact candidate, if reachable and ungated",
        "low": "Low-impact candidate, if reachable and ungated",
        "info": "Low-impact candidate, if reachable and ungated",
    }.get(str(severity), "Low-impact candidate, if reachable and ungated")


def _highest_finding_by_consequence(findings: tuple[ScanFinding, ...]) -> ScanFinding | None:
    if not findings:
        return None
    return max(findings, key=lambda finding: (_severity_index(finding.severity), 1 if finding.confidence == "high" else 0))


def _report_consequence_class(findings: tuple[ScanFinding, ...], *, include_context: bool = False) -> str:
    candidate_findings = findings if include_context else _runtime_source_findings(findings)
    highest = _highest_finding_by_consequence(candidate_findings)
    if highest is None:
        return "none_detected"
    return _consequence_class(highest.severity)


def _report_consequence_label(findings: tuple[ScanFinding, ...], *, include_context: bool = False) -> str:
    candidate_findings = findings if include_context else _runtime_source_findings(findings)
    highest = _highest_finding_by_consequence(candidate_findings)
    if highest is None:
        return "No runtime-source candidate paths detected"
    return _consequence_label(highest.severity)


def _finding_gating_status(finding: ScanFinding) -> str:
    if finding.control_gaps:
        return "Not verified"
    if finding.controls_present:
        return "Static control signals visible; runtime enforcement not verified"
    return "Not verified"


def _report_gating_status(findings: tuple[ScanFinding, ...], checks: tuple[ScanCheck, ...]) -> str:
    runtime_findings = _runtime_source_findings(findings)
    if any(_finding_gating_status(finding) == "Not verified" for finding in runtime_findings):
        return "Not verified"
    if any(check.status == "missing" for check in checks):
        return "Not verified"
    if runtime_findings:
        return "Static control signals visible; runtime enforcement not verified"
    return "Not applicable"


def _runtime_proof_status(report: ScanReport) -> str:
    if report.mode in {"repo", "mcp", "endpoint"}:
        return "Not Verified"
    if report.mode in {"local", "replay-harness"} and report.overall_status == "NO_OBVIOUS_EXECUTION_GAP_FOUND":
        return "Verified"
    if report.mode == "artifact-pair":
        return "Verified"
    return "Not Verified"


def _report_confidence(findings: tuple[ScanFinding, ...]) -> str:
    findings = _headline_findings(findings)
    if not findings:
        return "Low"
    if any(finding.confidence == "high" for finding in findings):
        return "High"
    if any(finding.confidence == "medium" for finding in findings):
        return "Medium"
    return "Low"


def _detected_categories(findings: tuple[ScanFinding, ...]) -> tuple[str, ...]:
    findings = _headline_findings(findings)
    return tuple(sorted({finding.category for finding in findings}))


def _is_runtime_source_finding(finding: ScanFinding) -> bool:
    return finding.context_classification not in NON_RUNTIME_CONTEXTS


def _runtime_source_findings(findings: tuple[ScanFinding, ...]) -> tuple[ScanFinding, ...]:
    return tuple(finding for finding in findings if _is_runtime_source_finding(finding))


def _non_runtime_findings(findings: tuple[ScanFinding, ...]) -> tuple[ScanFinding, ...]:
    return tuple(finding for finding in findings if not _is_runtime_source_finding(finding))


def _headline_findings(findings: tuple[ScanFinding, ...]) -> tuple[ScanFinding, ...]:
    runtime_findings = _runtime_source_findings(findings)
    return runtime_findings if runtime_findings else findings


def render_badge_markdown(report: ScanReport) -> str:
    if _runtime_source_findings(report.findings):
        return "![Actenon Scan: Review required](https://img.shields.io/badge/Actenon_Scan-review_required-yellow)"
    if _non_runtime_findings(report.findings):
        return "![Actenon Scan: Context review](https://img.shields.io/badge/Actenon_Scan-context_review-blue)"
    return "![Actenon Scan: No runtime candidates](https://img.shields.io/badge/Actenon_Scan-no_runtime_candidates-blue)"


def _badge_labels(report: ScanReport) -> list[str]:
    if _runtime_source_findings(report.findings):
        return [
            "Actenon Scan: Review required",
            f"Gating: {_report_gating_status(report.findings, report.checks)}",
            "Action Surface: Review required",
            f"Consequence Map: {_report_consequence_label(report.findings)}",
        ]
    if _non_runtime_findings(report.findings):
        return [
            "Actenon Scan: Context review",
            "Gating: Not verified",
            "Action Surface: Context findings",
        ]
    return ["Actenon Scan: No runtime candidates", "Gating: Not applicable"]


def _display_category(category: str) -> str:
    return CATEGORY_DISPLAY_NAMES.get(category, category.replace("_", " ").title())


def _display_severity(severity: str) -> str:
    return _consequence_label(severity)


def _display_confidence(confidence: str) -> str:
    return confidence.replace("_", " ").title()


def _finding_location(finding: ScanFinding) -> str:
    if finding.path is None:
        return "Not available"
    location = finding.path
    if finding.line is not None:
        location += f":{finding.line}"
    return location


def _finding_snippet(finding: ScanFinding) -> str:
    if not finding.snippet:
        return "No snippet captured."
    return _redact_sensitive_snippet(finding.snippet.strip())


def _path_context_rank(finding: ScanFinding) -> int:
    if finding.context_classification == "RUNTIME_CODE":
        return 30
    if finding.context_classification == "TEST_OR_EXAMPLE":
        return -20
    if finding.context_classification == "CONFIG":
        return -30
    if finding.context_classification in {"DOCS_OR_GENERATED", "OFFLINE_MIGRATION"}:
        return -40
    return -10


def _path_priority(finding: ScanFinding) -> int:
    path = (finding.path or "").lower()
    name = Path(path).name
    priority = _path_context_rank(finding)
    if finding.path_type == "tool handler":
        priority += 60
    elif finding.path_type == "action registry":
        priority += 45
    elif finding.path_type == "runtime agent loop":
        priority += 25
    if name in {"index.ts", "index.js", "index.mts", "index.mjs", "index.py"}:
        priority += 45
    if name in {"lib.ts", "lib.js", "lib.mts", "lib.mjs", "lib.py"}:
        priority += 40
    if "server" in name or "/server" in path:
        priority += 35
    if any(part in path for part in ("tool", "handler", "registration")):
        priority += 30
    if name in {"package.json", "pyproject.toml"} or finding.path_type == "config":
        priority -= 45
    return priority


def _finding_sort_key(finding: ScanFinding) -> tuple[int, int, int, int, str, int]:
    return (
        1 if _is_runtime_source_finding(finding) else 0,
        _path_priority(finding),
        _severity_index(finding.severity),
        1 if finding.confidence == "high" else 0,
        finding.path or "",
        finding.line or 0,
    )


def _source_context_label(finding: ScanFinding) -> str:
    if finding.context_classification == "RUNTIME_CODE":
        return "runtime_source"
    if finding.context_classification == "OFFLINE_MIGRATION":
        return "migration"
    if finding.context_classification == "CONFIG":
        return "config"
    if finding.path_type == "test":
        return "test"
    if finding.path_type == "example":
        return "example"
    if finding.path_type == "documentation":
        return "docs"
    if finding.path_type == "generated file":
        return "generated"
    if finding.context_classification == "DOCS_OR_GENERATED":
        return "generated"
    if finding.context_classification == "TEST_OR_EXAMPLE":
        return "test_or_example"
    return finding.context_classification.lower()


def _generic_control(finding: ScanFinding) -> str:
    controls: list[str] = []
    gaps = set(finding.control_gaps)
    if "missing proof gate" in gaps or "missing protected tool boundary" in gaps:
        controls.append("add a proof/authorization check before execution")
    if "missing evidence requirement" in gaps or "missing Preflight/policy" in gaps:
        controls.append("add an approval/evidence policy gate")
    if "missing credential broker" in gaps or "standing credential risk" in gaps:
        controls.append("remove standing credentials and broker least-privilege authority")
    if "missing Receipt/Refusal emission" in gaps:
        controls.append("emit an audit receipt/log for allowed and refused decisions")
    if "missing replay/idempotency protection" in gaps:
        controls.append("add replay/idempotency protection")
    if "missing human override" in gaps:
        controls.append("provide human override or escalation for high-impact actions")
    if not controls:
        controls.append("confirm an equivalent approval, authorization, audit, replay, and credential-boundary control before execution")
    return "; ".join(dict.fromkeys(controls)) + "."


def _generic_control_from_candidate(candidate: _CandidateFinding) -> str:
    placeholder = ScanFinding(
        finding_id="placeholder",
        category="placeholder",
        severity="info",
        title="placeholder",
        summary="placeholder",
        control_gaps=candidate.control_gaps,
    )
    return _generic_control(placeholder)


def _actenon_implementation(finding: ScanFinding) -> str:
    controls = []
    gaps = set(finding.control_gaps)
    if "missing Preflight/policy" in gaps or "missing evidence requirement" in gaps:
        controls.append("PreflightEngine")
    if "missing proof gate" in gaps or "missing protected tool boundary" in gaps:
        controls.append("ActionIntent/PCCB proof gate")
        controls.append("ProtectedExecutor")
    if "missing credential broker" in gaps or "standing credential risk" in gaps:
        controls.append("CredentialBroker")
    if "missing Receipt/Refusal emission" in gaps:
        controls.append("Receipt/Refusal")
    if "missing replay/idempotency protection" in gaps:
        controls.append("replay/escrow protection")
    if not controls and finding.recommended_actenon_control:
        controls.extend(part.strip() for part in finding.recommended_actenon_control.split(",") if part.strip())
    if not controls:
        controls.extend(("PreflightEngine", "ActionIntent/PCCB proof gate", "Receipt/Refusal"))
    return "; ".join(dict.fromkeys(controls)) + "."


def _actenon_implementation_from_candidate(candidate: _CandidateFinding) -> str:
    placeholder = ScanFinding(
        finding_id="placeholder",
        category="placeholder",
        severity="info",
        title="placeholder",
        summary="placeholder",
        control_gaps=candidate.control_gaps,
        recommended_actenon_control=", ".join(candidate.surface.recommended_actenon_controls),
    )
    return _actenon_implementation(placeholder)


def _decision_source_text(finding: ScanFinding) -> str:
    if finding.category == "MCP_TOOL_SIDE_EFFECT" or finding.path_type == "tool handler":
        return "an MCP/tool-exposed handler where a model-selected tool call"
    if finding.category == "BROWSER_AGENT_SIDE_EFFECT" or finding.path_type == "browser controller":
        return "a browser-agent controller where a model or workflow decision"
    if finding.category == "COMPUTER_USE_AGENT_SIDE_EFFECT" or finding.path_type == "desktop controller":
        return "a computer-use controller where an agent decision"
    if finding.path_type == "workflow executor":
        return "a workflow executor where an automated decision"
    if finding.agent_control_context == "yes":
        return "an agent-controlled path where a model/tool/workflow decision"
    if finding.agent_control_context == "unknown":
        return "a nearby agent or workflow context where a decision"
    return "a side-effecting code path that static analysis did not prove is agent-controlled but that"


def _side_effect_text(finding: ScanFinding) -> str:
    primitive = (finding.primitive or "side-effect primitive").replace("_", " ")
    side_effect = finding.side_effect_type or _display_category(finding.category)
    return f"{side_effect} via `{primitive}`"


def _why_this_matters(finding: ScanFinding) -> str:
    source = _decision_source_text(finding)
    effect = _side_effect_text(finding)
    missing = [gap.removeprefix("missing ") for gap in finding.control_gaps if gap.startswith("missing ")]
    if missing:
        missing_text = ", ".join(missing[:4])
        return (
            f"This appears to be {source} may reach {effect}. Static analysis did not find a visible "
            f"{missing_text} between the decision source and the side effect. This is the scanner's "
            "model/agent decision -> side effect -> no visible proof gate shape. Runtime reachability, "
            "exploitability, production exposure, and business impact are not proven by this scan."
        )
    return (
        f"This appears to be {source} may reach {effect}. Static analysis found some nearby control signals, "
        "but runtime enforcement and reachability are not proven by this scan."
    )


def _not_visible_text(finding: ScanFinding) -> str:
    missing = [gap.removeprefix("missing ") for gap in finding.control_gaps if gap.startswith("missing ")]
    if missing:
        return "No visible " + ", ".join(missing) + " was found in nearby static analysis."
    if finding.control_gaps:
        return ", ".join(finding.control_gaps)
    return "No specific missing Actenon control was attached to this finding."


def _recommended_control(finding: ScanFinding) -> str:
    if finding.recommended_actenon_control:
        return finding.recommended_actenon_control
    if finding.remediation:
        return finding.remediation
    return CATEGORY_CONTROL_HINTS.get(finding.category, "Add proof-bound execution before consequential side effects.")


def _category_stats(findings: tuple[ScanFinding, ...]) -> list[dict[str, str | int]]:
    stats: list[dict[str, str | int]] = []
    for category in sorted({finding.category for finding in findings}, key=_display_category):
        category_findings = tuple(finding for finding in findings if finding.category == category)
        runtime_findings = _runtime_source_findings(category_findings)
        context_findings = _non_runtime_findings(category_findings)
        headline_findings = runtime_findings if runtime_findings else category_findings
        highest = _highest_finding_by_consequence(headline_findings)
        consequence = _consequence_label(highest.severity) if highest is not None else "No runtime-source candidate paths detected"
        confidence = _report_confidence(headline_findings)
        generic_control = next(
            (finding.generic_control for finding in headline_findings if finding.generic_control),
            _generic_control(headline_findings[0]) if headline_findings else "Review equivalent authorization and audit controls.",
        )
        actenon_impl = next(
            (finding.actenon_implementation for finding in headline_findings if finding.actenon_implementation),
            _actenon_implementation(headline_findings[0]) if headline_findings else "PreflightEngine; ActionIntent/PCCB proof gate; Receipt/Refusal.",
        )
        stats.append(
            {
                "surface": _display_category(category),
                "runtime_count": len(runtime_findings),
                "context_count": len(context_findings),
                "highest_consequence_class": consequence,
                "confidence": confidence,
                "runtime_reachability": "Not proven",
                "gating_status": _report_gating_status(headline_findings, ()),
                "generic_control": generic_control,
                "actenon_implementation": actenon_impl,
            }
        )
    return stats


def _priority_fixes(report: ScanReport) -> list[str]:
    focus_findings = _headline_findings(report.findings)
    gaps = {gap for finding in focus_findings for gap in finding.control_gaps}
    fixes: list[str] = []
    if "missing proof gate" in gaps or any(check.key == "proof_binding" and check.status == "missing" for check in report.checks):
        fixes.append("Add proof-bound ActionIntent/PCCB verification before consequential actions execute.")
    if "missing credential broker" in gaps or any(check.key == "credential_broker" and check.status == "missing" for check in report.checks):
        fixes.append("Broker credentials inside protected endpoints after proof and policy verification.")
    if "missing Preflight/policy" in gaps or any(check.key == "approval_or_evidence_policy" and check.status == "missing" for check in report.checks):
        fixes.append("Add Preflight policy for high-impact actions that need approval or evidence.")
    if "missing Receipt/Refusal emission" in gaps or any(check.key == "structured_refusals" and check.status == "missing" for check in report.checks):
        fixes.append("Emit Receipt/Refusal records for every allowed or blocked consequential action.")
    if "missing replay/idempotency protection" in gaps or any(check.key == "replay_protection" and check.status == "missing" for check in report.checks):
        fixes.append("Add replay/idempotency protection so reused proof cannot trigger duplicate execution.")
    if "missing credential broker" in gaps and "missing proof gate" in gaps:
        fixes.append("Move standing credentials out of agent runtime and into a proof-gated execution boundary.")
    for step in report.remediation_steps:
        if step not in fixes:
            fixes.append(step)
    return fixes[:8]


def _executive_summary_text(report: ScanReport) -> str:
    runtime_findings = _runtime_source_findings(report.findings)
    categories = {finding.category for finding in runtime_findings}
    if "MCP_TOOL_SIDE_EFFECT" in categories and "FILE_MUTATION_SIDE_EFFECT" in categories:
        return (
            "Actenon found MCP tool execution and file mutation paths. Static analysis could not verify "
            "that these actions require proof-bound approval before execution. This is not a vulnerability "
            "claim; it is an advisory map of where proof gates, credential brokering, Preflight policy, "
            "and Receipt/Refusal logging may be needed."
        )
    return (
        "Actenon found candidate AI-controlled action paths in this repository. "
        "Static analysis could not verify that high-impact actions are proof-bound before execution. "
        "This static advisory requires maintainer review."
    )


def _top_runtime_findings(findings: tuple[ScanFinding, ...]) -> tuple[str, ...]:
    runtime_findings = _runtime_source_findings(findings)
    bullets: list[str] = []
    categories = {finding.category for finding in runtime_findings}
    gaps = {gap for finding in runtime_findings for gap in finding.control_gaps}
    if "MCP_TOOL_SIDE_EFFECT" in categories or any(finding.path_type == "tool handler" for finding in runtime_findings):
        bullets.append("MCP tool handler detected without visible proof-bound execution gate.")
    if "FILE_MUTATION_SIDE_EFFECT" in categories:
        bullets.append("File mutation capability detected without visible approval/evidence policy.")
    if "missing Receipt/Refusal emission" in gaps:
        bullets.append("Tool execution path detected without visible Receipt/Refusal emission.")
    if "missing credential broker" in gaps:
        bullets.append("Credential brokering was not visible near candidate runtime action paths.")
    if "missing replay/idempotency protection" in gaps:
        bullets.append("Replay/idempotency protection was not visible for candidate runtime side effects.")
    if not bullets and runtime_findings:
        for finding in sorted(runtime_findings, key=_finding_sort_key, reverse=True)[:3]:
            bullets.append(f"{_display_category(finding.category)} detected in `{_finding_location(finding)}`.")
    return tuple(dict.fromkeys(bullets))


def _render_action_surface_map(lines: list[str], findings: tuple[ScanFinding, ...]) -> None:
    lines.extend(
        [
            "| Surface | Runtime-source candidates | Test/context findings | Highest consequence class | Confidence | Runtime reachability | Gating status | Generic control | Actenon implementation |",
            "| --- | ---: | ---: | --- | --- | --- | --- | --- | --- |",
        ]
    )
    stats = _category_stats(findings)
    if not stats:
        lines.append("| None detected | 0 | 0 | No runtime-source candidate paths detected | Low | Not applicable | Not applicable | Keep existing controls reviewed | Keep protected endpoints and receipts in place |")
        return
    for row in stats:
        generic_control = str(row["generic_control"]).replace("|", "\\|")
        actenon_impl = str(row["actenon_implementation"]).replace("|", "\\|")
        lines.append(
            f"| {row['surface']} | {row['runtime_count']} | {row['context_count']} | "
            f"{row['highest_consequence_class']} | {row['confidence']} | {row['runtime_reachability']} | "
            f"{row['gating_status']} | {generic_control} | {actenon_impl} |"
        )


def _render_finding(lines: list[str], finding: ScanFinding, index: int, *, developer: bool) -> None:
    source_context = _source_context_label(finding)
    missing_controls = ", ".join(finding.control_gaps) if finding.control_gaps else "none visible from this static scan"
    nearby_controls = ", ".join(finding.controls_present) if finding.controls_present else "none visible nearby"
    function_name = finding.function_name or "file-level only; function/class/tool not available"
    line_number = str(finding.line) if finding.line is not None else "file-level only; line-level evidence not available"
    lines.extend(
        [
            f"### Finding {index}: {finding.title}",
            "",
            f"- Finding ID: `{finding.finding_id}`",
            f"- Category: {_display_category(finding.category)} (`{finding.category}`)",
            f"- Surface: `{finding.surface_id or finding.category}` / `{finding.surface_name or finding.category}`",
            f"- Consequence class: {_consequence_label(finding.severity)}",
            f"- Gating status: {_finding_gating_status(finding)}",
            "- Runtime reachability: Not proven",
            "- Vulnerability claim: No",
            f"- Confidence: {_display_confidence(finding.confidence)}",
            f"- File path: `{_finding_location(finding)}`",
            f"- Line: `{line_number}`",
            f"- Function/class/tool: `{function_name}`",
            f"- Source context: `{source_context}`",
            f"- Primitive: `{finding.primitive or 'unknown'}`",
            f"- Agent-control context: `{finding.agent_control_context}`",
            "- Evidence snippet:",
            "```text",
            _finding_snippet(finding),
            "```",
            f"- Nearby controls found: {nearby_controls}",
            f"- Missing controls: {missing_controls}",
            f"- Why this matters: {_why_this_matters(finding)}",
            f"- Generic control: {finding.generic_control or _generic_control(finding)}",
            f"- Actenon implementation: {finding.actenon_implementation or _actenon_implementation(finding)}",
            "- Caveat: "
            + (
                finding.caveat
                or "Static advisory execution-surface finding; runtime reachability, exploitability, production exposure, and business impact are not proven."
            ),
        ]
    )
    if developer:
        lines.extend(
            [
                f"- Path type: `{finding.path_type}`",
                f"- Context classification: `{finding.context_classification}`",
                f"- Legacy internal severity: `{finding.severity}`",
            ]
        )
    lines.append("")


def render_markdown_report(report: ScanReport, *, mode: MarkdownReportMode = "executive") -> str:
    if mode not in {"executive", "developer"}:
        raise ValueError("Markdown report mode must be 'executive' or 'developer'.")

    payload = report.to_dict()
    developer = mode == "developer"
    sorted_findings = sorted(report.findings, key=_finding_sort_key, reverse=True)
    runtime_findings = tuple(finding for finding in sorted_findings if _is_runtime_source_finding(finding))
    context_findings = tuple(finding for finding in sorted_findings if not _is_runtime_source_finding(finding))
    runtime_findings_to_render = runtime_findings if developer else runtime_findings[:7]
    context_findings_to_render = context_findings if developer else context_findings[:3]
    categories = ", ".join(_display_category(category) for category in payload["categories_detected"]) or "None"
    manual_review = "Yes" if payload["manual_review_required"] else "No"
    vulnerability_claim = "Yes" if payload["vulnerability_claim"] else "No"
    lines = [
        "# Actenon Agentic Action Scan",
        "",
        "## Executive Summary",
        "",
        _executive_summary_text(report),
        "",
        f"- Runtime-source candidate paths: {payload['runtime_source_candidate_paths']}",
        f"- Additional test/example/context findings: {payload['additional_test_example_context_findings']}, downgraded by context",
        f"- Consequence Class: {payload['consequence_class_label']}",
        f"- Gating Status: {payload['gating_status']}",
        f"- Runtime Reachability: {payload['runtime_reachability']}",
        f"- Vulnerability Claim: {vulnerability_claim}",
        f"- Manual Review Required: {manual_review}",
        f"- Confidence: {payload['confidence']}",
        f"- Categories Detected: {categories}",
        "",
        "This is not a vulnerability severity rating. It is a consequence-class map of candidate action surfaces found by static analysis.",
        "",
        "Runtime reachability, exploitability, production exposure and business impact are not proven by this scan.",
        "",
        report.summary,
        "",
        "## What This Means",
        "",
        "The scanner found runtime-source locations where an agent, workflow, MCP tool, browser/computer-use controller, or tool handler may be able to reach side effects such as database mutation, file mutation, external API calls, browser actions, operational workflows, access changes, communications, or data transfer.",
        "",
        "## What This Does Not Mean",
        "",
        "This scan does not prove runtime reachability, exploitability, production exposure, business impact, or vulnerability.",
        "",
        "Actenon Scanner maps agent authority. It does not accuse your repo of being vulnerable.",
        "",
        "## Useful Even If You Do Not Use Actenon",
        "",
        "You can use this report even without Actenon. At minimum, review each runtime-source candidate path and confirm there is an equivalent approval, authorization, audit, replay/idempotency and credential-boundary control before execution.",
        "",
        "- Approval gate: the side-effecting call cannot execute until a separate authorization step has run.",
        "- Proof/authorization gate: the exact action and parameters are bound to a verifiable approval.",
        "- Audit receipt: the allowed or refused decision leaves a durable record.",
        "- Replay/idempotency control: the same approval cannot be reused to execute twice.",
        "- Credential boundary: the agent does not hold standing production credentials.",
        "",
        "## Action Surface Map",
        "",
    ]
    _render_action_surface_map(lines, report.findings)

    lines.extend(["", "## Priority Fixes", ""])
    for index, fix in enumerate(_priority_fixes(report), start=1):
        lines.append(f"{index}. {fix}")
    if not _priority_fixes(report):
        lines.append("1. Keep proof-gated execution in place and re-run the scanner after tool or workflow changes.")

    lines.extend(["", "## Top Runtime-Source Findings", ""])
    top_runtime = _top_runtime_findings(report.findings)
    if top_runtime:
        for item in top_runtime[:6]:
            lines.append(f"- {item}")
    else:
        lines.append("- No runtime source finding drove the headline rating in this scan.")

    lines.extend(["", "## Findings", ""])
    if runtime_findings_to_render:
        lines.extend(["### Runtime-Source Findings", ""])
        for index, finding in enumerate(runtime_findings_to_render, start=1):
            _render_finding(lines, finding, index, developer=developer)
        if not developer and len(runtime_findings) > len(runtime_findings_to_render):
            remaining = len(runtime_findings) - len(runtime_findings_to_render)
            lines.append(
                f"_Executive mode shows the top {len(runtime_findings_to_render)} runtime findings. "
                f"{remaining} additional runtime finding(s) are available in developer or JSON mode._"
            )
    elif not context_findings_to_render:
        lines.append("No candidate consequential action findings were emitted for this scan mode.")
    else:
        lines.append("No runtime source findings were emitted. Context findings below are validation evidence only.")

    if context_findings_to_render:
        lines.extend(["", "### Test / Example / Context Findings", ""])
        for index, finding in enumerate(context_findings_to_render, start=1):
            _render_finding(lines, finding, index, developer=developer)
        if not developer and len(context_findings) > len(context_findings_to_render):
            remaining = len(context_findings) - len(context_findings_to_render)
            lines.append(
                f"_Executive mode shows {len(context_findings_to_render)} context finding(s). "
                f"{remaining} additional test/example/context finding(s) are available in developer or JSON mode._"
            )

    lines.extend(["", "## Recommended Integration Points", ""])
    integration_points = list(dict.fromkeys(_recommended_control(finding) for finding in _headline_findings(tuple(sorted_findings))))
    if integration_points:
        lines.append("Generic controls come first; Actenon is one open proof-bound implementation path.")
        lines.append("")
        for item in integration_points[:10]:
            lines.append(f"- {item}")
    else:
        lines.append("- Keep protected endpoints, Preflight policy, Credential Broker, and Receipt/Refusal emission in place.")

    lines.extend(["", "## Scanner Limitations", ""])
    lines.append("- Reports are static advisory and each finding requires maintainer review.")
    lines.append("- Consequence Class is not Vulnerability Severity.")
    lines.append("- Runtime reachability not proven by static analysis.")
    lines.append("- Runtime exploitability not proven by static analysis.")
    lines.append("- Test, example, migration, generated, and documentation paths may reduce confidence.")
    lines.append("- Receipts prove artifact origin and integrity, not business correctness or downstream finality.")
    lines.append("- This scanner does not upload source code or reports by default and does not publish target grades.")

    lines.extend(["", "## Technical Appendix", ""])
    lines.append(f"- Report mode: `{mode}`")
    lines.append(f"- Scanner mode: `{report.mode}`")
    lines.append(f"- Target: `{report.target}`")
    lines.append(f"- Status: `{report.overall_status}`")
    lines.append(f"- Scanner version: `{report.scanner_version}`")
    lines.append(f"- Registry version: `{report.registry_version}`")
    lines.append(f"- Legacy compatibility grade: `{report.grade}`")
    lines.append(f"- Total candidate findings including context: `{payload['candidate_consequential_action_paths']}`")
    lines.append(f"- Highest overall consequence class including context: `{payload['highest_overall_consequence_class']}`")
    lines.append(f"- Badge: {report.badge_markdown or render_badge_markdown(report)}")
    lines.append("")
    lines.append("| Plain-English check | Status | Detail |")
    lines.append("| --- | --- | --- |")
    for check in report.checks:
        detail = check.summary.replace("\n", " ").replace("|", "\\|")
        lines.append(f"| {check.label} | `{check.status}` | {detail} |")

    if developer:
        metadata = dict(report.metadata or {})
        if metadata:
            lines.extend(["", "### Scanner Metadata", ""])
            for key in sorted(metadata):
                value = metadata[key]
                if isinstance(value, list):
                    rendered = ", ".join(str(item) for item in value)
                else:
                    rendered = str(value)
                lines.append(f"- `{key}`: {rendered}")
    else:
        lines.extend(["", "Developer mode includes full finding metadata. JSON mode includes structured machine-readable output."])

    lines.extend(["", "Consequence Class is advisory static analysis, not a certification or exploitability proof."])
    return "\n".join(lines) + "\n"


def _mutated_scalar(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 0.5
    if isinstance(value, str):
        return value + "-scanner-mutation"
    return "scanner-mutation"


def _mutate_intent(intent: ActionIntent) -> ActionIntent:
    payload = deepcopy(intent.to_dict())
    action = payload["action"]
    parameters = action.get("parameters")
    if isinstance(parameters, dict) and parameters:
        first_key = sorted(parameters)[0]
        parameters[first_key] = _mutated_scalar(parameters[first_key])
    else:
        target = payload["target"]
        target["resource_id"] = f"{target['resource_id']}-scanner-mutation"
    return ActionIntentIntakeService().parse(payload)


def _materialize_refusal(
    *,
    request_id: str,
    occurred_at: datetime,
    exc: RefusalException,
    intent: ActionIntent | None,
    context: DynamicContextInput | None,
    pccb: PCCB | None,
) -> Refusal:
    return RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}").create_from_exception(
        exc,
        occurred_at=occurred_at,
        intent=intent,
        context=context,
        pccb_id=pccb.pccb_id if pccb is not None else None,
        escrow_id=pccb.escrow_id if pccb is not None else None,
    )


def scan_artifact_pair(
    *,
    intent: ActionIntent,
    pccb: PCCB,
    sdk: VerifierSDK,
    audience: AudienceRef,
    verification_time: datetime,
    request_id: str,
) -> ScanReport:
    checks: list[ScanCheck] = []
    base_context = sdk.build_context(
        request_id=request_id,
        audience=audience,
        now=verification_time,
        scope_capabilities=pccb.scope.capabilities,
        parameter_constraints=pccb.scope.parameter_constraints,
        resource_selectors=pccb.scope.resource_selectors,
    )

    baseline_error: RefusalException | None = None
    try:
        sdk.verify(intent=intent, pccb=pccb, context=base_context)
    except RefusalException as exc:
        baseline_error = exc

    if baseline_error is not None:
        checks.append(
            _build_check(
                "proof_binding",
                "missing",
                f"Baseline verification failed before proof-binding probes could succeed: {baseline_error.refusal_code}.",
                reason_code=baseline_error.refusal_code,
            )
        )
    else:
        mutated_intent = _mutate_intent(intent)
        try:
            sdk.verify(intent=mutated_intent, pccb=pccb, context=base_context)
        except RefusalException as exc:
            if exc.refusal_code in {"ACTION_MISMATCH", "ACTION_HASH_MISMATCH", "TARGET_MISMATCH", "INTENT_MISMATCH"}:
                checks.append(
                    _build_check(
                        "proof_binding",
                        "present",
                        f"Baseline verification succeeded and a mutated action was refused with {exc.refusal_code}.",
                        reason_code=exc.refusal_code,
                    )
                )
            else:
                checks.append(
                    _build_check(
                        "proof_binding",
                        "missing",
                        f"Mutated action was refused, but not with a proof-binding mismatch signal: {exc.refusal_code}.",
                        reason_code=exc.refusal_code,
                    )
                )
        else:
            checks.append(
                _build_check(
                    "proof_binding",
                    "missing",
                    "A mutated action still verified against the same PCCB in artifact-pair mode.",
                )
            )

    checks.append(
        _build_check(
            "replay_protection",
            "not_assessed",
            "Artifact-pair mode uses the verifier path only and cannot observe protected-endpoint replay enforcement without an execution harness.",
        )
    )

    wrong_audience = AudienceRef(type=audience.type, id=f"{audience.id}-scanner-wrong")
    wrong_audience_context = sdk.build_context(
        request_id=f"{request_id}_wrong_audience",
        audience=wrong_audience,
        now=verification_time,
        scope_capabilities=pccb.scope.capabilities,
        parameter_constraints=pccb.scope.parameter_constraints,
        resource_selectors=pccb.scope.resource_selectors,
    )
    wrong_audience_exc: RefusalException | None = None
    try:
        sdk.verify(intent=intent, pccb=pccb, context=wrong_audience_context)
    except RefusalException as exc:
        wrong_audience_exc = exc
    if wrong_audience_exc is not None and wrong_audience_exc.refusal_code == "AUDIENCE_MISMATCH":
        checks.append(
            _build_check(
                "audience_enforcement",
                "present",
                "A wrong-audience verification attempt was refused with AUDIENCE_MISMATCH.",
                reason_code=wrong_audience_exc.refusal_code,
            )
        )
    elif wrong_audience_exc is not None:
        checks.append(
            _build_check(
                "audience_enforcement",
                "missing",
                f"Wrong-audience verification failed, but not with AUDIENCE_MISMATCH: {wrong_audience_exc.refusal_code}.",
                reason_code=wrong_audience_exc.refusal_code,
            )
        )
    else:
        checks.append(
            _build_check(
                "audience_enforcement",
                "missing",
                "A wrong-audience verification attempt still succeeded in artifact-pair mode.",
            )
        )

    expired_time = pccb.expires_at.astimezone(timezone.utc) + timedelta(seconds=1)
    expired_context = sdk.build_context(
        request_id=f"{request_id}_expired",
        audience=audience,
        now=expired_time,
        scope_capabilities=pccb.scope.capabilities,
        parameter_constraints=pccb.scope.parameter_constraints,
        resource_selectors=pccb.scope.resource_selectors,
    )
    try:
        sdk.verify(intent=intent, pccb=pccb, context=expired_context)
    except RefusalException as exc:
        if exc.refusal_code == "PROOF_EXPIRED":
            checks.append(
                _build_check(
                    "expiry_enforcement",
                    "present",
                    "An expired verification attempt was refused with PROOF_EXPIRED.",
                    reason_code=exc.refusal_code,
                )
            )
        else:
            checks.append(
                _build_check(
                    "expiry_enforcement",
                    "missing",
                    f"Expired verification failed, but not with PROOF_EXPIRED: {exc.refusal_code}.",
                    reason_code=exc.refusal_code,
                )
            )
    else:
        checks.append(
            _build_check(
                "expiry_enforcement",
                "missing",
                "The verifier accepted proof after the PCCB expiry time.",
            )
        )

    if wrong_audience_exc is not None:
        refusal = _materialize_refusal(
            request_id=f"{request_id}_wrong_audience",
            occurred_at=verification_time,
            exc=wrong_audience_exc,
            intent=intent,
            context=wrong_audience_context,
            pccb=pccb,
        )
        if refusal.category == "proof" and refusal.reason_code == "AUDIENCE_MISMATCH":
            checks.append(
                _build_check(
                    "structured_refusals",
                    "present",
                    "The scanner materialized a canonical Refusal artifact from a blocked verification attempt.",
                    reason_code=refusal.reason_code,
                )
            )
        else:
            checks.append(
                _build_check(
                    "structured_refusals",
                    "missing",
                    "Blocked verification did not yield the expected canonical Refusal shape.",
                    reason_code=refusal.reason_code,
                )
            )
    else:
        checks.append(
            _build_check(
                "structured_refusals",
                "missing",
                "Structured refusal handling could not be demonstrated because the wrong-audience probe did not fail as expected.",
            )
        )

    return _build_report(
        mode="artifact-pair",
        target=f"{intent.intent_id} @ {audience.type}:{audience.id}",
        checks=checks,
    )


@dataclass(frozen=True)
class _HarnessState:
    kernel: ProtectedExecutionKernel
    payload: dict[str, Any]
    context: DynamicContextInput


def _build_replay_harness(tempdir: str) -> _HarnessState:
    replay_db = Path(tempdir) / "execution-gap-scan.sqlite3"
    now = FIXED_BASE_TIME
    payload = {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": "intent_execution_gap_scan_001",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "tenant": {"tenant_id": "tenant_alpha"},
        "requester": {"type": "service", "id": "scanner_actor_123"},
        "action": {
            "name": "refund.create",
            "capability": "refund.execute",
            "parameters": {"amount_minor": 1000, "currency": "USD"},
        },
        "target": {"resource_type": "payment", "resource_id": "pay_001"},
    }
    context = DynamicContextInput(
        request_id="req_execution_gap_scan_001",
        audience=AudienceRef(type="service", id="protected-endpoint"),
        scope_capabilities=("refund.execute",),
        now=now,
        facts={"risk_level": "normal"},
    )
    signer = HmacSha256Signer(secret=b"execution-gap-scan-secret", key_id="execution-gap-scan")
    writer = InMemoryOutcomeWriter()
    receipt_factory = ReceiptFactory(receipt_id_factory=lambda: "rcpt_execution_gap_scan")
    refusal_factory = RefusalFactory(refusal_id_factory=lambda: "rfsl_execution_gap_scan")
    escrow = InMemoryCapabilityEscrow()
    replay_protector = ReplayProtector(SqliteReplayStore(replay_db))
    policy = PolicyEngine(
        hard_rules=HardRuleEngine((IntentChronologyHardRule(), IntentTtlHardRule(), CapabilityScopeHardRule())),
        tenant_workflow_rules=TenantWorkflowRuleLayer(
            tenant_rules={
                "tenant_alpha": (
                    TenantWorkflowRule(
                        rule_id="tenant_alpha.refund.allow",
                        outcome="allow",
                        summary="The local scanner harness authorizes the protected refund path.",
                        reason_code="WORKFLOW_ALLOW",
                        capabilities=("refund.execute",),
                        required_fact_values={"risk_level": "normal"},
                    ),
                )
            }
        ),
    )
    middleware = ProtectedEndpointMiddleware(
        proof_verifier=PCCBVerifier(signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
        escrow=escrow,
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=writer,
        replay_protector=replay_protector,
    )
    kernel = ProtectedExecutionKernel(
        intake=ActionIntentIntakeService(),
        policy_engine=policy,
        pccb_minter=PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="service", id="scanner_kernel"),
            pccb_id_factory=lambda: "pccb_execution_gap_scan_001",
            nonce_factory=lambda: "nonce-execution-gap-scan-0001",
        ),
        escrow=escrow,
        middleware=middleware,
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=writer,
        escrow_id_factory=lambda: "esc_execution_gap_scan_001",
    )
    return _HarnessState(kernel=kernel, payload=payload, context=context)


def _submit_admission(harness: _HarnessState):
    admission = harness.kernel.submit_intent(harness.payload, harness.context)
    if admission.intent is None or admission.pccb is None:
        raise ValueError("local scanner harness did not produce an executable protected request")
    return admission


def _execute_request(harness: _HarnessState, *, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput):
    request = harness.kernel.build_execution_request(intent=intent, pccb=pccb, context=context)
    return harness.kernel.execute(request, lambda req: {"external_reference": "scan_exec_001"})


def scan_replay_harness() -> ScanReport:
    checks: list[ScanCheck] = []

    with TemporaryDirectory() as tempdir:
        harness = _build_replay_harness(tempdir)
        admission = _submit_admission(harness)
        mutated_intent = _mutate_intent(admission.intent)
        result = _execute_request(harness, intent=mutated_intent, pccb=admission.pccb, context=harness.context)
        if result.refusal is not None and result.refusal.reason_code in {"ACTION_MISMATCH", "ACTION_HASH_MISMATCH", "TARGET_MISMATCH", "INTENT_MISMATCH"}:
            checks.append(
                _build_check(
                    "proof_binding",
                    "present",
                    f"The protected endpoint refused a mutated execution attempt with {result.refusal.reason_code}.",
                    reason_code=result.refusal.reason_code,
                )
            )
        else:
            checks.append(
                _build_check(
                    "proof_binding",
                    "missing",
                    "The local protected-endpoint harness did not refuse a mutated execution attempt as a proof-binding failure.",
                )
            )

    with TemporaryDirectory() as tempdir:
        harness = _build_replay_harness(tempdir)
        admission = _submit_admission(harness)
        first = _execute_request(harness, intent=admission.intent, pccb=admission.pccb, context=harness.context)
        duplicate = _execute_request(harness, intent=admission.intent, pccb=admission.pccb, context=harness.context)
        if first.refusal is None and duplicate.refusal is not None and duplicate.refusal.reason_code == "DUPLICATE_REPLAY":
            checks.append(
                _build_check(
                    "replay_protection",
                    "present",
                    "The local protected-endpoint harness refused a duplicate execution attempt with DUPLICATE_REPLAY.",
                    reason_code=duplicate.refusal.reason_code,
                )
            )
        else:
            checks.append(
                _build_check(
                    "replay_protection",
                    "missing",
                    "The local protected-endpoint harness did not refuse a duplicate execution attempt as replay.",
                )
            )

    with TemporaryDirectory() as tempdir:
        harness = _build_replay_harness(tempdir)
        admission = _submit_admission(harness)
        wrong_context = DynamicContextInput(
            request_id="req_execution_gap_scan_wrong_audience",
            audience=AudienceRef(type="service", id="wrong-protected-endpoint"),
            scope_capabilities=harness.context.scope_capabilities,
            now=harness.context.now,
            facts=dict(harness.context.facts),
        )
        result = _execute_request(harness, intent=admission.intent, pccb=admission.pccb, context=wrong_context)
        if result.refusal is not None and result.refusal.reason_code == "AUDIENCE_MISMATCH":
            checks.append(
                _build_check(
                    "audience_enforcement",
                    "present",
                    "The local protected-endpoint harness refused a wrong-audience execution attempt with AUDIENCE_MISMATCH.",
                    reason_code=result.refusal.reason_code,
                )
            )
        else:
            checks.append(
                _build_check(
                    "audience_enforcement",
                    "missing",
                    "The local protected-endpoint harness did not surface AUDIENCE_MISMATCH on a wrong-audience execution attempt.",
                )
            )

    with TemporaryDirectory() as tempdir:
        harness = _build_replay_harness(tempdir)
        admission = _submit_admission(harness)
        expired_context = DynamicContextInput(
            request_id="req_execution_gap_scan_expired",
            audience=harness.context.audience,
            scope_capabilities=harness.context.scope_capabilities,
            now=admission.pccb.expires_at.astimezone(timezone.utc) + timedelta(seconds=1),
            facts=dict(harness.context.facts),
        )
        result = _execute_request(harness, intent=admission.intent, pccb=admission.pccb, context=expired_context)
        if result.refusal is not None and result.refusal.reason_code == "PROOF_EXPIRED":
            checks.append(
                _build_check(
                    "expiry_enforcement",
                    "present",
                    "The local protected-endpoint harness refused an expired execution attempt with PROOF_EXPIRED.",
                    reason_code=result.refusal.reason_code,
                )
            )
        else:
            checks.append(
                _build_check(
                    "expiry_enforcement",
                    "missing",
                    "The local protected-endpoint harness did not surface PROOF_EXPIRED after the proof validity window.",
                )
            )

    with TemporaryDirectory() as tempdir:
        harness = _build_replay_harness(tempdir)
        admission = _submit_admission(harness)
        wrong_context = DynamicContextInput(
            request_id="req_execution_gap_scan_refusal_shape",
            audience=AudienceRef(type="service", id="wrong-protected-endpoint"),
            scope_capabilities=harness.context.scope_capabilities,
            now=harness.context.now,
            facts=dict(harness.context.facts),
        )
        result = _execute_request(harness, intent=admission.intent, pccb=admission.pccb, context=wrong_context)
        if result.refusal is not None and result.receipt is not None and result.refusal.reason_code == "AUDIENCE_MISMATCH":
            checks.append(
                _build_check(
                    "structured_refusals",
                    "present",
                    "Blocked execution produced both a canonical Refusal artifact and a refused Receipt in the local harness.",
                    reason_code=result.refusal.reason_code,
                )
            )
        else:
            checks.append(
                _build_check(
                    "structured_refusals",
                    "missing",
                    "Blocked execution did not produce the expected canonical Refusal and refused Receipt pair in the local harness.",
                )
            )

    return _build_report(
        mode="replay-harness",
        target="built-in replay-protected local harness",
        checks=checks,
    )


def scan_local() -> ScanReport:
    harness_report = scan_replay_harness()
    checks = list(harness_report.checks)
    checks.append(
        _build_check(
            "credential_broker",
            "not_assessed",
            "Local harness mode exercises proof, replay, expiry, audience, and refusal behavior but does not inspect a deployment-specific credential broker.",
        )
    )
    return _build_report(
        mode="local",
        target="built-in local scanner harness",
        checks=checks,
        findings=list(harness_report.findings),
        summary_override=(
            "The local scanner harness observed proof binding, replay protection, audience enforcement, expiry enforcement, "
            "and structured refusal behavior. Credential brokering must be assessed on a concrete endpoint or repo path."
        ),
    )


@dataclass(frozen=True)
class _CodeHit:
    path: Path
    line: int
    snippet: str
    file_text: str = ""
    evidence_lines: tuple[int, ...] = ()


@dataclass(frozen=True)
class _SurfaceSpec:
    surface_id: str
    name: str
    side_effect_type: str
    signal_patterns: tuple[str, ...]
    import_patterns: tuple[str, ...]
    call_patterns: tuple[str, ...]
    path_patterns: tuple[str, ...]
    base_severity: FindingSeverity
    recommended_actenon_controls: tuple[str, ...]
    remediation: str
    caveats: str


@dataclass(frozen=True)
class _CandidateFinding:
    surface: _SurfaceSpec
    primitive: str
    hit: _CodeHit
    context_classification: str
    agent_control_context: AgentControlContext
    confidence: FindingConfidence
    control_gaps: tuple[str, ...]
    controls_present: tuple[str, ...]
    capability_signal_only: bool = False


_REGISTRY_CACHE: dict[str, Any] | None = None


def _load_registry() -> dict[str, Any]:
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is None:
        registry_path = Path(__file__).with_name(REGISTRY_RESOURCE)
        _REGISTRY_CACHE = json.loads(registry_path.read_text(encoding="utf-8"))
    return _REGISTRY_CACHE


def _registry_version() -> str:
    return str(_load_registry().get("registry_version", "unknown"))


def _registry_surfaces() -> tuple[_SurfaceSpec, ...]:
    surfaces: list[_SurfaceSpec] = []
    for raw in _load_registry().get("surfaces", []):
        if not isinstance(raw, Mapping):
            continue
        surfaces.append(
            _SurfaceSpec(
                surface_id=str(raw["surface_id"]),
                name=str(raw["name"]),
                side_effect_type=str(raw["side_effect_type"]),
                signal_patterns=tuple(raw.get("signal_patterns", [])),
                import_patterns=tuple(raw.get("import_patterns", [])),
                call_patterns=tuple(raw.get("call_patterns", [])),
                path_patterns=tuple(raw.get("path_patterns", [])),
                base_severity=str(raw.get("base_severity", "medium")),  # type: ignore[arg-type]
                recommended_actenon_controls=tuple(raw.get("recommended_actenon_controls", [])),
                remediation=str(raw.get("remediation", "")),
                caveats=str(raw.get("caveats", "")),
            )
        )
    return tuple(surfaces)


AGENT_CONTEXT_PATTERNS = (
    r"\bagent\b",
    r"agent",
    r"\bdecision\b",
    r"decision",
    r"\baction\b",
    r"\bworkflow\b",
    r"\btask\b",
    r"tool",
    r"\btool_call\b",
    r"\bfunction_call\b",
    r"\bavailable_tools\b",
    r"\bexecute_tool\b",
    r"\brun_tool\b",
    r"\binvoke_tool\b",
    r"\bplanner\b",
    r"\bexecutor\b",
    r"\bautonomous\b",
    r"\bllm\b",
    r"\bmodel\b",
    r"\bchain\b",
    r"\bcrew\b",
    r"\blangchain\b",
    r"\bllamaindex\b",
    r"\bautogen\b",
    r"\bcrewai\b",
    r"\bsemantic_kernel\b",
    r"\bopenai\b",
    r"\banthropic\b",
    r"\bmcp\b",
    r"\bbrowser agent\b",
    r"\bcomputer use\b",
    r"\bscheduler\b",
    r"\bbackground worker\b",
    r"\bplan_and_execute\b",
)

SIDE_EFFECT_PRIMITIVE_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "mutating_http",
        (
            r"\brequests\.(post|put|patch|delete)\(",
            r"\bhttpx\.(post|put|patch|delete)\(",
            r"\baxios\.(post|put|patch|delete)\(",
            r"\bfetch\([^\\n]*(POST|PUT|PATCH|DELETE)",
            r"\b[a-zA-Z_][\w.]*\.request\(\s*[\"'](POST|PUT|PATCH|DELETE)[\"']",
            r"\brequest\(\s*[\"'](POST|PUT|PATCH|DELETE)[\"']",
        ),
    ),
    ("graphql_mutation", (r"\bmutation\s+[A-Za-z_]", r"\bmutate\(")),
    (
        "database_write",
        (
            r"\b(insert|update|delete|upsert)\b",
            r"\bexecute\([^\\n]*(DELETE|UPDATE|INSERT|ALTER|DROP|TRUNCATE)",
            r"\bsession\.add\(",
            r"\bsession\.commit\(",
            r"\bcollection\.(insert|update|delete)",
            r"\bvector_store\.(add|upsert|delete)",
        ),
    ),
    (
        "file_mutation",
        (
            r"\bwrite_file\(",
            r"\bdelete_file\(",
            r"\bmove_file\(",
            r"\bwriteFile\(",
            r"\bdeleteFile\(",
            r"\bfs\.writeFile",
            r"\bfs\.promises\.writeFile",
            r"\bfs\.unlink",
            r"\bwrite_text\(",
            r"\bwrite_bytes\(",
            r"\bunlink\(",
            r"\bunlinkSync\(",
            r"\brmtree\(",
            r"\bremove\(",
            r"\bshutil\.move\(",
            r"\bopen\([^\\n]*[\"']w[ab+]*[\"']",
        ),
    ),
    (
        "shell_execution",
        (
            r"\bsubprocess\.",
            r"\bos\.system\(",
            r"\bshell=True",
            r"\beval\(",
            r"\bexec\(",
            r"\bterminal\.(run|execute)",
            r"\bexecute_command\(",
            r"\brun_shell\(",
        ),
    ),
    (
        "browser_navigation",
        (
            r"\bpage\.goto\(",
            r"\.goto\(",
            r"\bnew_page\(",
            r"\bopen_tab\(",
            r"\bclose_tab\(",
        ),
    ),
    (
        "browser_action",
        (
            r"\bpage\.click\(",
            r"\blocator\([^\\n]*\)\.click\(",
            r"\.click\(",
            r"\bpage\.fill\(",
            r"\blocator\([^\\n]*\)\.fill\(",
            r"\.fill\(",
            r"\bpage\.press\(",
            r"\bkeyboard\.press\(",
            r"\bmouse\.click\(",
            r"\bpage\.evaluate\(",
            r"\.submit\(",
            r"upload_file\(",
            r"\bdownload\(",
            r"\bstorage_state\(",
            r"\bcookies?\b",
            r"\blogin\b",
        ),
    ),
    (
        "desktop_action",
        (
            r"\bpyautogui\.",
            r"\bxdotool\b",
            r"\bmouse\.(click|move|scroll)",
            r"\bkeyboard\.(type|press|write)",
            r"\bclipboard\b",
            r"\bVNC\b",
            r"\bnoVNC\b",
            r"\bremote_desktop\b",
            r"\bopen_application\(",
        ),
    ),
    ("screen_observation", (r"\bscreenshot\(", r"\bscreen observation\b", r"\bobserve_screen\(", r"\bget_screenshot\(")),
    ("queue_or_event_publish", (r"\bpublish\(", r"\bemit\(", r"\bsend_webhook\(")),
    (
        "tool_invocation",
        (r"\bexecute_tool\(", r"\brun_tool\(", r"\binvoke_tool\(", r"@mcp\.tool", r"\bmcp\.tool\(", r"\bserver\.tool\("),
    ),
)

ACTENON_CONTROL_PATTERNS = {
    "proof gate": (
        r"\bActionIntent\b",
        r"\bPCCB\b",
        r"\bproof_verifier\b",
        r"\bproof_gate\b",
        r"\binvoke_protected_tool\b",
        r"\bPCCBVerifier\b",
        r"\bProtectedEndpointMiddleware\b",
        r"\bverify_proof\b",
        r"\bactenon\b",
    ),
    "credential broker": (r"\bCredentialBroker\b", r"\bBrokeredCredential\b", r"\bbrokered_credential\b", r"\bsecret_reference\b", r"\bProtectedExecutor\b"),
    "preflight/policy": (r"\bPreflightEngine\b", r"\bPolicyEngine\b", r"\ballow/deny\b", r"\bpolicy\b", r"\bhuman approval\b"),
    "receipt/refusal": (r"\bReceipt\b", r"\bRefusal\b", r"\bReceiptFactory\b", r"\bRefusalFactory\b", r"\breceipt\b", r"\brefusal\b"),
    "replay/idempotency": (r"\bReplayProtector\b", r"\bidempotenc", r"\breplay\b", r"\bescrow\b", r"\bconsume\b"),
}

GENERIC_CONTROL_PATTERNS = {
    "human override": (r"\bhuman[_ -]?override\b", r"\bescalation\b"),
    "approval/evidence": (r"\bapproval\b", r"\bevidence\b", r"\brequired_approvals\b", r"\brequired_evidence\b"),
    "audit log": (r"\baudit\b", r"\blog_event\b"),
    "dry-run": (r"\bdry[_-]?run\b",),
    "environment guard": (r"\benvironment\b", r"\bproduction\b", r"\bstaging\b"),
    "transaction limit": (r"\blimit\b", r"\bmax_amount\b", r"\bthreshold\b"),
    "rollback path": (r"\brollback\b", r"\bbackup\b"),
}

STRONG_SECRET_PATTERNS = (
    r"os\.environ\[[\"'][^\"']*(SECRET|TOKEN|KEY|PASSWORD)",
    r"os\.getenv\([\"'][^\"']*(SECRET|TOKEN|KEY|PASSWORD)",
    r"getenv\([\"'][^\"']*(SECRET|TOKEN|KEY|PASSWORD)",
    r"os\.environ\[[\"'](DATABASE_URL|POSTGRES_URL|MYSQL_URL|SQLALCHEMY_DATABASE_URI|[^\"']*DSN|[^\"']*CONNECTION_STRING)[\"']",
    r"os\.getenv\([\"'](DATABASE_URL|POSTGRES_URL|MYSQL_URL|SQLALCHEMY_DATABASE_URI|[^\"']*DSN|[^\"']*CONNECTION_STRING)[\"']",
    r"getenv\([\"'](DATABASE_URL|POSTGRES_URL|MYSQL_URL|SQLALCHEMY_DATABASE_URI|[^\"']*DSN|[^\"']*CONNECTION_STRING)[\"']",
    r"AWS_SECRET_ACCESS_KEY\s*=",
    r"AWS_ACCESS_KEY_ID\s*=",
    r"GOOGLE_APPLICATION_CREDENTIALS\s*=",
    r"AZURE_CLIENT_SECRET\s*=",
    r"STRIPE_SECRET_KEY\s*=",
    r"OPENAI_API_KEY\s*=",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"decrypt_text\(",
    r"\bvault\b",
    r"\bsecret_manager\b",
    r"boto3\.client\([\"']secretsmanager[\"']",
    r"keyring\.get_password\(",
    r"[\"']sk_live_[A-Za-z0-9_]{12,}[\"']",
)

CREDENTIAL_AUTHORITY_BYPASS_PATTERNS = (
    r"\b(OpenAI|Anthropic|WebClient|StripeClient|SlackClient|Github|GitHub|Gitlab|GitLab)\([^\\n]*(api[_-]?key|token|credential|authorization)",
    r"\b[A-Za-z_][\w]*(Client|Session|Connector)\([^\\n]*(api[_-]?key|token|credential|authorization)",
    r"\bstripe\.api_key\s*=",
    r"\brequests\.Session\(",
    r"\bboto3\.(client|resource|Session)\(",
    r"\bgoogle\.auth\.default\(",
    r"\bDefaultAzureCredential\(",
    r"\bcreate_engine\([^\\n]*(DATABASE_URL|POSTGRES_URL|SQLALCHEMY_DATABASE_URI|db_url|database_url)",
    r"\b(psycopg|psycopg2|asyncpg)\.(connect|create_pool)\([^\\n]*(DATABASE_URL|POSTGRES_URL|db_url|database_url)",
    r"\bstorage_state\s*=",
    r"\b(state|cookies|session)_path\s*=",
    r"\b(load|read|restore)_(cookies|session|storage_state)\(",
    r"\bcontext\.add_cookies\(",
    r"\bcookies?\.json\b",
)

WEAK_CREDENTIAL_KEYWORDS = (
    r"\bapi_key\b",
    r"\btoken\b",
    r"\bsecret\b",
    r"\bcredential\b",
    r"\bcaller_type\b",
    r"\bauth_type\b",
)


def _compile_patterns(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(pattern.search(text) for pattern in _compile_patterns(patterns))


def _normalize_extension(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        return cleaned
    return cleaned if cleaned.startswith(".") else f".{cleaned}"


def _effective_suffixes(options: ScannerOptions | None) -> set[str]:
    if options is None or options.extensions is None:
        return set(SCAN_FILE_SUFFIXES)
    return {_normalize_extension(value) for value in options.extensions if _normalize_extension(value)}


def _path_matches_any(path: Path, root: Path, patterns: Sequence[str]) -> bool:
    if not patterns:
        return False
    relative = _relative_path(path, root)
    return any(
        fnmatch(relative, pattern)
        or fnmatch(path.name, pattern)
        or pattern.strip("/") in relative
        for pattern in patterns
    )


def _emit_progress(options: ScannerOptions | None, message: str) -> None:
    if options is not None and options.progress_callback is not None:
        options.progress_callback(message)


def _collect_scan_files(root: Path, options: ScannerOptions | None = None) -> _ScanInventory:
    options = options or ScannerOptions()
    start = time.monotonic()
    suffixes = _effective_suffixes(options)
    files: list[Path] = []
    discovered = 0
    skipped_files = 0
    skipped_dirs = 0
    partial = False
    timed_out = False
    timeout_reason: str | None = None

    def timed_out_now() -> bool:
        return options.timeout_seconds is not None and time.monotonic() - start >= options.timeout_seconds

    def should_skip_file(path: Path) -> bool:
        if path.name in SCAN_EXCLUDED_FILES or any(path.name.endswith(suffix) for suffix in SCAN_EXCLUDED_SUFFIXES):
            return True
        if path.suffix.lower() not in suffixes:
            return True
        if options.include and not _path_matches_any(path, root, options.include):
            return True
        if options.exclude and _path_matches_any(path, root, options.exclude):
            return True
        try:
            if options.max_file_size is not None and path.stat().st_size > options.max_file_size:
                return True
        except OSError:
            return True
        return False

    if root.is_file():
        discovered = 1
        if should_skip_file(root):
            skipped_files = 1
            files = []
        else:
            files = [root]
        return _ScanInventory(
            files=tuple(files),
            files_discovered=discovered,
            files_scanned=len(files),
            skipped_files=skipped_files,
            skipped_dirs=0,
        )

    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if timed_out_now():
            partial = True
            timed_out = True
            timeout_reason = f"timed out after {options.timeout_seconds} second(s) while discovering files"
            break
        if path.is_dir():
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                relative_parts = path.parts
            if any(part in SCAN_EXCLUDED_DIRS for part in relative_parts) or (
                options.exclude and _path_matches_any(path, root, options.exclude)
            ):
                skipped_dirs += 1
            continue
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in SCAN_EXCLUDED_DIRS for part in relative_parts):
            skipped_files += 1
            continue
        discovered += 1
        if should_skip_file(path):
            skipped_files += 1
            continue
        files.append(path)
        if len(files) % 500 == 0:
            _emit_progress(options, f"actenon scan: files discovered={discovered} files queued={len(files)} skipped={skipped_files}")
        if options.max_files is not None and len(files) >= options.max_files:
            partial = True
            timeout_reason = f"stopped after max_files={options.max_files}"
            break
    _emit_progress(
        options,
        f"actenon scan: discovery complete files discovered={discovered} files scanned={len(files)} skipped_files={skipped_files} skipped_dirs={skipped_dirs}",
    )
    return _ScanInventory(
        files=tuple(files),
        files_discovered=discovered,
        files_scanned=len(files),
        skipped_files=skipped_files,
        skipped_dirs=skipped_dirs,
        partial=partial,
        timed_out=timed_out,
        timeout_reason=timeout_reason,
    )


def _iter_scan_files(root: Path) -> tuple[Path, ...]:
    return _collect_scan_files(root).files


def _scan_file_for_first_hit(path: Path, patterns: tuple[str, ...]) -> _CodeHit | None:
    compiled = _compile_patterns(patterns)
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    for line_number, line in enumerate(lines, start=1):
        if any(pattern.search(line) for pattern in compiled):
            return _CodeHit(
                path=path,
                line=line_number,
                snippet=_evidence_snippet(lines, line_number - 1),
                file_text="\n".join(lines),
                evidence_lines=_evidence_line_numbers(lines, line_number - 1),
            )
    return None


def _scan_repository_text(files: tuple[Path, ...]) -> str:
    chunks: list[str] = []
    for path in files:
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    return "\n".join(chunks)


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _finding(
    *,
    finding_id: str,
    category: str,
    severity: FindingSeverity,
    title: str,
    summary: str,
    hit: _CodeHit | None,
    root: Path,
    remediation: str,
) -> ScanFinding:
    return ScanFinding(
        finding_id=finding_id,
        category=category,
        severity=severity,
        title=title,
        summary=summary,
        path=_relative_path(hit.path, root) if hit is not None else None,
        line=hit.line if hit is not None else None,
        snippet=hit.snippet if hit is not None else None,
        remediation=remediation,
    )


def _path_context(path: Path, root: Path, content: str) -> str:
    relative = _relative_path(path, root).lower()
    parts = set(Path(relative).parts)
    if (
        "migrations" in parts
        or "alembic" in parts
        or "/alembic/versions/" in f"/{relative}"
        or "from alembic import op" in content
        or "import alembic.op" in content
        or ("def upgrade(" in content and "def downgrade(" in content)
    ):
        return "OFFLINE_MIGRATION"
    if any(part in parts for part in TEST_OR_EXAMPLE_DIRS) or Path(relative).name.lower().startswith("test"):
        return "TEST_OR_EXAMPLE"
    if (
        Path(relative).name.lower().startswith("readme")
        or "generated" in parts
        or "vendor" in parts
        or "dist" in parts
        or "build" in parts
    ):
        return "DOCS_OR_GENERATED"
    if Path(relative).name.lower() in {
        ".env",
        ".env.example",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "settings.py",
        "config.py",
    }:
        return "CONFIG"
    return "RUNTIME_CODE"


def _path_type(path: Path, root: Path, content: str, line: str, context_classification: str) -> str:
    relative = _relative_path(path, root).lower()
    name = Path(relative).name.lower()
    parts = set(Path(relative).parts)
    combined = f"{relative}\n{content}\n{line}"
    if context_classification == "OFFLINE_MIGRATION":
        return "database migration"
    if "tests" in parts or "test" in parts or "__tests__" in parts or name.startswith("test_") or name.endswith("_test.py"):
        return "test"
    if any(part in parts for part in {"fixtures", "mocks", "samples", "sample", "demo", "examples"}):
        return "example"
    if context_classification == "TEST_OR_EXAMPLE":
        if "docs" in parts or name.startswith("readme"):
            return "documentation"
        return "example"
    if context_classification == "DOCS_OR_GENERATED":
        if "docs" in parts or name.startswith("readme"):
            return "documentation"
        return "generated file"
    if context_classification == "CONFIG":
        return "config"
    if _matches_any(combined, (r"\bFastMCP\b", r"@mcp\.tool", r"\bmcp\.tool\(", r"\bserver\.tool\(", r"\bmodelcontextprotocol\b")):
        return "tool handler"
    if _matches_any(combined, (r"\bavailable_tools\b", r"\btool_registry\b", r"\bexecute_tool\b", r"\brun_tool\b", r"\binvoke_tool\b")):
        return "action registry"
    if _matches_any(combined, (r"\bpage\.", r"\blocator\(", r"\bplaywright\b", r"\bselenium\b", r"\bpuppeteer\b", r"\bbrowser_use\b", r"\bstagehand\b")):
        return "browser controller"
    if _matches_any(combined, (r"\bpyautogui\b", r"\bxdotool\b", r"\bVNC\b", r"\bnoVNC\b", r"\bremote_desktop\b", r"\bdesktop\b")):
        return "desktop controller"
    if _matches_any(combined, (r"\b@app\.(post|put|patch|delete)\b", r"\bAPIRouter\b", r"\bFastAPI\b", r"\brouter\.(post|put|patch|delete)\b")):
        return "API endpoint"
    if _matches_any(combined, (r"\bwebhook\b", r"\bhandle_webhook\b")):
        return "webhook handler"
    if _matches_any(combined, (r"\bworker\b", r"\bbackground\b", r"\bqueue\b", r"\bscheduler\b", r"\bcron\b")):
        return "background worker"
    if _matches_any(combined, (r"\bworkflow\b", r"\bdag\b", r"\bjob\b", r"\btask\b")):
        return "workflow executor"
    if _matches_any(combined, (r"\bsubprocess\b", r"\bos\.system\b", r"\bshell=True\b", r"\bterminal\b")):
        return "CLI command"
    if any(part in parts for part in {"integrations", "connectors", "clients", "adapters"}):
        return "integration connector"
    if _matches_any(combined, AGENT_CONTEXT_PATTERNS):
        return "runtime agent loop"
    return "runtime agent loop"


def _line_context(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith(("#", "//", "/*", "*", '"""', "'''")):
        return "COMMENT_OR_DOC"
    if "Literal[" in line or "typing.Literal" in line:
        return "ENUM_CONSTANT_OR_TYPE_CONTEXT"
    if re.search(r"\b(Enum|StrEnum)\b", line):
        return "ENUM_CONSTANT_OR_TYPE_CONTEXT"
    if re.search(r"^\s*[A-Z][A-Z0-9_]*\s*=\s*[\"']", line):
        return "ENUM_CONSTANT_OR_TYPE_CONTEXT"
    if re.search(r"^\s*(class|type)\s+", line) or re.search(r":\s*(str|int|Literal|Enum)\b", line):
        return "ENUM_CONSTANT_OR_TYPE_CONTEXT"
    return None


def _redact_sensitive_snippet(snippet: str) -> str:
    redacted = snippet
    redacted = SECRET_VALUE_PATTERNS[0].sub("sk_[REDACTED]", redacted)
    redacted = SECRET_VALUE_PATTERNS[1].sub("xox[REDACTED]", redacted)
    redacted = SECRET_VALUE_PATTERNS[2].sub("[REDACTED_AWS_ACCESS_KEY]", redacted)
    redacted = SECRET_VALUE_PATTERNS[3].sub(r"\1[REDACTED]\2", redacted)
    redacted = SECRET_VALUE_PATTERNS[4].sub(r"\1\2\3[REDACTED]\5", redacted)
    return redacted


def _window(lines: list[str], line_index: int, radius: int = 12) -> str:
    start = max(0, line_index - radius)
    end = min(len(lines), line_index + radius + 1)
    return "\n".join(lines[start:end])


def _evidence_line_numbers(lines: list[str], line_index: int, radius: int = 2) -> tuple[int, ...]:
    start = max(0, line_index - radius)
    end = min(len(lines), line_index + radius + 1)
    return tuple(range(start + 1, end + 1))


def _evidence_snippet(lines: list[str], line_index: int, radius: int = 2) -> str:
    start = max(0, line_index - radius)
    end = min(len(lines), line_index + radius + 1)
    rendered: list[str] = []
    for index in range(start, end):
        marker = ">" if index == line_index else " "
        line = _redact_sensitive_snippet(lines[index].rstrip())[:260]
        rendered.append(f"{marker} {index + 1:4} | {line}")
    return "\n".join(rendered)


def _extract_enclosing_symbol(file_text: str, line_number: int) -> str | None:
    if not file_text or line_number <= 0:
        return None
    lines = file_text.splitlines()
    hit_index = min(line_number - 1, len(lines) - 1)
    start = max(0, hit_index - 80)
    nearby_before = lines[start : hit_index + 1]
    nearby_after = lines[hit_index : min(len(lines), hit_index + 6)]
    for line in reversed(nearby_before):
        for pattern in (
            r"@mcp\.tool\(name=[\"']([^\"']+)[\"']",
            r"\bmcp\.tool\(name=[\"']([^\"']+)[\"']",
            r"\bserver\.tool\([\"']([^\"']+)[\"']",
            r"\btool\([\"']([^\"']+)[\"']",
        ):
            match = re.search(pattern, line)
            if match:
                return match.group(1)
    for line in nearby_after:
        for pattern in (
            r"@mcp\.tool\(name=[\"']([^\"']+)[\"']",
            r"\bmcp\.tool\(name=[\"']([^\"']+)[\"']",
            r"\bserver\.tool\([\"']([^\"']+)[\"']",
            r"\btool\([\"']([^\"']+)[\"']",
        ):
            match = re.search(pattern, line)
            if match:
                return match.group(1)
    for line in reversed(nearby_before):
        for pattern in (
            r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(",
            r"^\s*class\s+([A-Za-z_]\w*)\s*[:(]",
            r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(",
            r"^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(",
        ):
            match = re.search(pattern, line)
            if match:
                return match.group(1)
    return None


def _detect_primitive(line: str) -> str | None:
    if _matches_any(
        line,
        (
            r"\bpyautogui\.",
            r"\bxdotool\b",
            r"\bVNC\b",
            r"\bnoVNC\b",
            r"\bremote_desktop\b",
            r"\bopen_application\(",
        ),
    ):
        return "desktop_action"
    for primitive, patterns in SIDE_EFFECT_PRIMITIVE_PATTERNS:
        if _matches_any(line, patterns):
            return primitive
    return None


def _detect_agent_context(*, window_text: str, file_text: str) -> AgentControlContext:
    if _matches_any(window_text, AGENT_CONTEXT_PATTERNS):
        return "yes"
    if _matches_any(file_text, AGENT_CONTEXT_PATTERNS):
        return "unknown"
    return "no"


def _detect_controls(window_text: str, file_text: str) -> tuple[str, ...]:
    controls: list[str] = []
    combined = f"{window_text}\n{file_text}"
    for label, patterns in {**ACTENON_CONTROL_PATTERNS, **GENERIC_CONTROL_PATTERNS}.items():
        if _matches_any(combined, patterns):
            controls.append(label)
    return tuple(sorted(set(controls)))


def _control_gaps(controls_present: tuple[str, ...], *, agent_context: AgentControlContext) -> tuple[str, ...]:
    gaps: list[str] = []
    if "proof gate" not in controls_present:
        gaps.append("missing proof gate")
    if "credential broker" not in controls_present:
        gaps.append("missing credential broker")
    if "preflight/policy" not in controls_present:
        gaps.append("missing Preflight/policy")
    if "approval/evidence" not in controls_present:
        gaps.append("missing evidence requirement")
    if "receipt/refusal" not in controls_present:
        gaps.append("missing Receipt/Refusal emission")
    if "replay/idempotency" not in controls_present:
        gaps.append("missing replay/idempotency protection")
    if agent_context == "yes" and "human override" not in controls_present:
        gaps.append("missing human override")
    return tuple(gaps)


def _is_strong_secret_line(line: str) -> bool:
    return _matches_any(line, STRONG_SECRET_PATTERNS)


def _is_credential_bypass_line(line: str) -> bool:
    return _matches_any(line, CREDENTIAL_AUTHORITY_BYPASS_PATTERNS)


def _is_standing_credential_line(line: str) -> bool:
    return _is_strong_secret_line(line) or _is_credential_bypass_line(line)


def _is_suppressed_credential_keyword(*, line: str, path_context: str) -> bool:
    return (
        path_context in {"OFFLINE_MIGRATION", "TEST_OR_EXAMPLE", "DOCS_OR_GENERATED", "CONFIG"}
        and _matches_any(line, WEAK_CREDENTIAL_KEYWORDS)
        and not _is_standing_credential_line(line)
    )


def _is_scaffolding_line(line: str) -> bool:
    return _matches_any(line, (r"\bsys\.path\.insert\(",))


def _severity_index(severity: FindingSeverity) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical_candidate": 4}[severity]


def _severity_from_candidate(candidate: _CandidateFinding) -> FindingSeverity:
    severity = candidate.surface.base_severity
    path_type = _path_type(
        candidate.hit.path,
        candidate.hit.path.parent,
        candidate.hit.file_text,
        candidate.hit.snippet,
        candidate.context_classification,
    )
    if (
        candidate.surface.surface_id == "S6"
        and candidate.primitive in {"consequential_surface", "browser_navigation", "screen_observation"}
        and _matches_any(
            candidate.hit.snippet,
            (
                r"\.goto\(",
                r"\bscreenshot\(",
                r"\bget_screenshot\(",
                r"\bbrowser_context\b",
                r"\bchromium\b",
                r"\bplaywright\b",
                r"\bselenium\b",
                r"\bpuppeteer\b",
                r"\bbrowser_use\b",
                r"\bstagehand\b",
            ),
        )
        and not _matches_any(
            candidate.hit.snippet,
            (r"\.click\(", r"\.fill\(", r"\.press\(", r"\.submit\(", r"upload_file\(", r"storage_state\(", r"\blogin\b", r"\bcookie"),
        )
    ):
        severity = "low"
    if candidate.primitive == "standing_credential_signal":
        credential_kind = _credential_signal_kind(candidate.hit.snippet)
        if credential_kind == "runtime_credential_authority" and candidate.context_classification == "CONFIG":
            severity = "medium"
        elif credential_kind == "runtime_credential_authority":
            severity = "high"
        elif credential_kind == "hardcoded_secret_material":
            severity = "critical_candidate"
    if candidate.agent_control_context == "yes" and severity == "medium":
        severity = "high"
    if (
        candidate.agent_control_context == "yes"
        and candidate.surface.surface_id in {"S2", "S3", "S4", "S9", "S12", "S15"}
        and "missing proof gate" in candidate.control_gaps
    ):
        severity = "critical_candidate"
    if (
        candidate.context_classification == "RUNTIME_CODE"
        and path_type == "tool handler"
        and "missing proof gate" in candidate.control_gaps
        and candidate.agent_control_context in {"yes", "unknown"}
    ):
        severity = "critical_candidate" if candidate.confidence == "high" else "high"
    elif (
        candidate.context_classification == "RUNTIME_CODE"
        and Path(candidate.hit.path.name).name.lower() in {"lib.ts", "lib.js", "lib.mts", "lib.mjs", "lib.py"}
        and _severity_index(severity) < _severity_index("high")
    ):
        severity = "high"
    if candidate.context_classification == "TEST_OR_EXAMPLE":
        severity = "low"
    elif candidate.context_classification in {"DOCS_OR_GENERATED", "CONFIG"}:
        severity = "low" if _severity_index(severity) >= _severity_index("medium") else severity
    if candidate.context_classification == "OFFLINE_MIGRATION" and candidate.surface.surface_id == "S1":
        severity = "low"
    if "proof gate" in candidate.controls_present and "receipt/refusal" in candidate.controls_present:
        severity = "low" if _severity_index(severity) <= _severity_index("medium") else "medium"
    return severity


def _confidence_from_context(
    *,
    capability_signal_only: bool,
    context_classification: str,
    agent_control_context: AgentControlContext,
) -> FindingConfidence:
    if context_classification in {"DOCS_OR_GENERATED", "TEST_OR_EXAMPLE", "CONFIG"}:
        return "low"
    if capability_signal_only:
        return "medium"
    if agent_control_context == "yes":
        return "high"
    return "medium"


def _surface_patterns(surface: _SurfaceSpec) -> tuple[str, ...]:
    return (
        surface.signal_patterns
        + surface.import_patterns
        + surface.call_patterns
        + surface.path_patterns
    )


def _has_direct_finance_evidence(line: str, path: Path, root: Path) -> bool:
    relative = _relative_path(path, root).lower()
    if _matches_any(
        line,
        (
            r"\b(PaymentIntent|payment_intent)\b",
            r"\b(refunds|transfers|payouts|charges|checkout\.sessions)\.create\b",
            r"\b(release_payment|create_charge|approve_invoice|submit_order|issue_refund)\(",
            r"\bpayment\.(release|refund|charge|transfer|payout|capture|create|approve)\b",
            r"\bpayment[_\-.]?release\b",
            r"\b(stripe|paypal|adyen|plaid)\.[a-zA-Z0-9_.]*(create|refund|charge|transfer|payout|checkout|invoice)",
            r"\b(charge|refund|payout|transfer|invoice|subscription|billing|bank_detail|payroll|tax)\w*\(",
        ),
    ):
        return True
    finance_path = any(part in Path(relative).parts for part in {"payments", "billing", "finance", "invoices", "checkout"})
    return finance_path and _matches_any(line, DIRECT_FINANCE_PATTERNS)


def _line_matches_surface(line: str, path: Path, root: Path, surface: _SurfaceSpec) -> bool:
    relative = _relative_path(path, root).lower()
    primitive = _detect_primitive(line)
    if surface.surface_id == "S4" and not _has_direct_finance_evidence(line, path, root):
        return False
    if surface.surface_id == "S6" and primitive in {"browser_action", "browser_navigation", "desktop_action", "screen_observation"}:
        return True
    if surface.surface_id == "S7" and primitive == "shell_execution":
        return True
    if surface.surface_id == "S1" and primitive in {"database_write", "file_mutation"}:
        return True
    if surface.surface_id == "S8" and primitive in {"mutating_http", "graphql_mutation", "queue_or_event_publish"}:
        return True
    if surface.surface_id == "S10" and primitive == "tool_invocation":
        return True
    if _matches_any(line, surface.signal_patterns + surface.import_patterns + surface.call_patterns):
        return True
    if surface.surface_id == "S10":
        return False
    return _detect_primitive(line) is not None and any(pattern.lower() in relative for pattern in surface.path_patterns)


def _unknown_capability_surface() -> _SurfaceSpec:
    return _SurfaceSpec(
        surface_id="UNKNOWN_CAPABILITY",
        name="UNKNOWN_HIGH_CAPABILITY_PATH",
        side_effect_type="unclassified side-effect capability",
        signal_patterns=(),
        import_patterns=(),
        call_patterns=(),
        path_patterns=(),
        base_severity="medium",
        recommended_actenon_controls=("PreflightEngine", "ActionIntent/PCCB proof gate", "Receipt/Refusal"),
        remediation=(
            "Review the candidate path and add proof-bound execution, Preflight/policy, "
            "credential brokering, and Receipt/Refusal if it can trigger side effects."
        ),
        caveats="Specific action type was not classified; runtime reachability not proven; runtime exploitability not proven.",
    )


def _detect_unknown_capability(line: str, window_text: str) -> str | None:
    if _detect_primitive(line) is not None:
        return _detect_primitive(line)
    if _matches_any(window_text, (r"\b(auth|token|session|client|api_key|credential)\b",)) and _matches_any(
        line,
        (r"\b(execute|run|invoke|submit|update|delete|create|send|publish|upload|approve|cancel)\w*\(",),
    ):
        return "capability_reachability_signal"
    if _matches_any(window_text, AGENT_CONTEXT_PATTERNS) and _matches_any(
        line,
        (
            r"\b[a-zA-Z_]\w*\.(execute|run|invoke|submit|update|delete|create|send|publish|upload|approve|cancel)\w*\(",
            r"\b(execute|run|invoke|submit|update|delete|create|send|publish|upload|approve|cancel)\w*\(",
        ),
    ):
        return "capability_reachability_signal"
    return None


def _strong_mcp_signal(text: str) -> bool:
    return _matches_any(text, STRONG_MCP_PATTERNS)


def _detector_category(candidate: _CandidateFinding) -> str:
    primitive = candidate.primitive
    surface_id = candidate.surface.surface_id
    text = f"{candidate.hit.snippet}\n{candidate.hit.file_text}"
    if primitive in {"browser_action", "browser_navigation", "screen_observation"}:
        return "BROWSER_AGENT_SIDE_EFFECT"
    if primitive == "desktop_action":
        return "COMPUTER_USE_AGENT_SIDE_EFFECT"
    if primitive == "shell_execution":
        return "SHELL_EXECUTION_SIDE_EFFECT"
    if primitive == "file_mutation":
        return "FILE_MUTATION_SIDE_EFFECT"
    if primitive == "database_write":
        return "DATABASE_MUTATION_SIDE_EFFECT"
    if primitive == "tool_invocation":
        if _strong_mcp_signal(text) or (surface_id == "S10" and _matches_any(text, (r"\bmcp\b", r"\bFastMCP\b", r"@mcp\.tool", r"\bserver\.tool\("))):
            return "MCP_TOOL_SIDE_EFFECT"
        return "AGENT_TOOL_REGISTRY_SIGNAL"
    if primitive in {"mutating_http", "graphql_mutation", "queue_or_event_publish"}:
        return "EXTERNAL_API_SIDE_EFFECT"
    if primitive == "standing_credential_signal":
        return "CREDENTIAL_AUTHORITY_SIGNAL"
    if _strong_mcp_signal(text) or (surface_id == "S10" and _matches_any(text, (r"\bmcp\b", r"\bFastMCP\b", r"@mcp\.tool", r"\bserver\.tool\("))):
        return "MCP_TOOL_SIDE_EFFECT"
    return DETECTOR_CATEGORY_BY_SURFACE.get(surface_id, "AGENT_TOOL_REGISTRY_SIGNAL")


def _credential_signal_kind(line: str) -> str | None:
    if not _is_standing_credential_line(line):
        return None
    if _matches_any(line, (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"[\"']sk_live_[A-Za-z0-9_]{12,}[\"']")):
        return "hardcoded_secret_material"
    if _matches_any(
        line,
        (
            r"os\.environ",
            r"os\.getenv",
            r"getenv\(",
            r"\bvault\b",
            r"\bsecret_manager\b",
            r"secretsmanager",
            r"keyring\.get_password",
        ),
    ) or _is_credential_bypass_line(line):
        return "runtime_credential_authority"
    return "credential_authority_signal"


def _build_candidate_finding(
    *,
    candidate: _CandidateFinding,
    root: Path,
) -> ScanFinding:
    severity = _severity_from_candidate(candidate)
    controls = ", ".join(candidate.surface.recommended_actenon_controls)
    detector_category = _detector_category(candidate)
    path_type = _path_type(
        candidate.hit.path,
        root,
        candidate.hit.file_text,
        candidate.hit.snippet,
        candidate.context_classification,
    )
    credential_kind = _credential_signal_kind(candidate.hit.snippet)
    control_gaps = list(candidate.control_gaps)
    if detector_category == "MCP_TOOL_SIDE_EFFECT" and "missing proof gate" in control_gaps:
        control_gaps.append("missing protected tool boundary")
    if candidate.capability_signal_only:
        title = "Candidate consequential path detected via capability signals"
        summary = (
            "Actenon Scanner found a candidate consequential action path detected via capability signals; "
            "specific action type not classified; runtime reachability not proven; runtime exploitability not proven; maintainer review recommended."
        )
    elif candidate.primitive == "standing_credential_signal" and credential_kind == "runtime_credential_authority":
        title = "Runtime credential authority signal"
        summary = (
            "Actenon Scanner found a credential authority signal such as environment, vault, keyring, or provider-secret access. "
            "This is not classified as hardcoded secret exposure by itself; it is a static advisory signal that agent/tool paths "
            "may have standing authority and requires maintainer review."
        )
    elif candidate.primitive == "standing_credential_signal" and credential_kind == "hardcoded_secret_material":
        title = "Candidate hardcoded secret material"
        summary = (
            "Actenon Scanner found candidate hardcoded secret material. Static analysis cannot validate whether the value is live, "
            "but this requires maintainer review and should not be exposed to agents or public artifacts."
        )
    else:
        title = f"Candidate {candidate.surface.name} path"
        summary = (
            "Actenon Scanner found a candidate consequential action path. "
            f"Surface `{candidate.surface.surface_id}` indicates {candidate.surface.side_effect_type}; "
            f"agent-control context is `{candidate.agent_control_context}`; "
            "this is a static advisory; runtime reachability not proven; runtime exploitability not proven; maintainer review is recommended."
        )
    return ScanFinding(
        finding_id=f"{candidate.surface.surface_id.lower()}-{candidate.primitive}-{candidate.hit.line}",
        category=detector_category,
        surface_id=candidate.surface.surface_id,
        primitive=candidate.primitive,
        agent_control_context=candidate.agent_control_context,
        side_effect_type=candidate.surface.side_effect_type,
        severity=severity,
        confidence=candidate.confidence,
        title=title,
        summary=summary,
        path=_relative_path(candidate.hit.path, root),
        line=candidate.hit.line,
        snippet=candidate.hit.snippet,
        evidence_lines=candidate.hit.evidence_lines or (candidate.hit.line,),
        rationale=None,
        recommended_actenon_control=controls,
        caveat=candidate.surface.caveats,
        context_classification=candidate.context_classification,
        path_type=path_type,
        surface_name=candidate.surface.name,
        credential_signal_kind=credential_kind,
        control_gaps=tuple(dict.fromkeys(control_gaps)),
        controls_present=candidate.controls_present,
        function_name=_extract_enclosing_symbol(candidate.hit.file_text, candidate.hit.line),
        generic_control=_generic_control_from_candidate(candidate),
        actenon_implementation=_actenon_implementation_from_candidate(candidate),
        remediation=candidate.surface.remediation,
    )


def _dedupe_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    deduped: dict[tuple[str, str | None, str | None], ScanFinding] = {}
    for finding in findings:
        key = (finding.surface_id or finding.category, finding.path, finding.primitive)
        existing = deduped.get(key)
        if existing is None or _finding_sort_key(finding) > _finding_sort_key(existing):
            deduped[key] = finding
    return sorted(
        deduped.values(),
        key=_finding_sort_key,
        reverse=True,
    )


def _detect_repository_candidates(
    scan_root: Path,
    files: tuple[Path, ...],
    *,
    options: ScannerOptions | None = None,
) -> tuple[list[ScanFinding], dict[str, Any]]:
    options = options or ScannerOptions()
    start = time.monotonic()
    surfaces = _registry_surfaces()
    findings: list[ScanFinding] = []
    suppressed_credential_keywords = 0
    strong_secret_hits = 0
    all_controls: set[str] = set()
    any_agent_context = False
    any_primitive = False
    path_context_counts: dict[str, int] = {}
    partial = False
    timed_out = False
    timeout_reason: str | None = None
    scanned_files = 0
    stop_scan = False

    def timed_out_now() -> bool:
        return options.timeout_seconds is not None and time.monotonic() - start >= options.timeout_seconds

    for path in files:
        if stop_scan:
            break
        if timed_out_now():
            partial = True
            timed_out = True
            timeout_reason = f"timed out after {options.timeout_seconds} second(s) while scanning files"
            if not options.partial_report_on_timeout:
                raise TimeoutError(timeout_reason)
            break
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned_files += 1
        if scanned_files % 250 == 0:
            _emit_progress(options, f"actenon scan: current phase=scanning files_scanned={scanned_files} findings_so_far={len(findings)}")
        lines = content.splitlines()
        path_context = _path_context(path, scan_root, content)
        path_context_counts[path_context] = path_context_counts.get(path_context, 0) + 1
        file_context_text = f"{content}\n{_relative_path(path, scan_root)}"
        inside_docstring = False
        for line_index, line in enumerate(lines):
            if line_index and line_index % 500 == 0 and timed_out_now():
                partial = True
                timed_out = True
                timeout_reason = f"timed out after {options.timeout_seconds} second(s) while scanning file {path.name}"
                if not options.partial_report_on_timeout:
                    raise TimeoutError(timeout_reason)
                stop_scan = True
                break
            stripped = line.strip()
            if inside_docstring:
                if '"""' in stripped or "'''" in stripped:
                    inside_docstring = False
                continue
            if stripped.startswith(('"""', "'''")):
                marker = stripped[:3]
                if stripped.count(marker) == 1:
                    inside_docstring = True
                continue
            line_number = line_index + 1
            line_specific_context = _line_context(line)
            context = line_specific_context or path_context
            if line_specific_context in {"COMMENT_OR_DOC", "ENUM_CONSTANT_OR_TYPE_CONTEXT"} and not _is_standing_credential_line(line):
                if _matches_any(line, WEAK_CREDENTIAL_KEYWORDS):
                    suppressed_credential_keywords += 1
                continue
            if _is_scaffolding_line(line):
                continue
            if _is_suppressed_credential_keyword(line=line, path_context=path_context):
                suppressed_credential_keywords += 1
                continue
            window_text = _window(lines, line_index)
            controls_present = _detect_controls(window_text, content)
            all_controls.update(controls_present)
            agent_context = _detect_agent_context(window_text=window_text, file_text=file_context_text)
            any_agent_context = any_agent_context or agent_context in {"yes", "unknown"}
            primitive = _detect_primitive(line)
            any_primitive = any_primitive or primitive is not None

            if _is_standing_credential_line(line):
                strong_secret_hits += 1
                secret_surface = _registry_surfaces()[2] if len(_registry_surfaces()) >= 3 else _unknown_capability_surface()
                candidate = _CandidateFinding(
                    surface=secret_surface,
                    primitive="standing_credential_signal",
                    hit=_CodeHit(
                        path=path,
                        line=line_number,
                        snippet=_evidence_snippet(lines, line_index),
                        file_text=content,
                        evidence_lines=_evidence_line_numbers(lines, line_index),
                    ),
                    context_classification=context,
                    agent_control_context=agent_context,
                    confidence="high",
                    control_gaps=("standing credential risk",),
                    controls_present=controls_present,
                )
                findings.append(_build_candidate_finding(candidate=candidate, root=scan_root))

            matched_surface = False
            for surface in surfaces:
                if path_context == "OFFLINE_MIGRATION" and surface.surface_id == "S3" and not _is_standing_credential_line(line):
                    continue
                if path_context == "OFFLINE_MIGRATION" and surface.surface_id == "S10" and not _strong_mcp_signal(f"{content}\n{line}"):
                    continue
                if not _line_matches_surface(line, path, scan_root, surface):
                    continue
                matched_surface = True
                candidate = _CandidateFinding(
                    surface=surface,
                    primitive=primitive or "consequential_surface",
                    hit=_CodeHit(
                        path=path,
                        line=line_number,
                        snippet=_evidence_snippet(lines, line_index),
                        file_text=content,
                        evidence_lines=_evidence_line_numbers(lines, line_index),
                    ),
                    context_classification=context,
                    agent_control_context=agent_context,
                    confidence=_confidence_from_context(
                        capability_signal_only=False,
                        context_classification=context,
                        agent_control_context=agent_context,
                    ),
                    control_gaps=_control_gaps(controls_present, agent_context=agent_context),
                    controls_present=controls_present,
                )
                findings.append(_build_candidate_finding(candidate=candidate, root=scan_root))

            if not matched_surface:
                unknown_primitive = _detect_unknown_capability(line, window_text)
                if unknown_primitive and agent_context in {"yes", "unknown"}:
                    surface = _unknown_capability_surface()
                    candidate = _CandidateFinding(
                        surface=surface,
                        primitive=unknown_primitive,
                        hit=_CodeHit(
                            path=path,
                            line=line_number,
                            snippet=_evidence_snippet(lines, line_index),
                            file_text=content,
                            evidence_lines=_evidence_line_numbers(lines, line_index),
                        ),
                        context_classification=context,
                        agent_control_context=agent_context,
                        confidence=_confidence_from_context(
                            capability_signal_only=True,
                            context_classification=context,
                            agent_control_context=agent_context,
                        ),
                        control_gaps=_control_gaps(controls_present, agent_context=agent_context),
                        controls_present=controls_present,
                        capability_signal_only=True,
                    )
                    findings.append(_build_candidate_finding(candidate=candidate, root=scan_root))

    deduped = _dedupe_findings(findings)
    runtime_finding_count = sum(1 for finding in deduped if _is_runtime_source_finding(finding))
    non_runtime_finding_count = sum(1 for finding in deduped if not _is_runtime_source_finding(finding))
    test_or_example_finding_count = sum(1 for finding in deduped if finding.context_classification == "TEST_OR_EXAMPLE")
    metadata = {
        "controls": tuple(sorted(all_controls)),
        "suppressed_credential_keywords": suppressed_credential_keywords,
        "credential_keyword_suppressed_in_migration": suppressed_credential_keywords,
        "strong_secret_hits": strong_secret_hits,
        "any_agent_context": any_agent_context,
        "any_primitive": any_primitive,
        "offline_migration_context": path_context_counts.get("OFFLINE_MIGRATION", 0),
        "downgraded_test_fixture_context": test_or_example_finding_count,
        "test_or_example_context": test_or_example_finding_count,
        "runtime_source_finding_count": runtime_finding_count,
        "additional_test_example_context_finding_count": non_runtime_finding_count,
        "test_or_example_finding_count": test_or_example_finding_count,
        "context_classifications": tuple(sorted(path_context_counts)),
        "files_scanned_by_detector": scanned_files,
        "partial": partial,
        "timed_out": timed_out,
        "timeout_reason": timeout_reason,
    }
    return deduped, metadata


def _repository_text_has_strong_mcp(scan_root: Path, files: tuple[Path, ...]) -> bool:
    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _path_context(path, scan_root, content) == "OFFLINE_MIGRATION" and not _strong_mcp_signal(content):
            continue
        if _strong_mcp_signal(content) or "mcp" in _relative_path(path, scan_root).lower():
            return True
    return False


def scan_repository(
    root: str | Path = ".",
    *,
    mode: str = "repo",
    options: ScannerOptions | None = None,
) -> ScanReport:
    options = options or ScannerOptions()
    scan_root = Path(root).resolve()
    inventory = _collect_scan_files(scan_root, options)
    files = inventory.files
    text = _scan_repository_text(files)
    findings, metadata = _detect_repository_candidates(scan_root, files, options=options)
    runtime_findings = _runtime_source_findings(tuple(findings))
    has_consequential = bool(runtime_findings)
    has_mcp = _repository_text_has_strong_mcp(scan_root, files)
    controls = set(metadata["controls"])
    has_proof = "proof gate" in controls or _matches_any(text, PROOF_PATTERNS)
    has_receipts = "receipt/refusal" in controls or _matches_any(text, RECEIPT_PATTERNS)
    has_replay_escrow = "replay/idempotency" in controls or _matches_any(text, REPLAY_ESCROW_PATTERNS)
    has_broker = "credential broker" in controls or _matches_any(text, CREDENTIAL_BROKER_PATTERNS)
    has_policy = "preflight/policy" in controls or "approval/evidence" in controls or _matches_any(text, APPROVAL_EVIDENCE_PATTERNS)
    has_standing_credentials = bool(metadata["strong_secret_hits"])
    report_metadata = {
        "side_effect_primitive_found": bool(metadata["any_primitive"]),
        "consequential_surface_found": bool(findings),
        "agent_control_context_found": bool(metadata["any_agent_context"]),
        "candidate_agent_controlled_consequential_path_found": any(
            finding.agent_control_context == "yes" for finding in findings
        ),
        "visible_controls_found": tuple(sorted(controls)),
        "credential_keyword_suppressed_in_migration": metadata["credential_keyword_suppressed_in_migration"],
        "offline_migration_context": metadata["offline_migration_context"],
        "downgraded_test_fixture_context": metadata["downgraded_test_fixture_context"],
        "test_or_example_context": metadata["test_or_example_context"],
        "runtime_source_finding_count": metadata["runtime_source_finding_count"],
        "additional_test_example_context_finding_count": metadata["additional_test_example_context_finding_count"],
        "test_or_example_finding_count": metadata["test_or_example_finding_count"],
        "context_classifications": metadata["context_classifications"],
        "files_discovered": inventory.files_discovered,
        "files_scanned": inventory.files_scanned,
        "files_scanned_by_detector": metadata["files_scanned_by_detector"],
        "skipped_files": inventory.skipped_files,
        "skipped_dirs": inventory.skipped_dirs,
        "partial": bool(inventory.partial or metadata["partial"]),
        "timed_out": bool(inventory.timed_out or metadata["timed_out"]),
        "timeout_reason": inventory.timeout_reason or metadata["timeout_reason"],
        "consequence_class": _report_consequence_class(tuple(findings)),
        "consequence_class_label": _report_consequence_label(tuple(findings)),
        "highest_overall_consequence_class": _report_consequence_label(tuple(findings), include_context=True),
        "gating_status": _report_gating_status(tuple(findings), ()),
        "runtime_reachability": "Not proven",
        "vulnerability_claim": False,
        "vulnerability_severity": None,
        "finding_type": "Static advisory execution-surface finding",
        "runtime_proof_status": "Not Verified",
        "manual_review_required": bool(findings),
        "confidence": _report_confidence(tuple(findings)),
        "consequential_action_categories_detected": _detected_categories(tuple(findings)),
    }
    checks = _checks_from_static_signals(
        has_consequential=has_consequential,
        has_mcp=has_mcp,
        has_proof=has_proof,
        has_receipts=has_receipts,
        has_replay_escrow=has_replay_escrow,
        has_broker=has_broker,
        has_policy=has_policy,
        has_standing_credentials=has_standing_credentials,
        suppressed_credential_keywords=int(metadata["suppressed_credential_keywords"]),
    )
    summary = _static_summary(mode=mode, has_consequential=has_consequential, findings=findings)
    if report_metadata["partial"]:
        reason = report_metadata["timeout_reason"] or "scan stopped before all files were reviewed"
        summary = f"Partial scan only: {reason}. {summary}"
    return _build_report(
        mode=mode,
        target=str(scan_root),
        checks=checks,
        findings=findings,
        summary_override=summary,
        metadata=report_metadata,
    )


def _first_hit(files: tuple[Path, ...], patterns: tuple[str, ...]) -> _CodeHit | None:
    for path in files:
        hit = _scan_file_for_first_hit(path, patterns)
        if hit is not None:
            return hit
    return None


def _checks_from_static_signals(
    *,
    has_consequential: bool,
    has_mcp: bool,
    has_proof: bool,
    has_receipts: bool,
    has_replay_escrow: bool,
    has_broker: bool,
    has_policy: bool,
    has_standing_credentials: bool,
    suppressed_credential_keywords: int = 0,
) -> list[ScanCheck]:
    if not has_consequential:
        consequential_summary = "No obvious consequential action patterns were detected in scanned code paths."
    else:
        consequential_summary = "Consequential action patterns were detected in scanned code paths."
    return [
        _build_check(
            "proof_binding",
            "present" if has_proof else ("missing" if has_consequential else "not_assessed"),
            "A local Actenon proof-gate signal was found." if has_proof else f"{consequential_summary} No visible Actenon proof gate was found.",
        ),
        _build_check(
            "audience_enforcement",
            "not_assessed",
            "Static scan mode cannot prove runtime audience-enforcement behavior. Use artifact-pair or local harness mode for this check.",
        ),
        _build_check(
            "expiry_enforcement",
            "not_assessed",
            "Static scan mode cannot prove runtime proof-expiry behavior. Use artifact-pair or local harness mode for this check.",
        ),
        _build_check(
            "credential_broker",
            "present" if has_broker else ("missing" if has_consequential else "not_assessed"),
            "A credential-broker or protected-executor signal was found."
            if has_broker
            else f"{consequential_summary} No visible credential-broker boundary was found.",
        ),
        _build_check(
            "structured_refusals",
            "present" if has_receipts else ("missing" if has_consequential else "not_assessed"),
            "Receipt/Refusal emission signals were found."
            if has_receipts
            else f"{consequential_summary} No visible Receipt/Refusal emission was found.",
        ),
        _build_check(
            "replay_protection",
            "present" if has_replay_escrow else ("missing" if has_consequential else "not_assessed"),
            "Replay or escrow protection signals were found."
            if has_replay_escrow
            else f"{consequential_summary} No visible replay or escrow protection was found.",
        ),
        _build_check(
            "approval_or_evidence_policy",
            "present" if has_policy else ("missing" if has_consequential else "not_assessed"),
            "Approval or evidence policy signals were found."
            if has_policy
            else f"{consequential_summary} No visible approval/evidence policy was found.",
        ),
        _build_check(
            "standing_credentials",
            "missing" if has_standing_credentials else "present",
            "Potential standing credential access was detected."
            if has_standing_credentials
            else (
                "No strong runtime standing credential signals were detected in scanned files. "
                f"Suppressed {suppressed_credential_keywords} offline-migration credential keyword(s)."
                if suppressed_credential_keywords
                else "No strong runtime standing credential signals were detected in scanned files."
            ),
        ),
        _build_check(
            "mcp_tool_boundary",
            "present" if (has_mcp and has_proof) else ("missing" if has_mcp and has_consequential else "not_assessed"),
            "MCP/tool-handler proof-boundary signals were found."
            if has_mcp and has_proof
            else "No MCP destructive tool boundary issue was detected." if not has_mcp else "MCP/tool signals were found without a visible proof-boundary signal.",
        ),
    ]


def _static_summary(*, mode: str, has_consequential: bool, findings: list[ScanFinding]) -> str:
    if findings:
        runtime_count = len(_runtime_source_findings(tuple(findings)))
        context_count = len(findings) - runtime_count
        return (
            f"{mode} scan found {runtime_count} runtime source candidate consequential action path(s) "
            f"and {context_count} test/example/context finding(s). "
            "Reports are static advisory; runtime reachability not proven; runtime exploitability not proven; at least one finding requires maintainer review."
        )
    if has_consequential:
        return (
            f"{mode} scan found candidate consequential action patterns and visible control signals. "
            "Review not-assessed checks before relying on this result."
        )
    return (
        f"{mode} scan did not find obvious candidate consequential action patterns in scanned code files. "
        "High-capability unknown paths may still require maintainer review."
    )
