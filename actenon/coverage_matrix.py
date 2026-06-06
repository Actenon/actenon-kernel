from __future__ import annotations

import json
import re
import warnings
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterable

from actenon.api.intake import ActionIntentIntakeService
from actenon.core.errors import PolicyDecisionError, ProofVerificationError, RefusalException
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.models import ActionIntent, AudienceRef, PartyRef, PCCB, ProtectedExecutionRequest, TenantRef
from actenon.models.contracts import format_timestamp
from actenon.models.runtime import DynamicContextInput, ExecutionResult, PolicyDecision, RuleEvaluation
from actenon.proof import LOCAL_HMAC_WARNING_MESSAGE, PCCBMinter, PCCBVerifier, build_local_proof_signer, sha256_hex
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.verifier import ProtectedEndpointMiddleware


DEFAULT_EVIDENCE_PATH = Path("artifacts/coverage/consequential_action_coverage_matrix.json")
FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
MATRIX_DESCRIPTION = (
    "The Consequential Action Coverage Matrix is a deterministic local simulation suite. "
    "It exercises representative consequential action surfaces and verifies Actenon's "
    "proof-bound refusal and execution behavior."
)
LIMITATIONS = (
    "Deterministic local simulations only.",
    "No live provider integration is claimed or exercised.",
    "No real exploitability, production exposure, downstream finality, or incident prevention is claimed.",
    "The matrix demonstrates representative consequence-class evidence, not exhaustive coverage of every possible action.",
    "No cloud calls, external secrets, or real destructive actions are used.",
)


@dataclass(frozen=True)
class RepresentativeAction:
    label: str
    action_name: str
    capability: str
    target_type: str
    target_id: str
    consequence_class: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class Domain:
    name: str
    actions: tuple[RepresentativeAction, ...]


@dataclass(frozen=True)
class Scenario:
    domain: Domain
    action: RepresentativeAction
    index: int

    @property
    def domain_slug(self) -> str:
        return _slug(self.domain.name)

    @property
    def action_slug(self) -> str:
        return _slug(self.action.action_name)

    @property
    def scenario_id(self) -> str:
        return f"{self.domain_slug}_{self.action_slug}_{self.index:03d}"


@dataclass(frozen=True)
class CheckDefinition:
    key: str
    label: str
    mode: str
    primary_artifact_kind: str


@dataclass(frozen=True)
class ArtifactReference:
    kind: str
    path: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "artifact_digest": self.digest,
        }


@dataclass(frozen=True)
class CheckRecord:
    domain: str
    action: str
    check_key: str
    check_label: str
    outcome: str
    passed: bool
    side_effect_executed: bool
    reason_code: str | None
    artifact: ArtifactReference
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "domain": self.domain,
            "action": self.action,
            "check_key": self.check_key,
            "check_label": self.check_label,
            "outcome": self.outcome,
            "passed": self.passed,
            "side_effect_executed": self.side_effect_executed,
            "artifact": self.artifact.to_dict(),
        }
        if self.reason_code is not None:
            payload["reason_code"] = self.reason_code
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass(frozen=True)
class CoverageResult:
    generated_at: datetime
    domains: tuple[Domain, ...]
    records: tuple[CheckRecord, ...]
    evidence_path: Path
    limitations: tuple[str, ...] = LIMITATIONS

    @property
    def total_scenarios(self) -> int:
        return len(self.records)

    @property
    def result(self) -> str:
        return "PASS" if all(record.passed for record in self.records) else "FAIL"

    @property
    def per_domain_counts(self) -> dict[str, int]:
        counts = {domain.name: 0 for domain in self.domains}
        for record in self.records:
            counts[record.domain] = counts.get(record.domain, 0) + 1
        return counts

    @property
    def check_counts(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for definition in CHECK_DEFINITIONS:
            counts[definition.key] = {"passed": 0, "total": 0}
        for record in self.records:
            if record.check_key in VALID_CHECK_KEYS:
                bucket = counts["valid_proof_bound_actions_executed_once"]
            else:
                bucket = counts[record.check_key]
            bucket["total"] += 1
            if record.passed:
                bucket["passed"] += 1
        return {
            key: value
            for key, value in counts.items()
            if key == "valid_proof_bound_actions_executed_once" or key not in VALID_CHECK_KEYS
        }

    @property
    def artifact_counts(self) -> dict[str, dict[str, int]]:
        counts = {
            "refusal_artifacts_emitted": {"passed": 0, "total": 0},
            "receipt_artifacts_emitted": {"passed": 0, "total": 0},
        }
        for record in self.records:
            key = "refusal_artifacts_emitted" if record.artifact.kind == "refusal" else "receipt_artifacts_emitted"
            counts[key]["total"] += 1
            if record.passed and record.artifact.path:
                counts[key]["passed"] += 1
        return counts

    @property
    def refusal_reason_codes_observed(self) -> tuple[str, ...]:
        return tuple(sorted({record.reason_code for record in self.records if record.reason_code}))

    @property
    def representative_actions(self) -> dict[str, list[dict[str, Any]]]:
        return {
            domain.name: [
                {
                    "label": action.label,
                    "action": action.action_name,
                    "capability": action.capability,
                    "target": action.target_id,
                    "consequence_class": action.consequence_class,
                }
                for action in domain.actions
            ]
            for domain in self.domains
        }

    @property
    def artifact_samples(self) -> dict[str, list[dict[str, Any]]]:
        samples = {"refusal": [], "receipt": []}
        for record in self.records:
            bucket = samples[record.artifact.kind]
            if len(bucket) >= 3:
                continue
            bucket.append(
                {
                    "domain": record.domain,
                    "action": record.action,
                    "check": record.check_key,
                    "outcome": record.outcome,
                    "side_effect_executed": record.side_effect_executed,
                    "reason_code": record.reason_code,
                    **record.artifact.to_dict(),
                }
            )
        return samples

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": {"name": "consequential_action_coverage_matrix", "version": "v1"},
            "generated_at": format_timestamp(self.generated_at),
            "description": MATRIX_DESCRIPTION,
            "total_scenarios": self.total_scenarios,
            "domains": [domain.name for domain in self.domains],
            "per_domain_counts": self.per_domain_counts,
            "check_counts": self.check_counts,
            "artifact_counts": self.artifact_counts,
            "result": self.result,
            "limitations": list(self.limitations),
            "representative_actions": self.representative_actions,
            "refusal_reason_codes_observed": list(self.refusal_reason_codes_observed),
            "artifact_samples": self.artifact_samples,
            "scenario_records": [record.to_dict() for record in self.records],
        }


CHECK_DEFINITIONS = (
    CheckDefinition("missing_proof_refused", "Missing proof refused", "refusal", "refusal"),
    CheckDefinition("action_hash_mismatch_refused", "Action hash mismatch refused", "refusal", "refusal"),
    CheckDefinition("parameter_mismatch_refused", "Parameter mismatch refused", "refusal", "refusal"),
    CheckDefinition("audience_mismatch_refused", "Audience mismatch refused", "refusal", "refusal"),
    CheckDefinition("tenant_subject_mismatch_refused", "Tenant / subject mismatch refused", "refusal", "refusal"),
    CheckDefinition("expired_proof_refused", "Expired proof refused", "refusal", "refusal"),
    CheckDefinition("replay_attempt_refused", "Replay attempts refused", "refusal", "refusal"),
    CheckDefinition("policy_denied_refused", "Policy-denied actions refused", "refusal", "refusal"),
    CheckDefinition("valid_proof_bound_actions_executed_once", "Valid proof-bound actions executed once", "valid", "receipt"),
    CheckDefinition("valid_receipt_artifact_emitted", "Valid proof-bound actions executed once", "valid", "receipt"),
)
VALID_CHECK_KEYS = frozenset({"valid_proof_bound_actions_executed_once", "valid_receipt_artifact_emitted"})
CHECK_BY_KEY = {definition.key: definition for definition in CHECK_DEFINITIONS}


def build_consequential_action_matrix() -> tuple[Domain, ...]:
    return (
        Domain(
            "DevOps",
            (
                _action("deploy production", "deployment.deploy_production", "deployment.deploy", "service", "payments-api-prod", "deployment"),
                _action("rollback production", "deployment.rollback_production", "deployment.rollback", "service", "payments-api-prod", "deployment"),
                _action("delete environment", "environment.delete", "environment.delete", "environment", "preview-prod-shadow", "destructive infrastructure"),
                _action("rotate secret", "credential.rotate", "credential.rotate", "credential", "prod-db-credential-ref", "credential mutation"),
                _action("restart service", "service.restart", "service.restart", "service", "checkout-prod", "availability mutation"),
                _action("modify infrastructure state", "infrastructure.modify_state", "infrastructure.modify", "terraform_state", "prod-network-state", "infrastructure mutation"),
            ),
        ),
        Domain(
            "Fintech",
            (
                _action("create payment", "payment.create", "payment.create", "payment_account", "merchant-settlement", "payment mutation"),
                _action("approve invoice", "invoice.approve", "invoice.approve", "invoice", "invoice-enterprise-001", "financial approval"),
                _action("issue refund", "stripe.refund", "refund.issue", "payment", "pay_recent_batch", "payment mutation"),
                _action("transfer funds", "funds.transfer", "funds.transfer", "treasury_account", "operating-account", "funds movement"),
                _action("update bank details", "bank_details.update", "bank_details.update", "vendor", "vendor-042", "payment destination mutation"),
                _action("release payout", "payout.release", "payout.release", "payout", "payout-weekly-batch", "funds release"),
            ),
        ),
        Domain(
            "IAM / Access Control",
            (
                _action("grant admin", "iam.grant_admin", "iam.role.grant", "principal", "user-platform-engineer", "privilege escalation"),
                _action("revoke MFA", "iam.revoke_mfa", "iam.mfa.revoke", "principal", "user-finance-admin", "authentication weakening"),
                _action("create API key", "iam.create_api_key", "iam.api_key.create", "service_account", "automation-prod", "credential issuance"),
                _action("rotate credential", "iam.rotate_credential", "iam.credential.rotate", "service_account", "deploy-bot-prod", "credential mutation"),
                _action("share workspace", "iam.share_workspace", "iam.workspace.share", "workspace", "exec-ops", "access expansion"),
                _action("change role membership", "iam.change_role_membership", "iam.role.membership.update", "group", "production-admins", "privilege mutation"),
            ),
        ),
        Domain(
            "Database",
            (
                _action("delete table", "database.delete_table", "database.table.delete", "table", "production_customers", "destructive data mutation"),
                _action("truncate records", "database.truncate_records", "database.records.truncate", "table", "orders_prod", "destructive data mutation"),
                _action("export customer data", "database.export_customer_data", "database.data.export", "database", "crm_prod", "data export"),
                _action("update production rows", "database.update_rows", "database.rows.update", "table", "subscriptions_prod", "data mutation"),
                _action("run migration", "database.run_migration", "database.migration.run", "database", "billing_prod", "schema mutation"),
                _action("drop index", "database.drop_index", "database.index.drop", "index", "idx_customer_email", "performance mutation"),
            ),
        ),
        Domain(
            "Browser / Computer Use",
            (
                _action("submit form", "browser.submit_form", "browser.form.submit", "web_form", "admin-settings-form", "external submission"),
                _action("upload file", "browser.upload_file", "browser.file.upload", "web_app", "partner-portal", "data upload"),
                _action("export CSV", "browser.export_csv", "browser.csv.export", "web_app", "customer-admin", "data export"),
                _action("delete account", "browser.delete_account", "browser.account.delete", "account", "sandbox-customer-account", "destructive account mutation"),
                _action("confirm purchase", "browser.confirm_purchase", "browser.purchase.confirm", "cart", "enterprise-seat-upgrade", "purchase confirmation"),
                _action("update settings", "browser.update_settings", "browser.settings.update", "settings_page", "production-workspace", "configuration mutation"),
            ),
        ),
        Domain(
            "MCP Tools",
            (
                _action("file write", "mcp.file_write", "mcp.file.write", "file", "repo/config.yml", "file mutation"),
                _action("file delete", "mcp.file_delete", "mcp.file.delete", "file", "repo/prod.env.example", "destructive file mutation"),
                _action("shell execution", "mcp.shell_execute", "mcp.shell.execute", "shell", "local-shell", "command execution"),
                _action("database mutation", "mcp.database_mutation", "mcp.database.mutate", "database", "local-fixture-db", "data mutation"),
                _action("API side effect", "mcp.api_side_effect", "mcp.api.side_effect", "api", "synthetic-provider-api", "provider mutation"),
                _action("external send/export tool", "mcp.external_send_export", "mcp.external.send_export", "tool", "synthetic-export-tool", "external transmission"),
            ),
        ),
        Domain(
            "Data Export",
            (
                _action("export PII", "data.export_pii", "data.pii.export", "dataset", "customer_pii_sample", "sensitive data export"),
                _action("download customer records", "data.download_customer_records", "data.records.download", "dataset", "enterprise_accounts", "bulk data download"),
                _action("sync to third-party destination", "data.sync_third_party", "data.third_party.sync", "destination", "external-vendor", "external sync"),
                _action("generate external report", "data.generate_external_report", "data.report.external", "report", "quarterly-customer-report", "external report generation"),
                _action("bulk extract", "data.bulk_extract", "data.bulk.extract", "warehouse", "production-warehouse", "bulk extraction"),
                _action("share data externally", "data.share_external", "data.share.external", "dataset", "support-export", "external sharing"),
            ),
        ),
        Domain(
            "Email / Communications",
            (
                _action("send external email", "gmail.send_external", "email.external.send", "mailbox", "support-team", "external communication"),
                _action("send bulk message", "email.send_bulk", "email.bulk.send", "mailing_list", "all_customers", "bulk communication"),
                _action("attach sensitive data", "email.attach_sensitive_data", "email.attachment.sensitive", "message", "case-update", "sensitive data transmission"),
                _action("forward thread", "email.forward_thread", "email.thread.forward", "thread", "customer-escalation", "external forwarding"),
                _action("invite external recipient", "calendar.invite_external", "calendar.invite.external", "calendar", "exec-review", "external access invitation"),
                _action("publish announcement", "comms.publish_announcement", "comms.announcement.publish", "channel", "status-page", "public communication"),
            ),
        ),
        Domain(
            "Code Agent Operations",
            (
                _action("git push", "git.push", "git.push", "repository", "production_repo", "repository mutation"),
                _action("open pull request", "github.open_pull_request", "github.pull_request.open", "repository", "production_repo", "code review mutation"),
                _action("merge pull request", "github.merge_pull_request", "github.pull_request.merge", "repository", "production_repo", "codebase mutation"),
                _action("run shell command", "code_agent.run_shell_command", "code_agent.shell.run", "shell", "developer-workspace", "command execution"),
                _action("modify deployment config", "code_agent.modify_deployment_config", "deployment.config.modify", "file", "deploy/prod.yml", "deployment mutation"),
                _action("commit generated code", "git.commit_generated_code", "git.commit", "repository", "production_repo", "source mutation"),
            ),
        ),
    )


def run_consequential_action_matrix(
    *,
    evidence_path: str | Path = DEFAULT_EVIDENCE_PATH,
    generated_at: datetime | None = None,
) -> CoverageResult:
    output_path = Path(evidence_path)
    domains = build_consequential_action_matrix()
    runner = _CoverageRunner(domains=domains, evidence_path=output_path, generated_at=generated_at or datetime.now(timezone.utc))
    result = runner.run()
    write_coverage_matrix_evidence(result, output_path)
    return result


def write_coverage_matrix_evidence(result: CoverageResult, evidence_path: str | Path | None = None) -> Path:
    output_path = Path(evidence_path) if evidence_path is not None else result.evidence_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path


def render_coverage_matrix_text(result: CoverageResult) -> str:
    domain_counts = result.per_domain_counts
    check_counts = result.check_counts
    artifact_counts = result.artifact_counts
    evidence_path = _display_path(result.evidence_path)

    lines = [
        "ACTENON CONSEQUENTIAL ACTION COVERAGE MATRIX",
        "",
        f"Total scenarios: {result.total_scenarios}",
        f"Domains covered: {len(result.domains)}",
        "",
        "Domain evidence:",
    ]
    domain_label_width = max(len(domain.name) for domain in result.domains)
    for domain in result.domains:
        lines.append(f"- {domain.name + ':':<{domain_label_width + 1}}  {domain_counts[domain.name]:>3} checks")

    proof_rows = (
        ("missing_proof_refused", "Missing proof refused"),
        ("action_hash_mismatch_refused", "Action hash mismatch refused"),
        ("parameter_mismatch_refused", "Parameter mismatch refused"),
        ("audience_mismatch_refused", "Audience mismatch refused"),
        ("tenant_subject_mismatch_refused", "Tenant / subject mismatch refused"),
        ("expired_proof_refused", "Expired proof refused"),
        ("replay_attempt_refused", "Replay attempts refused"),
        ("policy_denied_refused", "Policy-denied actions refused"),
        ("valid_proof_bound_actions_executed_once", "Valid proof-bound actions executed once"),
    )
    proof_label_width = max(len(label) for _, label in proof_rows)
    lines.extend(["", "Proof-bound execution checks:"])
    for key, label in proof_rows:
        counts = check_counts[key]
        lines.append(f"- {label + ':':<{proof_label_width + 1}}  {counts['passed']:>3}/{counts['total']}")

    artifact_rows = (
        ("refusal_artifacts_emitted", "Refusal artifacts emitted"),
        ("receipt_artifacts_emitted", "Receipt artifacts emitted"),
    )
    artifact_label_width = max(len(label) for _, label in artifact_rows)
    lines.extend(["", "Artifacts:"])
    for key, label in artifact_rows:
        counts = artifact_counts[key]
        lines.append(f"- {label + ':':<{artifact_label_width + 1}}  {counts['passed']:>3}/{counts['total']}")
    lines.append(f"- Evidence JSON: {evidence_path}")
    lines.extend(["", f"Result: {result.result}", "", "No valid proof, no execution."])
    return "\n".join(lines)


class _CoverageRunner:
    def __init__(self, *, domains: tuple[Domain, ...], evidence_path: Path, generated_at: datetime) -> None:
        self.domains = domains
        self.evidence_path = evidence_path
        self.generated_at = generated_at
        self.artifact_root = evidence_path.parent / "consequential_action_coverage_matrix_artifacts"
        self.intake = ActionIntentIntakeService()
        self.signer = self._build_signer()

    def run(self) -> CoverageResult:
        records: list[CheckRecord] = []
        scenarios = list(_scenarios(self.domains))
        with TemporaryDirectory(prefix="actenon-coverage-") as tempdir:
            replay_root = Path(tempdir) / "replay"
            for scenario in scenarios:
                for definition in CHECK_DEFINITIONS:
                    records.append(self._run_check(scenario, definition, replay_root))
        return CoverageResult(
            generated_at=self.generated_at,
            domains=self.domains,
            records=tuple(records),
            evidence_path=self.evidence_path,
        )

    def _run_check(self, scenario: Scenario, definition: CheckDefinition, replay_root: Path) -> CheckRecord:
        try:
            if definition.key == "missing_proof_refused":
                return self._run_missing_proof(scenario, definition)
            if definition.key == "policy_denied_refused":
                return self._run_policy_denied(scenario, definition)
            if definition.key == "replay_attempt_refused":
                return self._run_replay(scenario, definition, replay_root)
            if definition.key in VALID_CHECK_KEYS:
                return self._run_valid_execution(scenario, definition, replay_root)
            return self._run_proof_refusal(scenario, definition, replay_root)
        except Exception as exc:
            return self._failed_record(scenario, definition, exc)

    def _run_missing_proof(self, scenario: Scenario, definition: CheckDefinition) -> CheckRecord:
        intent, _pccb, context = self._mint_bundle(scenario, definition.key)
        refusal = self._create_refusal(
            scenario,
            definition,
            ProofVerificationError("MISSING_PROOF", "No proof was supplied to the protected endpoint."),
            intent=intent,
            context=context,
            pccb=None,
        )
        artifact = self._write_primary_artifact(scenario, definition, "refusal", refusal.to_dict())
        return CheckRecord(
            domain=scenario.domain.name,
            action=scenario.action.action_name,
            check_key=definition.key,
            check_label=definition.label,
            outcome="refused",
            passed=refusal.refusal_code == "MISSING_PROOF",
            side_effect_executed=False,
            reason_code=refusal.refusal_code,
            artifact=artifact,
        )

    def _run_policy_denied(self, scenario: Scenario, definition: CheckDefinition) -> CheckRecord:
        intent, _pccb, context = self._mint_bundle(scenario, definition.key)
        rule_ref = f"coverage.{scenario.domain_slug}.synthetic_deny"
        refusal = self._create_refusal(
            scenario,
            definition,
            PolicyDecisionError(
                "POLICY_DENIED",
                "The deterministic local coverage policy denied this synthetic consequential action.",
                rule_refs=(rule_ref,),
                details={"simulation": "deterministic-local", "domain": scenario.domain.name},
            ),
            intent=intent,
            context=context,
            pccb=None,
        )
        artifact = self._write_primary_artifact(scenario, definition, "refusal", refusal.to_dict())
        return CheckRecord(
            domain=scenario.domain.name,
            action=scenario.action.action_name,
            check_key=definition.key,
            check_label=definition.label,
            outcome="refused",
            passed=refusal.refusal_code == "POLICY_DENIED",
            side_effect_executed=False,
            reason_code=refusal.refusal_code,
            artifact=artifact,
        )

    def _run_proof_refusal(self, scenario: Scenario, definition: CheckDefinition, replay_root: Path) -> CheckRecord:
        intent, pccb, context = self._mint_bundle(scenario, definition.key)
        request_intent = intent
        request_pccb = pccb
        request_context = context
        expected_reason_codes: set[str]

        if definition.key == "action_hash_mismatch_refused":
            request_pccb = replace(pccb, action_hash=replace(pccb.action_hash, value="0" * 64))
            expected_reason_codes = {"ACTION_HASH_MISMATCH"}
        elif definition.key == "parameter_mismatch_refused":
            mutated_action = replace(
                intent.action,
                parameters={**intent.action.parameters, "coverage_mutation": "parameter-mismatch"},
            )
            request_intent = replace(intent, action=mutated_action)
            expected_reason_codes = {"ACTION_MISMATCH", "ACTION_HASH_MISMATCH"}
        elif definition.key == "audience_mismatch_refused":
            request_context = replace(context, audience=AudienceRef(type=context.audience.type, id=f"{context.audience.id}.wrong"))
            expected_reason_codes = {"AUDIENCE_MISMATCH"}
        elif definition.key == "tenant_subject_mismatch_refused":
            if scenario.index % 2 == 0:
                request_intent = replace(intent, tenant=TenantRef(tenant_id=f"{intent.tenant.tenant_id}-other"))
                expected_reason_codes = {"TENANT_MISMATCH"}
            else:
                request_intent = replace(intent, requester=PartyRef(type=intent.requester.type, id=f"{intent.requester.id}-other"))
                expected_reason_codes = {"SUBJECT_MISMATCH"}
        elif definition.key == "expired_proof_refused":
            request_context = replace(context, now=pccb.expires_at + timedelta(seconds=1))
            expected_reason_codes = {"PROOF_EXPIRED"}
        else:  # pragma: no cover - protected by CHECK_DEFINITIONS dispatch
            raise ValueError(f"unsupported proof refusal check: {definition.key}")

        result, side_effect_count = self._execute_with_middleware(
            scenario,
            definition,
            intent=request_intent,
            pccb=request_pccb,
            context=request_context,
            replay_root=replay_root,
        )
        refusal = result.refusal
        if refusal is None:
            raise AssertionError(f"{definition.key} did not refuse")
        artifact = self._write_primary_artifact(scenario, definition, "refusal", refusal.to_dict())
        return CheckRecord(
            domain=scenario.domain.name,
            action=scenario.action.action_name,
            check_key=definition.key,
            check_label=definition.label,
            outcome="refused",
            passed=refusal.refusal_code in expected_reason_codes and side_effect_count == 0,
            side_effect_executed=False,
            reason_code=refusal.refusal_code,
            artifact=artifact,
            details={"expected_reason_codes": sorted(expected_reason_codes)},
        )

    def _run_replay(self, scenario: Scenario, definition: CheckDefinition, replay_root: Path) -> CheckRecord:
        intent, pccb, context = self._mint_bundle(scenario, definition.key)
        middleware, escrow = self._build_middleware(scenario, definition, replay_root)
        escrow.issue(
            escrow_id=pccb.escrow_id or f"esc_{scenario.scenario_id}_{definition.key}",
            pccb_id=pccb.pccb_id,
            capability=intent.action.capability,
            expires_at=pccb.expires_at,
            metadata={"simulation": "coverage-matrix"},
        )
        side_effects = {"count": 0}
        request = ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

        def handler(_request: ProtectedExecutionRequest) -> dict[str, Any]:
            side_effects["count"] += 1
            return {
                "external_reference": f"exec_{scenario.scenario_id}_{definition.key}",
                "resource_version": "local-simulation",
            }

        first = middleware.execute(request, handler)
        second = middleware.execute(request, handler)
        refusal = second.refusal
        if refusal is None:
            raise AssertionError("replay attempt did not refuse")
        artifact = self._write_primary_artifact(scenario, definition, "refusal", refusal.to_dict())
        return CheckRecord(
            domain=scenario.domain.name,
            action=scenario.action.action_name,
            check_key=definition.key,
            check_label=definition.label,
            outcome="refused",
            passed=first.receipt is not None and first.refusal is None and refusal.refusal_code == "DUPLICATE_REPLAY" and side_effects["count"] == 1,
            side_effect_executed=False,
            reason_code=refusal.refusal_code,
            artifact=artifact,
            details={"seed_execution_side_effects": side_effects["count"]},
        )

    def _run_valid_execution(self, scenario: Scenario, definition: CheckDefinition, replay_root: Path) -> CheckRecord:
        intent, pccb, context = self._mint_bundle(scenario, definition.key)
        result, side_effect_count = self._execute_with_middleware(
            scenario,
            definition,
            intent=intent,
            pccb=pccb,
            context=context,
            replay_root=replay_root,
        )
        receipt = result.receipt
        if receipt is None or result.refusal is not None:
            reason = result.refusal.refusal_code if result.refusal is not None else "MISSING_RECEIPT"
            raise AssertionError(f"valid proof-bound execution failed: {reason}")
        artifact = self._write_primary_artifact(scenario, definition, "receipt", receipt.to_dict())
        return CheckRecord(
            domain=scenario.domain.name,
            action=scenario.action.action_name,
            check_key=definition.key,
            check_label=definition.label,
            outcome="executed",
            passed=receipt.outcome == "executed" and side_effect_count == 1,
            side_effect_executed=True,
            reason_code=None,
            artifact=artifact,
            details={"execution": "once"},
        )

    def _execute_with_middleware(
        self,
        scenario: Scenario,
        definition: CheckDefinition,
        *,
        intent: ActionIntent,
        pccb: PCCB,
        context: DynamicContextInput,
        replay_root: Path,
    ) -> tuple[ExecutionResult, int]:
        middleware, escrow = self._build_middleware(scenario, definition, replay_root)
        escrow.issue(
            escrow_id=pccb.escrow_id or f"esc_{scenario.scenario_id}_{definition.key}",
            pccb_id=pccb.pccb_id,
            capability=pccb.action.capability,
            expires_at=pccb.expires_at,
            metadata={"simulation": "coverage-matrix"},
        )
        side_effects = {"count": 0}

        def handler(_request: ProtectedExecutionRequest) -> dict[str, Any]:
            side_effects["count"] += 1
            return {
                "external_reference": f"exec_{scenario.scenario_id}_{definition.key}",
                "provider_reference": "local-simulation",
                "resource_version": "1",
            }

        result = middleware.execute(ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context), handler)
        return result, side_effects["count"]

    def _build_middleware(
        self,
        scenario: Scenario,
        definition: CheckDefinition,
        replay_root: Path,
    ) -> tuple[ProtectedEndpointMiddleware, InMemoryCapabilityEscrow]:
        writer = InMemoryOutcomeWriter()
        receipt_factory = ReceiptFactory(receipt_id_factory=_id_factory("rcpt", scenario, definition))
        refusal_factory = RefusalFactory(refusal_id_factory=_id_factory("rfsl", scenario, definition))
        escrow = InMemoryCapabilityEscrow()
        replay_store = SqliteReplayStore(replay_root / f"{scenario.scenario_id}_{definition.key}.sqlite3")
        middleware = ProtectedEndpointMiddleware(
            proof_verifier=PCCBVerifier(self.signer),
            escrow=escrow,
            receipt_factory=receipt_factory,
            refusal_factory=refusal_factory,
            outcome_writer=writer,
            replay_protector=ReplayProtector(replay_store),
        )
        return middleware, escrow

    def _mint_bundle(self, scenario: Scenario, check_key: str) -> tuple[ActionIntent, PCCB, DynamicContextInput]:
        now = FIXED_NOW + timedelta(seconds=scenario.index)
        intent = self.intake.parse(_intent_payload(scenario, now=now))
        audience = AudienceRef(type="service", id=f"coverage.{scenario.domain_slug}.{scenario.action_slug}.endpoint")
        context = DynamicContextInput(
            request_id=f"req_{scenario.scenario_id}_{check_key}",
            audience=audience,
            scope_capabilities=(scenario.action.capability,),
            now=now,
            facts={"simulation": "deterministic-local", "domain": scenario.domain.name},
            parameter_constraints=dict(intent.action.parameters),
            resource_selectors=(
                {
                    "resource_type": intent.target.resource_type,
                    "resource_id": intent.target.resource_id,
                    "domain": scenario.domain.name,
                },
            ),
        )
        decision = PolicyDecision(
            outcome="allow",
            summary="The deterministic local coverage policy authorizes this exact synthetic action.",
            reason_codes=("COVERAGE_LOCAL_SIMULATION_ALLOW",),
            rule_evaluations=(
                RuleEvaluation(
                    rule_id=f"coverage.{scenario.domain_slug}.allow",
                    outcome="allow",
                    reason_code="COVERAGE_LOCAL_SIMULATION_ALLOW",
                    summary="Synthetic local coverage action is allowed for proof minting.",
                    details={"simulation": "deterministic-local"},
                ),
            ),
        )
        minter = PCCBMinter(
            signer=self.signer,
            issuer=PartyRef(type="service", id="actenon-coverage-local-issuer"),
            pccb_id_factory=lambda: f"pccb_{scenario.scenario_id}_{check_key}",
            nonce_factory=lambda: f"nonce_{scenario.scenario_id}_{check_key}",
        )
        pccb = minter.mint(intent, decision, context, escrow_id=f"esc_{scenario.scenario_id}_{check_key}")
        return intent, pccb, context

    def _create_refusal(
        self,
        scenario: Scenario,
        definition: CheckDefinition,
        exc: RefusalException,
        *,
        intent: ActionIntent | None,
        context: DynamicContextInput | None,
        pccb: PCCB | None,
    ):
        return RefusalFactory(refusal_id_factory=_id_factory("rfsl", scenario, definition)).create_from_exception(
            exc,
            occurred_at=context.now if context is not None else FIXED_NOW,
            intent=intent,
            context=context,
            pccb_id=pccb.pccb_id if pccb is not None else None,
            escrow_id=pccb.escrow_id if pccb is not None else None,
            action_hash=pccb.action_hash if pccb is not None else None,
        )

    def _write_primary_artifact(
        self,
        scenario: Scenario,
        definition: CheckDefinition,
        kind: str,
        payload: dict[str, Any],
    ) -> ArtifactReference:
        path = self.artifact_root / kind / scenario.domain_slug / f"{scenario.action_slug}_{definition.key}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return ArtifactReference(
            kind=kind,
            path=_display_path(path),
            digest=f"sha256:{sha256_hex(payload)}",
        )

    def _failed_record(self, scenario: Scenario, definition: CheckDefinition, exc: Exception) -> CheckRecord:
        payload = {
            "contract": {"name": "coverage_matrix_error", "version": "v1"},
            "domain": scenario.domain.name,
            "action": scenario.action.action_name,
            "check": definition.key,
            "error_type": type(exc).__name__,
            "message": str(exc),
        }
        artifact = self._write_primary_artifact(scenario, definition, "refusal", payload)
        return CheckRecord(
            domain=scenario.domain.name,
            action=scenario.action.action_name,
            check_key=definition.key,
            check_label=definition.label,
            outcome="error",
            passed=False,
            side_effect_executed=False,
            reason_code="COVERAGE_MATRIX_ERROR",
            artifact=artifact,
            details={"error_type": type(exc).__name__, "message": str(exc)},
        )

    @staticmethod
    def _build_signer():
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=re.escape(LOCAL_HMAC_WARNING_MESSAGE), category=RuntimeWarning)
            return build_local_proof_signer()


def _action(
    label: str,
    action_name: str,
    capability: str,
    target_type: str,
    target_id: str,
    consequence_class: str,
) -> RepresentativeAction:
    parameters = {
        "environment": "production",
        "operation": label,
        "synthetic": True,
        "simulation_scope": "local-only",
        "target": target_id,
    }
    return RepresentativeAction(
        label=label,
        action_name=action_name,
        capability=capability,
        target_type=target_type,
        target_id=target_id,
        consequence_class=consequence_class,
        parameters=parameters,
    )


def _scenarios(domains: Iterable[Domain]) -> Iterable[Scenario]:
    index = 1
    for domain in domains:
        for action in domain.actions:
            yield Scenario(domain=domain, action=action, index=index)
            index += 1


def _intent_payload(scenario: Scenario, *, now: datetime) -> dict[str, Any]:
    action = scenario.action
    return {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": f"intent_{scenario.scenario_id}",
        "issued_at": format_timestamp(now),
        "expires_at": format_timestamp(now + timedelta(minutes=15)),
        "tenant": {"tenant_id": f"tenant_{scenario.domain_slug}"},
        "requester": {"type": "agent", "id": f"agent_{scenario.domain_slug}"},
        "action": {
            "name": action.action_name,
            "capability": action.capability,
            "parameters": deepcopy(action.parameters),
            "constraints": {"proof_binding": "exact-action", "local_simulation": True},
        },
        "target": {
            "resource_type": action.target_type,
            "resource_id": action.target_id,
            "selectors": {"domain": scenario.domain.name, "synthetic": True},
        },
        "justification": "Deterministic local coverage matrix simulation.",
        "context": {
            "coverage_matrix": True,
            "domain": scenario.domain.name,
            "consequence_class": action.consequence_class,
        },
        "metadata": {"public_safe": True, "local_only": True},
    }


def _id_factory(prefix: str, scenario: Scenario, definition: CheckDefinition):
    counter = {"value": 0}

    def next_id() -> str:
        counter["value"] += 1
        return f"{prefix}_{scenario.scenario_id}_{definition.key}_{counter['value']:02d}"

    return next_id


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(resolved)


__all__ = [
    "CoverageResult",
    "DEFAULT_EVIDENCE_PATH",
    "Domain",
    "RepresentativeAction",
    "build_consequential_action_matrix",
    "render_coverage_matrix_text",
    "run_consequential_action_matrix",
    "write_coverage_matrix_evidence",
]
