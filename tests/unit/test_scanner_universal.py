from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.scanner import render_markdown_report, scan_repository


UNSAFE_DEFINITIVE_TERMS = (
    " unsafe",
    "exploitable",
    "breached",
    "definitely reaches production",
    "caused harm",
)


class UniversalScannerTests(unittest.TestCase):
    def _scan_source(self, relative_path: str, source: str):
        tempdir = TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        path = Path(tempdir.name) / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source.strip() + "\n", encoding="utf-8")
        return scan_repository(tempdir.name)

    def _scan_files(self, files: dict[str, str]):
        tempdir = TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        for relative_path, source in files.items():
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source.strip() + "\n", encoding="utf-8")
        return scan_repository(tempdir.name)

    def _surface_ids(self, report) -> set[str]:
        return {finding.surface_id or finding.category for finding in report.findings}

    def _finding_for(self, report, surface_id: str):
        for finding in report.findings:
            if finding.surface_id == surface_id:
                return finding
        self.fail(f"missing scanner finding for {surface_id}")

    def _finding_for_primitive(self, report, surface_id: str, primitive: str):
        for finding in report.findings:
            if finding.surface_id == surface_id and finding.primitive == primitive:
                return finding
        self.fail(f"missing scanner finding for {surface_id} primitive {primitive}")

    def test_detects_all_universal_consequential_surfaces(self) -> None:
        cases = [
            (
                "S1",
                "tools/db_agent.py",
                """
                def agent_tool(db):
                    return db.execute("DELETE FROM customers WHERE id = 1")
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S2",
                "tools/infra_agent.py",
                """
                import subprocess
                def agent_tool():
                    return subprocess.run("terraform destroy -auto-approve", shell=True)
                """,
                {"critical_candidate"},
            ),
            (
                "S3",
                "tools/iam_agent.py",
                """
                def agent_tool(iam_client, user_id):
                    return iam_client.grant_admin(user_id)
                """,
                {"critical_candidate"},
            ),
            (
                "S4",
                "tools/payment_agent.py",
                """
                import stripe
                def agent_tool():
                    return stripe.transfers.create(amount=5000, currency="usd")
                """,
                {"critical_candidate"},
            ),
            (
                "S5",
                "tools/comms_agent.py",
                """
                def agent_tool(customer):
                    return send_email(customer.email, "account update")
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S6",
                "tools/browser_agent.py",
                """
                from playwright.sync_api import Page
                def agent_tool(page: Page):
                    page.fill("#email", "agent@example.com")
                    page.click("button[type=submit]")
                    return page.context.storage_state()
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S7",
                "tools/release_agent.py",
                """
                import subprocess
                def agent_tool():
                    return subprocess.run("git push origin main", shell=True)
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S8",
                "tools/export_agent.py",
                """
                import requests
                def agent_tool(payload):
                    return requests.post("https://webhook.example/export", json=payload)
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S9",
                "tools/iot_agent.py",
                """
                def agent_tool(door):
                    return door.unlock_door("front")
                """,
                {"critical_candidate"},
            ),
            (
                "S10",
                "tools/delegate_agent.py",
                """
                def agent_tool(args):
                    return execute_tool("filesystem.delete", args)
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S11",
                "tools/memory_agent.py",
                """
                def agent_tool(vector_store, docs):
                    return vector_store.add_documents(docs)
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S12",
                "tools/legal_agent.py",
                """
                def agent_tool(user_id):
                    return accept_terms(user_id)
                """,
                {"critical_candidate"},
            ),
            (
                "S13",
                "tools/admin_agent.py",
                """
                def agent_tool():
                    return disable_approval("refunds")
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S14",
                "tools/dispatch_agent.py",
                """
                def agent_tool(order_id):
                    return dispatch_driver(order_id)
                """,
                {"high", "critical_candidate"},
            ),
            (
                "S15",
                "tools/regulated_agent.py",
                """
                def agent_tool(patient_record):
                    return update_patient(patient_record)
                """,
                {"critical_candidate"},
            ),
        ]
        for surface_id, path, source, expected_severities in cases:
            with self.subTest(surface_id=surface_id):
                report = self._scan_source(path, source)
                finding = self._finding_for(report, surface_id)
                self.assertIn(finding.severity, expected_severities)
                self.assertIn(finding.confidence, {"medium", "high"})
                self.assertEqual("yes", finding.agent_control_context)
                self.assertTrue(finding.side_effect_type)
                self.assertTrue(finding.recommended_actenon_control)
                self.assertIn("missing proof gate", finding.control_gaps)

    def test_browser_navigation_only_is_lower_severity_context(self) -> None:
        report = self._scan_source(
            "browser/probe.py",
            """
            from playwright.sync_api import Page
            def browser_context(page: Page):
                return page.goto("https://example.com")
            """,
        )
        finding = self._finding_for(report, "S6")
        self.assertEqual("low", finding.severity)
        self.assertEqual("BROWSER_AGENT_SIDE_EFFECT", finding.category)
        self.assertEqual("browser controller", finding.path_type)

    def test_unknown_capability_path_uses_reachability_heuristic(self) -> None:
        report = self._scan_source(
            "runtime/unknown_vendor.py",
            """
            def agent_decision(client, session, payload):
                client.authenticate(session)
                return client.run(payload)
            """,
        )
        finding = self._finding_for(report, "UNKNOWN_CAPABILITY")
        self.assertEqual("capability_reachability_signal", finding.primitive)
        self.assertIn("specific action type not classified", finding.summary)
        self.assertTrue(report.findings)

    def test_unknown_mutating_api_inside_agent_tool_is_detected_without_named_sdk(self) -> None:
        report = self._scan_source(
            "agents/vendor_transport.py",
            """
            def agent_tool(model_decision, vendor_transport, payload):
                endpoint = "https://api.vendor.example/resources"
                return vendor_transport.request("POST", endpoint, json=payload)
            """,
        )
        finding = self._finding_for(report, "S8")
        payload = report.to_dict()
        self.assertEqual("mutating_http", finding.primitive)
        self.assertEqual("EXTERNAL_API_SIDE_EFFECT", finding.category)
        self.assertEqual("yes", finding.agent_control_context)
        self.assertIn("missing proof gate", finding.control_gaps)
        self.assertEqual("missing", payload["checks"]["proof_binding"]["status"])
        self.assertTrue(payload["metadata"]["side_effect_primitive_found"])
        self.assertTrue(payload["metadata"]["candidate_agent_controlled_consequential_path_found"])
        self.assertIn("candidate consequential action path", finding.summary)
        self.assertIn("runtime reachability not proven", finding.summary)

    def test_unknown_sdk_submit_in_autonomous_workflow_uses_capability_reachability(self) -> None:
        report = self._scan_source(
            "workflows/autonomous_vendor.py",
            """
            def autonomous_workflow(vendor_sdk, model_plan):
                decision = model_plan["next_action"]
                return vendor_sdk.submit_decision(decision)
            """,
        )
        finding = self._finding_for(report, "UNKNOWN_CAPABILITY")
        self.assertEqual("capability_reachability_signal", finding.primitive)
        self.assertEqual("yes", finding.agent_control_context)
        self.assertIn("missing proof gate", finding.control_gaps)
        self.assertIn(finding.severity, {"high", "medium"})
        self.assertIn("specific action type not classified", finding.summary)
        self.assertIn("runtime reachability not proven", finding.summary)

    def test_llm_output_coupled_to_mutating_http_is_detected_as_external_api_path(self) -> None:
        report = self._scan_source(
            "agents/llm_http_action.py",
            """
            import requests

            def agent_tool(llm, customer):
                model_payload = llm.invoke({"customer_id": customer.id})
                return requests.patch("https://api.vendor.example/customers/123", json=model_payload)
            """,
        )
        finding = self._finding_for_primitive(report, "S8", "mutating_http")
        payload = report.to_dict()
        self.assertEqual("mutating_http", finding.primitive)
        self.assertEqual("yes", finding.agent_control_context)
        self.assertIn("missing proof gate", finding.control_gaps)
        self.assertEqual("missing", payload["checks"]["proof_binding"]["status"])
        self.assertTrue(payload["metadata"]["side_effect_primitive_found"])
        self.assertTrue(payload["metadata"]["candidate_agent_controlled_consequential_path_found"])

    def test_unknown_mutating_path_downgrades_when_actenon_controls_are_visible(self) -> None:
        report = self._scan_source(
            "agents/protected_vendor_transport.py",
            """
            from actenon.credentials import CredentialBroker
            from actenon.execution import ProtectedExecutor
            from actenon.models import Receipt, Refusal
            from actenon.preflight import PreflightEngine
            from actenon.replay import ReplayProtector

            def agent_tool(vendor_transport, payload):
                ProtectedExecutor()
                CredentialBroker()
                PreflightEngine()
                ReplayProtector()
                Receipt
                Refusal
                return vendor_transport.request("POST", "https://api.vendor.example/resources", json=payload)
            """,
        )
        finding = self._finding_for(report, "S8")
        self.assertEqual("mutating_http", finding.primitive)
        self.assertEqual("EXTERNAL_API_SIDE_EFFECT", finding.category)
        self.assertNotIn("missing proof gate", finding.control_gaps)
        self.assertNotIn("missing credential broker", finding.control_gaps)
        self.assertNotIn("missing Receipt/Refusal emission", finding.control_gaps)
        self.assertIn(finding.severity, {"low", "medium"})
        self.assertIn(report.grade, {"A", "B", "C"})

    def test_browser_use_style_actions_are_detected_as_browser_agent_side_effects(self) -> None:
        report = self._scan_source(
            "controller/actions.py",
            """
            from browser_use import Controller

            controller = Controller()

            @controller.action("Submit account form")
            async def submit_account(browser_session, params):
                page = await browser_session.get_current_page()
                await page.fill("#email", params.email)
                await page.click("button[type=submit]")
            """,
        )
        finding = self._finding_for(report, "S6")
        self.assertEqual("BROWSER_AGENT_SIDE_EFFECT", finding.category)
        self.assertIn(finding.primitive, {"browser_action", "consequential_surface"})
        self.assertEqual("yes", finding.agent_control_context)
        self.assertIn("missing proof gate", finding.control_gaps)

    def test_computer_use_desktop_actions_are_detected(self) -> None:
        report = self._scan_source(
            "desktop/bytebot_worker.py",
            """
            import pyautogui

            def computer_use_agent(task):
                pyautogui.click(400, 220)
                pyautogui.write(task.text)
                return pyautogui.screenshot()
            """,
        )
        finding = self._finding_for(report, "S6")
        self.assertEqual("COMPUTER_USE_AGENT_SIDE_EFFECT", finding.category)
        self.assertEqual("desktop_action", finding.primitive)
        self.assertEqual("desktop controller", finding.path_type)
        self.assertEqual("yes", finding.agent_control_context)

    def test_mcp_tool_side_effect_is_separate_from_migration_strings(self) -> None:
        report = self._scan_source(
            "server.py",
            """
            from mcp import FastMCP
            mcp = FastMCP("filesystem")

            @mcp.tool()
            def delete_file(path: str):
                return filesystem.delete(path)
            """,
        )
        finding = self._finding_for(report, "S10")
        self.assertEqual("MCP_TOOL_SIDE_EFFECT", finding.category)
        self.assertEqual("tool handler", finding.path_type)

    def test_mcp_filesystem_report_prioritizes_runtime_and_separates_tests(self) -> None:
        report = self._scan_files(
            {
                "index.ts": """
                import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
                import { writeManagedFile } from "./lib";

                const server = new McpServer({ name: "filesystem", version: "1.0.0" });

                server.tool("write_file", async ({ path, content }) => {
                  return writeManagedFile(path, content);
                });
                """,
                "lib.ts": """
                import fs from "node:fs/promises";

                export async function writeManagedFile(path: string, content: string) {
                  return fs.writeFile(path, content, "utf8");
                }
                """,
                "__tests__/filesystem.test.ts": """
                import { describe, it } from "vitest";
                import fs from "node:fs/promises";

                const sortOrder = "price sort order only";

                describe("filesystem tools", () => {
                  it("validates delete tool shape", async () => {
                    await fs.unlink("tmp.txt");
                  });
                });
                """,
            }
        )
        payload = report.to_dict()
        markdown = render_markdown_report(report, mode="developer")
        runtime_findings = [
            finding for finding in report.findings if finding.context_classification == "RUNTIME_CODE"
        ]
        context_findings = [
            finding for finding in report.findings if finding.context_classification == "TEST_OR_EXAMPLE"
        ]

        self.assertEqual("Critical-impact candidate, if reachable and ungated", payload["consequence_class_label"])
        self.assertEqual("critical_impact_candidate", payload["consequence_class"])
        self.assertIs(False, payload["vulnerability_claim"])
        self.assertIsNone(payload["vulnerability_severity"])
        self.assertNotIn("static_advisory_rating", payload)
        self.assertIn("badge_labels", payload)
        self.assertIn("Actenon Scan: Review required", payload["badge_labels"])
        self.assertEqual("Not proven", payload["runtime_reachability"])
        self.assertEqual("Not verified", payload["gating_status"])
        self.assertEqual("High", payload["confidence"])
        self.assertGreaterEqual(payload["runtime_source_candidate_paths"], 2)
        self.assertGreaterEqual(payload["additional_test_example_context_findings"], 1)
        self.assertGreaterEqual(payload["metadata"]["runtime_source_finding_count"], 2)
        self.assertGreaterEqual(payload["metadata"]["test_or_example_finding_count"], 1)
        self.assertTrue(runtime_findings)
        self.assertTrue(context_findings)
        self.assertTrue(any(finding.category == "MCP_TOOL_SIDE_EFFECT" for finding in runtime_findings))
        self.assertTrue(any(finding.category == "FILE_MUTATION_SIDE_EFFECT" for finding in runtime_findings))
        self.assertTrue(all(finding.context_classification == "TEST_OR_EXAMPLE" for finding in context_findings))
        first_finding = runtime_findings[0].to_dict()
        self.assertIn("path", first_finding)
        self.assertIn("line", first_finding)
        self.assertIn("function_name", first_finding)
        self.assertIn("source_context", first_finding)
        self.assertEqual("runtime_source", first_finding["source_context"])
        self.assertIn("primitive", first_finding)
        self.assertIn("agent_control_context", first_finding)
        self.assertIn("missing_controls", first_finding)
        self.assertIn("nearby_controls_found", first_finding)
        self.assertIn("why_this_matters", first_finding)
        self.assertIn("decision source and the side effect", first_finding["why_this_matters"])
        self.assertIn("model/agent decision -> side effect -> no visible proof gate", first_finding["why_this_matters"])
        self.assertIn("generic_control", first_finding)
        self.assertIn("actenon_implementation", first_finding)
        self.assertNotIn("S4", {finding.surface_id for finding in report.findings})
        self.assertIn("MCP tool execution and file mutation paths", markdown)
        self.assertIn("## Top Runtime-Source Findings", markdown)
        self.assertIn("MCP tool handler detected without visible proof-bound execution gate.", markdown)
        self.assertIn("File mutation capability detected without visible approval/evidence policy.", markdown)
        self.assertIn("### Runtime-Source Findings", markdown)
        self.assertIn("### Test / Example / Context Findings", markdown)
        self.assertIn("Consequence Class: Critical-impact candidate, if reachable and ungated", markdown)
        self.assertIn("This is not a vulnerability severity rating", markdown)
        self.assertIn("Useful Even If You Do Not Use Actenon", markdown)
        self.assertIn("- Line: `", markdown)
        self.assertNotIn("Static Advisory Rating: Critical", markdown)
        self.assertIn("server.tool", markdown)
        self.assertIn("fs.writeFile", markdown)
        self.assertIn("```text", markdown)

    def test_test_only_mcp_findings_do_not_drive_headline_rating(self) -> None:
        report = self._scan_files(
            {
                "__tests__/filesystem.test.ts": """
                import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
                import fs from "node:fs/promises";

                const server = new McpServer({ name: "filesystem-test", version: "1.0.0" });

                server.tool("delete_file", async ({ path }) => {
                  await fs.unlink(path);
                });
                """,
                "package.json": """
                { "name": "mcp-filesystem", "description": "test package metadata" }
                """,
            }
        )
        payload = report.to_dict()

        self.assertEqual("No runtime-source candidate paths detected", payload["consequence_class_label"])
        self.assertEqual(0, payload["metadata"]["runtime_source_finding_count"])
        self.assertGreaterEqual(payload["metadata"]["test_or_example_finding_count"], 1)
        self.assertEqual(0, payload["runtime_source_candidate_paths"])
        self.assertGreaterEqual(payload["additional_test_example_context_findings"], 1)
        self.assertTrue(report.findings)
        self.assertTrue(all(finding.context_classification != "RUNTIME_CODE" for finding in report.findings))
        self.assertNotEqual("F", payload["grade"])

    def test_additional_context_count_includes_config_docs_and_tests(self) -> None:
        report = self._scan_files(
            {
                "tests/test_browser_agent.py": """
                def test_browser_action(page):
                    page.click("#submit")
                """,
                "settings.py": """
                import os
                DATABASE_URL = os.environ["DATABASE_URL"]
                """,
                "docs/snippet.py": """
                def agent_tool(api):
                    return api.post("https://example.invalid/mutate", json={})
                """,
            }
        )
        payload = report.to_dict()
        non_runtime_count = sum(1 for finding in report.findings if finding.context_classification != "RUNTIME_CODE")

        self.assertGreaterEqual(non_runtime_count, 2)
        self.assertEqual(0, payload["runtime_source_candidate_paths"])
        self.assertEqual(non_runtime_count, payload["additional_test_example_context_findings"])
        self.assertGreaterEqual(
            payload["additional_test_example_context_findings"],
            payload["metadata"]["test_or_example_finding_count"],
        )
        self.assertEqual("No runtime-source candidate paths detected", payload["consequence_class_label"])

    def test_alembic_migration_does_not_trigger_mcp_or_credential_config_findings(self) -> None:
        report = self._scan_source(
            "alembic/versions/003_add_tool_auth_enum.py",
            """
            from alembic import op

            def upgrade():
                op.create_check_constraint("ck_tool_auth_type", "tools", "auth_type in ('api_key', 'token', 'system')")

            def downgrade():
                pass
            """,
        )
        payload = report.to_dict()
        self.assertEqual([], payload["findings"])
        self.assertEqual("not_assessed", payload["checks"]["mcp_tool_boundary"]["status"])
        self.assertEqual("present", payload["checks"]["standing_credentials"]["status"])
        self.assertEqual(1, payload["metadata"]["offline_migration_context"])

    def test_alembic_credential_table_names_do_not_trigger_identity_secret_surface(self) -> None:
        report = self._scan_source(
            "alembic/versions/004_google_oauth_credentials.py",
            """
            from alembic import op
            import sqlalchemy as sa

            def upgrade():
                op.add_column("google_oauth_credentials", sa.Column("consent_app_origin", sa.String()))
                op.create_foreign_key(None, "totp_codes", "workflow_runs", ["workflow_run_id"], ["workflow_run_id"])

            def downgrade():
                pass
            """,
        )
        self.assertNotIn("S3", self._surface_ids(report))
        self.assertEqual("present", report.to_dict()["checks"]["standing_credentials"]["status"])

    def test_api_key_config_is_credential_authority_not_hardcoded_secret(self) -> None:
        report = self._scan_source(
            "config.py",
            """
            import os

            OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
            """,
        )
        finding = self._finding_for(report, "S3")
        self.assertEqual("CREDENTIAL_AUTHORITY_SIGNAL", finding.category)
        self.assertEqual("runtime_credential_authority", finding.credential_signal_kind)
        self.assertIn("not classified as hardcoded secret exposure", finding.summary.lower())
        self.assertNotIn("leaked", finding.summary.lower())
        self.assertEqual("config", finding.path_type)

    def test_agent_api_client_construction_is_standing_credential_candidate(self) -> None:
        report = self._scan_source(
            "agents/customer_support_agent.py",
            """
            from openai import OpenAI

            def agent_executor(settings, ticket):
                client = OpenAI(api_key=settings.OPENAI_API_KEY)
                return client.responses.create(input=ticket.summary)
            """,
        )
        finding = self._finding_for_primitive(report, "S3", "standing_credential_signal")
        self.assertEqual("CREDENTIAL_AUTHORITY_SIGNAL", finding.category)
        self.assertEqual("runtime_credential_authority", finding.credential_signal_kind)
        self.assertEqual("yes", finding.agent_control_context)
        self.assertIn("standing credential risk", finding.control_gaps)
        self.assertEqual("missing", report.to_dict()["checks"]["standing_credentials"]["status"])

    def test_agent_browser_session_state_is_standing_credential_candidate(self) -> None:
        report = self._scan_source(
            "agents/browser_agent.py",
            """
            def agent_tool(browser):
                context = browser.new_context(storage_state="prod-cookies.json")
                page = context.new_page()
                page.goto("https://admin.example")
                page.click("button.submit")
            """,
        )
        finding = self._finding_for_primitive(report, "S3", "standing_credential_signal")
        self.assertEqual("CREDENTIAL_AUTHORITY_SIGNAL", finding.category)
        self.assertEqual("runtime_credential_authority", finding.credential_signal_kind)
        self.assertEqual("yes", finding.agent_control_context)
        self.assertEqual("missing", report.to_dict()["checks"]["standing_credentials"]["status"])

    def test_agent_database_url_and_cloud_session_are_standing_credential_candidates(self) -> None:
        report = self._scan_source(
            "agents/data_agent.py",
            """
            import os
            import boto3
            from sqlalchemy import create_engine

            def agent_tool(task):
                engine = create_engine(os.getenv("DATABASE_URL"))
                cloud = boto3.Session(profile_name="prod-admin")
                return cloud.client("s3").delete_object(Bucket=task.bucket, Key=task.key)
            """,
        )
        credential_findings = [
            finding
            for finding in report.findings
            if finding.surface_id == "S3" and finding.primitive == "standing_credential_signal"
        ]
        self.assertGreaterEqual(len(credential_findings), 1)
        self.assertTrue(all(finding.credential_signal_kind == "runtime_credential_authority" for finding in credential_findings))
        self.assertEqual("missing", report.to_dict()["checks"]["standing_credentials"]["status"])

    def test_mcp_tool_with_direct_credentials_reports_broker_gap(self) -> None:
        report = self._scan_source(
            "server.py",
            """
            import os
            import stripe
            from mcp import FastMCP

            mcp = FastMCP("payments")

            @mcp.tool()
            def issue_refund(payment_id):
                stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
                return stripe.refunds.create(payment_intent=payment_id)
            """,
        )
        payload = report.to_dict()
        self.assertEqual("missing", payload["checks"]["credential_broker"]["status"])
        self.assertEqual("missing", payload["checks"]["standing_credentials"]["status"])
        self.assertTrue(any(finding.category == "MCP_TOOL_SIDE_EFFECT" for finding in report.findings))
        credential_finding = self._finding_for_primitive(report, "S3", "standing_credential_signal")
        self.assertIn("standing credential risk", credential_finding.control_gaps)

    def test_test_example_credential_signals_are_downgraded_context(self) -> None:
        report = self._scan_source(
            "tests/test_agent_credentials.py",
            """
            import os

            def test_agent_uses_fake_key():
                fake_key = os.getenv("STRIPE_SECRET_KEY")
                assert fake_key is None
            """,
        )
        finding = self._finding_for_primitive(report, "S3", "standing_credential_signal")
        payload = report.to_dict()
        self.assertEqual("TEST_OR_EXAMPLE", finding.context_classification)
        self.assertEqual("low", finding.severity)
        self.assertEqual(0, payload["runtime_source_candidate_paths"])
        self.assertGreaterEqual(payload["additional_test_example_context_findings"], 1)

    def test_offline_migration_suppresses_bare_credential_enum_keywords(self) -> None:
        report = self._scan_source(
            "alembic/versions/001_add_auth_type.py",
            """
            from alembic import op

            def upgrade():
                op.create_table("credential_policy", "api_key", "token", "auth_type")

            def downgrade():
                op.drop_table("credential_policy")
            """,
        )
        payload = report.to_dict()
        self.assertEqual([], payload["findings"])
        self.assertEqual("present", payload["checks"]["standing_credentials"]["status"])
        self.assertEqual(1, payload["metadata"]["offline_migration_context"])
        self.assertGreaterEqual(payload["metadata"]["credential_keyword_suppressed_in_migration"], 1)

    def test_strong_runtime_secret_still_fires_in_migration_context(self) -> None:
        report = self._scan_source(
            "migrations/002_runtime_secret.py",
            """
            from alembic import op
            import os

            def upgrade():
                return os.environ["STRIPE_SECRET_KEY"]

            def downgrade():
                pass
            """,
        )
        self.assertIn("S3", self._surface_ids(report))
        self.assertEqual("missing", report.to_dict()["checks"]["standing_credentials"]["status"])

    def test_enum_constant_context_does_not_create_runtime_secret_finding(self) -> None:
        report = self._scan_source(
            "auth/types.py",
            """
            from enum import Enum

            class AuthType(str, Enum):
                API_KEY = "api_key"
                TOKEN = "token"
            """,
        )
        self.assertNotIn("S3", self._surface_ids(report))

    def test_actenon_controls_improve_grade_and_remove_primary_gaps(self) -> None:
        report = self._scan_source(
            "tools/protected_payment.py",
            """
            from actenon.models import ActionIntent, PCCB, Receipt, Refusal
            from actenon.execution import ProtectedExecutor
            from actenon.credentials import CredentialBroker, BrokeredCredential
            from actenon.preflight import PreflightEngine
            from actenon.replay import ReplayProtector

            def agent_tool(payment):
                approval = "human approval evidence"
                human_override = True
                ReplayProtector()
                PreflightEngine()
                ProtectedExecutor()
                CredentialBroker()
                Receipt
                Refusal
                return payment.release_payment("invoice-1")
            """,
        )
        finding = self._finding_for(report, "S4")
        self.assertIn(report.grade, {"A", "B"})
        self.assertNotIn("missing proof gate", finding.control_gaps)
        self.assertNotIn("missing credential broker", finding.control_gaps)
        self.assertEqual("present", report.to_dict()["checks"]["proof_binding"]["status"])

    def test_json_and_markdown_reports_are_cautious_and_actionable(self) -> None:
        report = self._scan_source(
            "tools/slack_agent.py",
            """
            def agent_tool(slack_client):
                return slack_client.chat_postMessage(channel="#ops", text="hello")
            """,
        )
        payload_text = json.dumps(report.to_dict()).lower()
        markdown = render_markdown_report(report)
        combined = f"{payload_text}\n{markdown.lower()}"
        for term in UNSAFE_DEFINITIVE_TERMS:
            self.assertNotIn(term, combined)
        self.assertIn("recommended_actenon_control", payload_text)
        self.assertIn("# Actenon Agentic Action Scan", markdown)
        self.assertIn("## Executive Summary", markdown)
        self.assertIn("## Action Surface Map", markdown)
        self.assertIn("## Priority Fixes", markdown)
        self.assertIn("## Recommended Integration Points", markdown)
        self.assertIn("Runtime-source candidate paths", markdown)
        self.assertIn("Consequence Class", markdown)
        self.assertIn("not a vulnerability severity rating", markdown)
        self.assertIn("Useful Even If You Do Not Use Actenon", markdown)
        self.assertIn("candidate_consequential_action_paths", payload_text)
        self.assertIn("consequence_class", payload_text)
        self.assertIn("vulnerability_claim", payload_text)
        self.assertIn("vulnerability_severity", payload_text)
        self.assertNotIn("static_advisory_rating", payload_text)
        self.assertIn("runtime_source_count", payload_text)
        self.assertIn("test_context_count", payload_text)
        self.assertIn("why_this_matters", payload_text)
        self.assertIn("generic_control", payload_text)
        self.assertIn("actenon_implementation", payload_text)
        self.assertIn("categories_detected", payload_text)
        self.assertIn("Consequence Class is advisory static analysis", markdown)
        self.assertIn("candidate consequential action path", combined)
        self.assertIn("static advisory", combined)
        self.assertIn("runtime reachability not proven", combined)
        self.assertIn("runtime exploitability not proven", combined)

        developer_markdown = render_markdown_report(report, mode="developer")
        self.assertIn("Path type", developer_markdown)
        self.assertIn("Context classification", developer_markdown)


if __name__ == "__main__":
    unittest.main()
