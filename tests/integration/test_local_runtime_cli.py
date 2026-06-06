from __future__ import annotations

import json
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import main
from actenon.local_runtime_server import start_local_runtime_services


class LocalRuntimeCliIntegrationTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_up_bootstrap_only_bootstraps_single_node_runtime(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            code, stdout, stderr = self._run_cli(["up", "--runtime-dir", str(runtime_dir), "--bootstrap-only", "--json"])
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual("bootstrap-only", payload["mode"])
            self.assertEqual(str(runtime_dir.resolve()), payload["runtime"]["runtime_root"])
            self.assertTrue((runtime_dir / "runtime_manifest.json").exists())
            self.assertTrue((runtime_dir / "labs" / "local_proof" / "manifest.json").exists())
            self.assertTrue((runtime_dir / "labs" / "invoice_payment_local_proof" / "manifest.json").exists())
            self.assertTrue((runtime_dir / "labs" / "portable_local_proof" / "manifest.json").exists())
            self.assertTrue((runtime_dir / "labs" / "local_proof" / "state" / "escrow.sqlite3").exists())
            self.assertEqual(str((runtime_dir / "artifacts").resolve()), payload["runtime"]["storage"]["artifacts_root"])
            self.assertEqual(str((runtime_dir / "state").resolve()), payload["runtime"]["storage"]["state_root"])
            self.assertEqual(
                str((runtime_dir / "state" / "replay.sqlite3").resolve()),
                payload["runtime"]["storage"]["replay_store"]["path"],
            )
            self.assertEqual(
                str((runtime_dir / "state" / "escrow.sqlite3").resolve()),
                payload["runtime"]["storage"]["capability_escrow"]["path"],
            )
            self.assertEqual("sqlite", payload["runtime"]["storage"]["replay_store"]["type"])
            self.assertEqual("sqlite", payload["runtime"]["storage"]["capability_escrow"]["type"])
            self.assertEqual("json-artifact-store", payload["runtime"]["storage"]["receipt_store"]["type"])
            self.assertEqual("json-artifact-store", payload["runtime"]["storage"]["refusal_store"]["type"])
            self.assertEqual("local-artifact-index", payload["runtime"]["storage"]["evidence_query_source"]["type"])

    def test_up_bootstrap_only_migrates_legacy_runtime_layout(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            legacy_runtime_server = runtime_dir / "runtime_server"
            legacy_runtime_server.mkdir(parents=True, exist_ok=True)
            (legacy_runtime_server / "requests").mkdir(parents=True, exist_ok=True)
            (legacy_runtime_server / "state").mkdir(parents=True, exist_ok=True)
            (legacy_runtime_server / "service_manifest.json").write_text('{"format":"legacy"}\n', encoding="utf-8")
            (legacy_runtime_server / "state" / "replay.sqlite3").write_text("", encoding="utf-8")
            (runtime_dir / "lab" / "portable_local_proof").mkdir(parents=True, exist_ok=True)

            code, _stdout, stderr = self._run_cli(["up", "--runtime-dir", str(runtime_dir), "--bootstrap-only"])
            self.assertEqual(0, code, stderr)
            self.assertTrue((runtime_dir / "service_manifest.json").exists())
            self.assertTrue((runtime_dir / "state" / "replay.sqlite3").exists())
            self.assertTrue((runtime_dir / "labs").exists())

    def test_doctor_reports_needs_attention_after_bootstrap_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            self._run_cli(["up", "--runtime-dir", str(runtime_dir), "--bootstrap-only"])
            code, stdout, stderr = self._run_cli(["doctor", "--runtime-dir", str(runtime_dir), "--json"])
            self.assertEqual(1, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("fast", payload["mode"])
            self.assertEqual("needs_attention", payload["overall_status"])
            self.assertEqual(10, payload["summary"]["total"])
            checks = {item["name"]: item for item in payload["checks"]}
            self.assertEqual("ok", checks["signer"]["status"])
            self.assertEqual("ok", checks["replay_store"]["status"])
            self.assertEqual("ok", checks["escrow_store"]["status"])
            self.assertEqual("ok", checks["artifact_directory"]["status"])
            self.assertEqual("fail", checks["runtime_server"]["status"])
            self.assertEqual("fail", checks["key_discovery"]["status"])
            self.assertEqual("fail", checks["trace_viewer"]["status"])
            self.assertNotIn("outcome_writer", checks)
            self.assertNotIn("local_runtime_storage", checks)
            self.assertNotIn("portable_verification", checks)
            self.assertNotIn("evidence_query", checks)
            self.assertNotIn("scanner_harness", checks)
            self.assertEqual(3, len(payload["action_items"]))

    def test_doctor_deep_runs_labs_and_scanner_checks(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            self._run_cli(["up", "--runtime-dir", str(runtime_dir), "--bootstrap-only"])
            code, stdout, stderr = self._run_cli(["doctor", "--runtime-dir", str(runtime_dir), "--deep", "--json"])
            self.assertEqual(1, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("deep", payload["mode"])
            checks = {item["name"]: item for item in payload["checks"]}
            self.assertEqual("ok", checks["local_proof_lab"]["status"])
            self.assertEqual("ok", checks["local_runtime_storage"]["status"])
            self.assertEqual("ok", checks["outcome_writer"]["status"])
            self.assertEqual("ok", checks["portable_verifier_lab"]["status"])
            self.assertEqual("ok", checks["portable_verification"]["status"])
            self.assertEqual("ok", checks["evidence_query"]["status"])
            self.assertEqual("ok", checks["scanner_harness"]["status"])

    def test_doctor_reports_ready_when_runtime_is_serving(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                trace_viewer_port=0,
            )
            try:
                code, stdout, stderr = self._run_cli(["doctor", "--runtime-dir", str(runtime_dir), "--json"])
            finally:
                session.close()
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("fast", payload["mode"])
            self.assertEqual("ready", payload["overall_status"])
            checks = {item["name"]: item for item in payload["checks"]}
            self.assertEqual("ok", checks["runtime_server"]["status"])
            self.assertEqual("ok", checks["key_discovery"]["status"])
            self.assertEqual("ok", checks["trace_viewer"]["status"])

    def test_simulate_all_runs_expected_local_incidents(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            code, stdout, stderr = self._run_cli(["simulate", "--runtime-dir", str(runtime_dir), "--scenario", "all", "--json"])
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["succeeded"])
            self.assertTrue(payload["takeaways"])
            results = {item["name"]: item for item in payload["results"]}
            self.assertEqual("verified", results["valid-proof"]["status"])
            self.assertEqual("AUDIENCE_MISMATCH", results["audience-mismatch"]["reason_code"])
            self.assertEqual("ACTION_HASH_MISMATCH", results["action-hash-mismatch"]["reason_code"])
            self.assertEqual("PROOF_EXPIRED", results["expired-proof"]["reason_code"])
            self.assertEqual("DUPLICATE_REPLAY", results["replay-refused"]["reason_code"])
            self.assertTrue((runtime_dir / "simulations" / "manifest.json").exists())
            self.assertTrue((runtime_dir / "simulations" / "replay-refused" / "INCIDENT_SUMMARY.md").exists())
            self.assertTrue((runtime_dir / "simulations" / "replay-refused" / "counterfactual_unprotected_execution.json").exists())
            self.assertTrue((runtime_dir / "simulations" / "replay-refused" / "intent_record.json").exists())
            replay_perspectives = {item["key"]: item for item in results["replay-refused"]["perspectives"]}
            self.assertEqual("would_verify_twice", replay_perspectives["proof_verifier_only"]["status"])
            self.assertEqual("first_execution_then_refused", replay_perspectives["protected_endpoint_runtime"]["status"])
            self.assertIn("Replay protection is a runtime property", results["replay-refused"]["lesson"])

    def test_simulate_single_scenario_makes_execution_gap_explicit(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            code, stdout, stderr = self._run_cli(
                ["simulate", "--runtime-dir", str(runtime_dir), "--scenario", "audience-mismatch", "--json"]
            )
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("audience-mismatch", payload["scenario"])
            self.assertEqual(1, len(payload["results"]))
            result = payload["results"][0]
            self.assertEqual("refused", result["status"])
            self.assertEqual("AUDIENCE_MISMATCH", result["reason_code"])
            perspectives = {item["key"]: item for item in result["perspectives"]}
            self.assertEqual("counterfactual", perspectives["without_execution_edge"]["basis"])
            self.assertEqual("would_execute", perspectives["without_execution_edge"]["status"])
            self.assertEqual("would_refuse", perspectives["proof_verifier_only"]["status"])
            self.assertEqual("refused", perspectives["protected_endpoint_runtime"]["status"])
            self.assertTrue(Path(result["summary_path"]).exists())
            self.assertTrue((runtime_dir / "simulations" / "audience-mismatch" / "counterfactual_unprotected_execution.json").exists())
            self.assertTrue((runtime_dir / "simulations" / "audience-mismatch" / "intent_record.json").exists())

    def test_simulate_named_incidents_write_signature_artifacts(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            code, stdout, stderr = self._run_cli(["simulate", "--runtime-dir", str(runtime_dir), "--incident", "all", "--json"])
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("incident", payload["mode"])
            self.assertTrue(payload["succeeded"])
            self.assertIn("Educational simulations and pattern reconstructions.", payload["framing_note"])
            results = {item["name"]: item for item in payload["results"]}
            self.assertEqual({"prod-delete", "replit", "openai-eggs", "amazon-kiro"}, set(results))
            self.assertEqual("approval-required", results["prod-delete"]["status"])
            self.assertEqual(
                "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
                results["prod-delete"]["reason_code"],
            )
            self.assertEqual("refused", results["replit"]["status"])
            self.assertEqual("ACTION_HASH_MISMATCH", results["replit"]["reason_code"])
            self.assertEqual("approval-required", results["openai-eggs"]["status"])
            self.assertEqual("refused", results["amazon-kiro"]["status"])
            for incident_name in ("prod-delete", "replit", "openai-eggs", "amazon-kiro"):
                incident_root = runtime_dir / "simulations" / incident_name
                self.assertTrue((incident_root / "INCIDENT_SUMMARY.md").exists())
                self.assertTrue((incident_root / "incident_story.json").exists())
                self.assertTrue((incident_root / "framing.json").exists())
                self.assertTrue((incident_root / "intent_record.json").exists())
                self.assertTrue((incident_root / "trace_viewer_follow_up.json").exists())
            self.assertTrue((runtime_dir / "simulations" / "prod-delete" / "without_actenon.json").exists())
            self.assertTrue((runtime_dir / "simulations" / "prod-delete" / "preflight_decision.json").exists())
            self.assertTrue((runtime_dir / "simulations" / "prod-delete" / "credential_broker_boundary.json").exists())
            self.assertTrue((runtime_dir / "simulations" / "prod-delete" / "refusal.json").exists())
            for incident_name in ("replit", "openai-eggs", "amazon-kiro"):
                incident_root = runtime_dir / "simulations" / incident_name
                self.assertTrue((incident_root / "weak_control_path.json").exists())
                self.assertTrue((incident_root / "proof_bound_path.json").exists())
                self.assertTrue((incident_root / "proof_only_gap.json").exists())
                self.assertTrue((incident_root / "bounded_intent_change.json").exists())

    def test_simulate_named_incident_replit_explains_action_drift(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            code, stdout, stderr = self._run_cli(["simulate", "--runtime-dir", str(runtime_dir), "--incident", "replit", "--json"])
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("incident", payload["mode"])
            self.assertEqual("replit", payload["scenario"])
            self.assertEqual(1, len(payload["results"]))
            result = payload["results"][0]
            self.assertEqual("Replit-Style Destructive Drift", result["title"])
            self.assertEqual("refused", result["status"])
            self.assertEqual("ACTION_HASH_MISMATCH", result["reason_code"])
            perspectives = {item["key"]: item for item in result["perspectives"]}
            self.assertEqual("would_execute", perspectives["weak_control_path"]["status"])
            self.assertEqual("refused", perspectives["proof_bound_path"]["status"])
            self.assertEqual("still_needs_runtime_state", perspectives["proof_only_gap"]["status"])
            self.assertEqual("constrained", perspectives["bounded_intent_change"]["status"])
            incident_root = runtime_dir / "simulations" / "replit"
            self.assertTrue((incident_root / "action_intent.json").exists())
            self.assertTrue((incident_root / "intent_record.json").exists())
            self.assertTrue((incident_root / "pccb.json").exists())
            self.assertTrue((incident_root / "refusal.json").exists())
            self.assertTrue((incident_root / "counterfactual_unprotected_execution.json").exists())
            intent_record = json.loads((incident_root / "intent_record.json").read_text(encoding="utf-8"))
            self.assertEqual("intent_record", intent_record["contract"]["name"])
            self.assertEqual("issued", intent_record["proof"]["status"])
            self.assertIn("database.drop", intent_record["boundaries"]["prohibited_actions"])

    def test_simulate_named_incident_openai_eggs_requires_approval_before_proof(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            code, stdout, stderr = self._run_cli(["simulate", "--runtime-dir", str(runtime_dir), "--incident", "openai-eggs", "--json"])
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            result = payload["results"][0]
            self.assertEqual("approval-required", result["status"])
            self.assertIsNone(result["reason_code"])
            self.assertIsNotNone(result["receipt_id"])
            perspectives = {item["key"]: item for item in result["perspectives"]}
            self.assertEqual("approval-required", perspectives["proof_bound_path"]["status"])
            incident_root = runtime_dir / "simulations" / "openai-eggs"
            self.assertTrue((incident_root / "action_intent.json").exists())
            self.assertTrue((incident_root / "intent_record.json").exists())
            self.assertTrue((incident_root / "decision.json").exists())
            self.assertTrue((incident_root / "decision_receipt.json").exists())
            self.assertTrue((incident_root / "counterfactual_unprotected_execution.json").exists())
            intent_record = json.loads((incident_root / "intent_record.json").read_text(encoding="utf-8"))
            self.assertEqual("approval-required", intent_record["decision"]["outcome"])
            self.assertEqual("not-issued", intent_record["proof"]["status"])
            self.assertEqual(["customer_confirmed"], intent_record["boundaries"]["required_approvals"])

    def test_hero_pattern_scenarios_write_preflight_and_broker_artifacts(self) -> None:
        scenarios = {
            "mcp-tool-proof-laundering": "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
            "iam-escalation": "PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED",
            "data-export": "PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED",
        }
        with TemporaryDirectory() as tempdir:
            for scenario, reason_code in scenarios.items():
                runtime_dir = Path(tempdir) / scenario
                code, stdout, stderr = self._run_cli(
                    ["simulate", "--runtime-dir", str(runtime_dir), "--scenario", scenario, "--json"]
                )
                self.assertEqual(0, code, stderr)
                payload = json.loads(stdout)
                self.assertTrue(payload["succeeded"])
                result = payload["results"][0]
                self.assertEqual(scenario, result["name"])
                self.assertEqual("approval-required", result["status"])
                self.assertEqual(reason_code, result["reason_code"])
                perspectives = {item["key"]: item for item in result["perspectives"]}
                self.assertEqual("would_execute", perspectives["without_actenon"]["status"])
                self.assertEqual("approval-required", perspectives["with_preflight"]["status"])
                self.assertEqual("side_door_removed", perspectives["with_credential_broker"]["status"])
                scenario_root = runtime_dir / "simulations" / scenario
                self.assertTrue((scenario_root / "without_actenon.json").exists())
                self.assertTrue((scenario_root / "preflight_decision.json").exists())
                self.assertTrue((scenario_root / "decision_receipt.json").exists())
                self.assertTrue((scenario_root / "refusal.json").exists())
                self.assertTrue((scenario_root / "refused_receipt.json").exists())
                self.assertTrue((scenario_root / "credential_broker_boundary.json").exists())
                self.assertTrue((scenario_root / "what_actenon_does_not_claim.json").exists())
                broker = json.loads((scenario_root / "credential_broker_boundary.json").read_text(encoding="utf-8"))
                self.assertFalse(broker["agent_has_standing_credential"])
                self.assertFalse(broker["raw_secret_exposed"])
                decision = json.loads((scenario_root / "preflight_decision.json").read_text(encoding="utf-8"))
                self.assertEqual(reason_code, decision["reason_code"])

    def test_incident_docs_do_not_publish_unsourced_pocketos_claim(self) -> None:
        docs_root = Path(__file__).resolve().parents[2] / "docs" / "incidents"
        docs = "".join(path.read_text(encoding="utf-8") for path in docs_root.glob("*.md"))
        self.assertNotIn("PocketOS", docs)
        self.assertIn("not a named factual incident report", docs)

    def test_bundle_export_writes_actenon_bundle_with_chain_manifest(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            bundle_path = Path(tempdir) / "runtime_bundle.actenon"
            self._run_cli(["up", "--runtime-dir", str(runtime_dir), "--bootstrap-only"])
            self._run_cli(["simulate", "--runtime-dir", str(runtime_dir), "--scenario", "audience-mismatch"])
            code, stdout, stderr = self._run_cli(
                [
                    "bundle",
                    "export",
                    "--runtime-dir",
                    str(runtime_dir),
                    "--output",
                    str(bundle_path),
                    "--json",
                ]
            )
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("zip", payload["kind"])
            self.assertTrue(bundle_path.exists())
            with zipfile.ZipFile(bundle_path) as archive:
                self.assertIn("bundle_manifest.json", archive.namelist())
                self.assertIn("runtime_manifest.json", archive.namelist())
                manifest = json.loads(archive.read("bundle_manifest.json").decode("utf-8"))
            self.assertEqual("portable_execution_evidence_bundle", manifest["artifact_class"])
            self.assertEqual(".actenon", manifest["file_extension"])
            self.assertGreaterEqual(manifest["summary"]["proof_chain_count"], 1)
            self.assertIn("simulations/audience-mismatch/action_intent.json", manifest["file_hashes"])
            first_chain = manifest["evidence_chains"][0]
            self.assertIn("intent", first_chain)
            self.assertIn("pccb", first_chain)
            self.assertIn("outcome", first_chain)

    def test_bundle_verify_reports_success_for_exported_bundle(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            bundle_path = Path(tempdir) / "runtime_bundle.actenon"
            self._run_cli(["up", "--runtime-dir", str(runtime_dir), "--bootstrap-only"])
            self._run_cli(["simulate", "--runtime-dir", str(runtime_dir), "--incident", "replit"])
            export_code, _stdout, export_stderr = self._run_cli(
                ["bundle", "export", "--runtime-dir", str(runtime_dir), "--output", str(bundle_path)]
            )
            self.assertEqual(0, export_code, export_stderr)

            code, stdout, stderr = self._run_cli(["bundle", "verify", str(bundle_path), "--json"])
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual("portable_execution_evidence_bundle", payload["artifact_class"])
            self.assertGreaterEqual(payload["summary"]["verified_proof_chain_count"], 1)
            self.assertEqual([], payload["errors"])

    def test_bundle_verify_detects_tampered_directory_bundle(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            bundle_dir = Path(tempdir) / "runtime_bundle_dir"
            self._run_cli(["up", "--runtime-dir", str(runtime_dir), "--bootstrap-only"])
            self._run_cli(["simulate", "--runtime-dir", str(runtime_dir), "--scenario", "audience-mismatch"])
            export_code, _stdout, export_stderr = self._run_cli(
                ["bundle", "export", "--runtime-dir", str(runtime_dir), "--output", str(bundle_dir)]
            )
            self.assertEqual(0, export_code, export_stderr)

            tampered_target = bundle_dir / "simulations" / "audience-mismatch" / "refusal.json"
            tampered = json.loads(tampered_target.read_text(encoding="utf-8"))
            tampered["message"] = "tampered refusal"
            tampered_target.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            code, stdout, stderr = self._run_cli(["bundle", "verify", str(bundle_dir), "--json"])
            self.assertEqual(1, code, stderr)
            payload = json.loads(stdout)
            self.assertFalse(payload["ok"])
            self.assertTrue(any("digest mismatch" in item.lower() or "file hash mismatch" in item.lower() for item in payload["errors"]))

    def test_keys_generate_writes_local_hmac_key_file(self) -> None:
        with TemporaryDirectory() as tempdir:
            key_path = Path(tempdir) / "local_key.json"
            code, stdout, stderr = self._run_cli(
                [
                    "keys",
                    "generate",
                    "--key-id",
                    "local-runtime-test",
                    "--output",
                    str(key_path),
                    "--json",
                ]
            )
            self.assertEqual(0, code, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertTrue(key_path.exists())
            key_payload = json.loads(key_path.read_text(encoding="utf-8"))
            self.assertEqual("actenon-local-hmac-key-v1", key_payload["format"])
            self.assertEqual("local-runtime-test", key_payload["key_id"])
            self.assertFalse(key_payload["publishable"])


if __name__ == "__main__":
    unittest.main()
