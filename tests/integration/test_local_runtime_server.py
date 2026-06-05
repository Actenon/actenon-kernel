from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from actenon.local_runtime import simulate_local_runtime
from actenon.local_runtime_server import start_local_runtime_services


class LocalRuntimeServerIntegrationTests(unittest.TestCase):
    def _request_json(
        self,
        url: str,
        *,
        expected_status: int,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        request = Request(url, method="POST" if payload is not None else "GET")
        if payload is not None:
            request.data = json.dumps(payload).encode("utf-8")
            request.add_header("Content-Type", "application/json")
        try:
            with urlopen(request, timeout=5) as response:
                status = response.status
                body = response.read()
        except HTTPError as exc:
            status = exc.code
            body = exc.read()
        self.assertEqual(expected_status, status, body.decode("utf-8"))
        return json.loads(body.decode("utf-8"))

    def test_health_and_key_discovery_surface_are_available(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                trace_viewer_port=0,
            )
            try:
                self.assertTrue((runtime_dir / "service_manifest.json").exists())
                health = self._request_json(session.startup_info.health_url, expected_status=200)
                self.assertTrue(health["ok"])
                self.assertEqual(session.startup_info.issuer_url, health["issuer_url"])
                self.assertEqual(session.startup_info.intents_url, health["intents_url"])
                self.assertEqual("actenon_local_runtime", health["issuer"]["id"])
                self.assertEqual(["refund.execute", "invoice_payment.execute"], health["supported_capabilities"])
                self.assertEqual(f"{session.startup_info.issuer_url}/v1/preflight", health["preflight_url"])
                self.assertEqual(str((runtime_dir / "artifacts").resolve()), health["artifact_dir"])
                self.assertEqual(str((runtime_dir / "state" / "replay.sqlite3").resolve()), health["replay_store_path"])
                self.assertEqual(str((runtime_dir / "state" / "escrow.sqlite3").resolve()), health["escrow_store_path"])
                self.assertFalse(health["key_discovery_available"])
                self.assertEqual(str((runtime_dir / "keys" / "actenon-keys.json").resolve()), health["key_discovery_document_path"])
                self.assertEqual(f"curl -s {session.startup_info.health_url}", health["next_step_example"])
                self.assertIsNotNone(health["trace_viewer_url"])

                canonical = self._request_json(session.startup_info.key_discovery_url, expected_status=409)
                self.assertEqual("KEY_DISCOVERY_UNAVAILABLE", canonical["reason_code"])
                self.assertEqual(str((runtime_dir / "keys" / "actenon-keys.json").resolve()), canonical["publication_path"])
                legacy = self._request_json(session.startup_info.key_discovery_alias_url, expected_status=409)
                self.assertEqual("KEY_DISCOVERY_UNAVAILABLE", legacy["reason_code"])
            finally:
                session.close()

    def test_post_preflight_returns_local_decision(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                enable_trace_viewer=False,
            )
            try:
                issued_at = "2026-01-01T12:00:00Z"
                payload = {
                    "contract": {"name": "action_intent", "version": "v1"},
                    "intent_id": "intent_preflight_endpoint_001",
                    "issued_at": issued_at,
                    "expires_at": "2026-01-01T12:10:00Z",
                    "tenant": {"tenant_id": "tenant_alpha"},
                    "requester": {"type": "agent", "id": "infra-agent"},
                    "action": {
                        "name": "database.delete",
                        "capability": "database.delete",
                        "parameters": {"environment": "production", "resource_id": "prod-db-primary"},
                    },
                    "target": {
                        "resource_type": "database",
                        "resource_id": "prod-db-primary",
                        "selectors": {"environment": "production"},
                    },
                }
                response = self._request_json(
                    f"{session.startup_info.issuer_url}/v1/preflight",
                    expected_status=200,
                    payload={
                        "action_intent": payload,
                        "evidence_context": {"change_ticket": "CHG-001", "backup_verified": True},
                    },
                )
                self.assertTrue(response["ok"])
                self.assertEqual("preflight_decision", response["decision"]["contract"]["name"])
                self.assertEqual("approval_required", response["decision"]["outcome"])
                self.assertEqual("PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED", response["decision"]["reason_code"])
            finally:
                session.close()

    def test_key_discovery_route_rejects_non_discovery_documents(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                enable_trace_viewer=False,
            )
            try:
                (runtime_dir / "keys" / "actenon-keys.json").write_text(
                    json.dumps(
                        {
                            "format": "actenon-local-hmac-key-v1",
                            "key_id": "local-runtime-dev",
                            "algorithm": "HS256",
                            "publishable": False,
                            "secret_b64url": "not-a-real-secret",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                payload = self._request_json(session.startup_info.key_discovery_url, expected_status=409)
                self.assertEqual("KEY_DISCOVERY_INVALID", payload["reason_code"])
                self.assertIn("must not be served", payload["summary"])
            finally:
                session.close()

    def test_trace_viewer_startup_does_not_depend_on_current_working_directory(self) -> None:
        original_cwd = Path.cwd()
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            outside_cwd = Path(tempdir) / "elsewhere"
            outside_cwd.mkdir(parents=True, exist_ok=True)
            os.chdir(outside_cwd)
            try:
                session = start_local_runtime_services(
                    runtime_dir=runtime_dir,
                    port=0,
                    trace_viewer_port=0,
                )
                try:
                    self.assertEqual("started", session.startup_info.trace_viewer_status)
                    runs = self._request_json(f"{session.startup_info.trace_viewer_url}/api/runs", expected_status=200)
                    titles = {run["title"] for run in runs["runs"]}
                    self.assertIn("Local Proof: Refund", titles)
                    self.assertIn("Local Proof: Invoice Payment", titles)
                    simulate_local_runtime(runtime_dir, incident="replit")
                    runs_after_simulation = self._request_json(f"{session.startup_info.trace_viewer_url}/api/runs", expected_status=200)
                    titles_after_simulation = {run["title"] for run in runs_after_simulation["runs"]}
                    self.assertIn("Incident Simulator", titles_after_simulation)
                finally:
                    session.close()
            finally:
                os.chdir(original_cwd)

    def test_post_intents_reuses_local_kernel_minting_and_writes_artifacts(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                enable_trace_viewer=False,
            )
            try:
                intent_path = runtime_dir / "labs" / "local_proof" / "scenarios" / "allow" / "action_intent.json"
                payload = json.loads(intent_path.read_text(encoding="utf-8"))
                response = self._request_json(
                    session.startup_info.intents_url,
                    expected_status=200,
                    payload={
                        "action_intent": payload,
                        "context": {"now": payload["issued_at"]},
                    },
                )
                self.assertTrue(response["ok"])
                self.assertEqual("allow", response["decision"]["outcome"])
                self.assertEqual("actenon_local_runtime", response["issuer"]["id"])
                self.assertEqual(["refund.execute", "invoice_payment.execute"], response["supported_capabilities"])
                self.assertIsNotNone(response["escrow_id"])
                self.assertIsNotNone(response["pccb"])
                self.assertIsNotNone(response["receipt"])
                self.assertIsNone(response["refusal"])

                artifacts = response["artifacts"]
                self.assertTrue(Path(artifacts["request_dir"]).exists())
                self.assertTrue(Path(artifacts["action_intent"]).exists())
                self.assertTrue(Path(artifacts["context"]).exists())
                self.assertTrue(Path(artifacts["intent_record"]).exists())
                self.assertTrue(Path(artifacts["pccb"]).exists())
                self.assertTrue(Path(artifacts["receipt"]).exists())
                intent_record = json.loads(Path(artifacts["intent_record"]).read_text(encoding="utf-8"))
                self.assertEqual("intent_record", intent_record["contract"]["name"])
                self.assertEqual("allow", intent_record["decision"]["outcome"])
                self.assertEqual("issued", intent_record["proof"]["status"])
            finally:
                session.close()

    def test_post_intents_returns_deny_and_approval_required_shapes(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                enable_trace_viewer=False,
            )
            try:
                deny_payload = json.loads((runtime_dir / "labs" / "local_proof" / "scenarios" / "deny" / "action_intent.json").read_text(encoding="utf-8"))
                deny_response = self._request_json(
                    session.startup_info.intents_url,
                    expected_status=200,
                    payload={"action_intent": deny_payload, "context": {"now": deny_payload["issued_at"]}},
                )
                self.assertFalse(deny_response["ok"])
                self.assertEqual("deny", deny_response["decision"]["outcome"])
                self.assertIsNone(deny_response["escrow_id"])
                self.assertIsNone(deny_response["pccb"])
                self.assertIsNotNone(deny_response["receipt"])
                self.assertIsNotNone(deny_response["refusal"])
                deny_intent_record = json.loads(Path(deny_response["artifacts"]["intent_record"]).read_text(encoding="utf-8"))
                self.assertEqual("deny", deny_intent_record["decision"]["outcome"])
                self.assertEqual("not-issued", deny_intent_record["proof"]["status"])

                approval_payload = json.loads(
                    (runtime_dir / "labs" / "local_proof" / "scenarios" / "approval_required" / "action_intent.json").read_text(encoding="utf-8")
                )
                approval_response = self._request_json(
                    session.startup_info.intents_url,
                    expected_status=200,
                    payload={"action_intent": approval_payload, "context": {"now": approval_payload["issued_at"]}},
                )
                self.assertTrue(approval_response["ok"])
                self.assertEqual("approval-required", approval_response["decision"]["outcome"])
                self.assertIsNone(approval_response["escrow_id"])
                self.assertIsNone(approval_response["pccb"])
                self.assertIsNotNone(approval_response["receipt"])
                self.assertIsNone(approval_response["refusal"])
                approval_intent_record = json.loads(Path(approval_response["artifacts"]["intent_record"]).read_text(encoding="utf-8"))
                self.assertEqual("approval-required", approval_intent_record["decision"]["outcome"])
                self.assertEqual("not-issued", approval_intent_record["proof"]["status"])
            finally:
                session.close()

    def test_post_intents_supports_invoice_payment_workflow_outcomes(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                enable_trace_viewer=False,
            )
            try:
                approval_payload = json.loads(
                    (runtime_dir / "labs" / "invoice_payment_local_proof" / "scenarios" / "approval_missing" / "action_intent.json").read_text(
                        encoding="utf-8"
                    )
                )
                approval_response = self._request_json(
                    session.startup_info.intents_url,
                    expected_status=200,
                    payload={"action_intent": approval_payload, "context": {"now": approval_payload["issued_at"]}},
                )
                self.assertTrue(approval_response["ok"])
                self.assertEqual("approval-required", approval_response["decision"]["outcome"])
                self.assertIsNone(approval_response["pccb"])
                self.assertIsNotNone(approval_response["receipt"])
                self.assertIsNone(approval_response["refusal"])

                evidence_payload = json.loads(
                    (runtime_dir / "labs" / "invoice_payment_local_proof" / "scenarios" / "evidence_missing" / "action_intent.json").read_text(
                        encoding="utf-8"
                    )
                )
                evidence_response = self._request_json(
                    session.startup_info.intents_url,
                    expected_status=200,
                    payload={"action_intent": evidence_payload, "context": {"now": evidence_payload["issued_at"]}},
                )
                self.assertTrue(evidence_response["ok"])
                self.assertEqual("needs-evidence", evidence_response["decision"]["outcome"])
                self.assertIsNone(evidence_response["pccb"])
                self.assertIsNotNone(evidence_response["receipt"])
                self.assertIsNone(evidence_response["refusal"])
            finally:
                session.close()


if __name__ == "__main__":
    unittest.main()
