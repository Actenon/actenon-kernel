from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from actenon.local_runtime_server import start_local_runtime_services
from examples.refund_guard_local.call_endpoint import main as call_endpoint_main
from examples.refund_guard_local.server import start_refund_guard_server


class RefundGuardLocalServerIntegrationTests(unittest.TestCase):
    def _request_json(
        self,
        url: str,
        *,
        expected_status: int,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        request = Request(url, method="POST" if payload is not None else "GET")
        if payload is not None:
            request.add_header("Content-Type", "application/json")
            request.data = json.dumps(payload).encode("utf-8")
        try:
            with urlopen(request, timeout=5) as response:
                status = response.status
                body = response.read()
        except HTTPError as exc:
            status = exc.code
            body = exc.read()
        self.assertEqual(expected_status, status, body.decode("utf-8"))
        return json.loads(body.decode("utf-8"))

    def _run_call_endpoint(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = call_endpoint_main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_refund_guard_server_executes_then_refuses_duplicate_replay(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            runtime_session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                enable_trace_viewer=False,
            )
            refund_server = start_refund_guard_server(runtime_dir=runtime_dir, port=0)
            try:
                health = self._request_json(refund_server.startup_info.health_url, expected_status=200)
                self.assertTrue(health["ok"])
                self.assertEqual("service:local-refund-endpoint", health["audience"])
                self.assertEqual(["refund.execute"], health["capabilities"])
                self.assertEqual(refund_server.startup_info.local_admission_url, health["local_admission_url"])
                self.assertEqual(str((runtime_dir / "state" / "replay.sqlite3").resolve()), health["replay_store_path"])
                self.assertEqual(str((runtime_dir / "state" / "escrow.sqlite3").resolve()), health["escrow_store_path"])

                allow_intent = json.loads(
                    (runtime_dir / "labs" / "local_proof" / "scenarios" / "allow" / "action_intent.json").read_text(encoding="utf-8")
                )
                issued = self._request_json(
                    runtime_session.startup_info.intents_url,
                    expected_status=200,
                    payload={"action_intent": allow_intent, "context": {"now": allow_intent["issued_at"]}},
                )
                issue_response_path = runtime_dir / "issued_refund.json"
                issue_response_path.write_text(json.dumps(issued, indent=2, sort_keys=True) + "\n", encoding="utf-8")

                code, stdout, stderr = self._run_call_endpoint(
                    ["--issue-response", str(issue_response_path), "--endpoint-url", refund_server.startup_info.refunds_url, "--json"]
                )
                self.assertEqual(0, code, stderr)
                executed = json.loads(stdout)
                self.assertTrue(executed["ok"])
                self.assertEqual("executed", executed["receipt"]["outcome"])
                self.assertIsNone(executed["refusal"])
                self.assertTrue(Path(executed["artifacts"]["receipt"]).exists())
                state = json.loads(Path(executed["artifacts"]["state_path"]).read_text(encoding="utf-8"))
                self.assertEqual(3500, state["payments"]["payment_demo_001"]["remaining_refundable_minor"])
                self.assertEqual(1, len(state["payments"]["payment_demo_001"]["refunds"]))

                code, stdout, stderr = self._run_call_endpoint(
                    ["--issue-response", str(issue_response_path), "--endpoint-url", refund_server.startup_info.refunds_url, "--json"]
                )
                self.assertEqual(0, code, stderr)
                refused = json.loads(stdout)
                self.assertFalse(refused["ok"])
                self.assertEqual("DUPLICATE_REPLAY", refused["refusal"]["refusal_code"])
                self.assertEqual("refused", refused["receipt"]["outcome"])
                self.assertTrue(Path(refused["artifacts"]["refusal"]).exists())
            finally:
                refund_server.close()
                runtime_session.close()

    def test_refund_guard_local_admission_supports_allow_and_approval_required(self) -> None:
        with TemporaryDirectory() as tempdir:
            runtime_dir = Path(tempdir) / "runtime"
            runtime_session = start_local_runtime_services(
                runtime_dir=runtime_dir,
                port=0,
                enable_trace_viewer=False,
            )
            refund_server = start_refund_guard_server(runtime_dir=runtime_dir, port=0)
            try:
                allow_response = self._request_json(
                    refund_server.startup_info.local_admission_url,
                    expected_status=200,
                    payload={
                        "payment_id": "payment_demo_001",
                        "amount_minor": 1200,
                        "currency": "USD",
                        "requester_id": "framework_agent",
                        "risk_level": "normal",
                        "tenant_id": "tenant_demo",
                    },
                )
                self.assertTrue(allow_response["ok"])
                self.assertEqual("proof-absent-local-admission", allow_response["mode"])
                self.assertEqual("edge-only-admission", allow_response["adoption_stage"])
                self.assertEqual("allow", allow_response["decision"]["outcome"])
                self.assertIsNotNone(allow_response["normalized_action_intent"])
                self.assertIsNotNone(allow_response["pccb"])
                self.assertIsNotNone(allow_response["admission_receipt"])
                self.assertIsNotNone(allow_response["execution_receipt"])
                self.assertIsNone(allow_response["refusal"])
                self.assertTrue(Path(allow_response["artifacts"]["action_intent"]).exists())
                self.assertTrue(Path(allow_response["artifacts"]["pccb"]).exists())
                self.assertTrue(Path(allow_response["artifacts"]["execution_receipt"]).exists())

                approval_response = self._request_json(
                    refund_server.startup_info.local_admission_url,
                    expected_status=200,
                    payload={
                        "payment_id": "payment_demo_001",
                        "amount_minor": 2200,
                        "currency": "USD",
                        "requester_id": "framework_agent",
                        "risk_level": "approval",
                        "tenant_id": "tenant_demo",
                    },
                )
                self.assertTrue(approval_response["ok"])
                self.assertEqual("approval-required", approval_response["decision"]["outcome"])
                self.assertIsNotNone(approval_response["admission_receipt"])
                self.assertIsNone(approval_response["execution_receipt"])
                self.assertIsNone(approval_response["pccb"])
                self.assertIsNone(approval_response["refusal"])
                self.assertTrue(Path(approval_response["artifacts"]["action_intent"]).exists())
                self.assertTrue(Path(approval_response["artifacts"]["admission_receipt"]).exists())
            finally:
                refund_server.close()
                runtime_session.close()


if __name__ == "__main__":
    unittest.main()
