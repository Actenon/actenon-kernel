from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from actenon.cli import main
from actenon.demo.local_proof import run_local_proof_demo
from actenon.models import (
    ActionHashSpec,
    ActionSpec,
    AudienceRef,
    CorrelationRef,
    PartyRef,
    Refusal,
    TargetRef,
    TenantRef,
)


class _RecordingHttpExecutionGraphClient:
    published_anchors = []

    def __init__(self, endpoint_url: str) -> None:
        self.endpoint_url = endpoint_url

    def publish(self, anchor) -> None:
        self.__class__.published_anchors.append((self.endpoint_url, anchor))


class GraphAnchorCliIntegrationTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_graph_anchor_dry_run_from_receipt_auto_resolves_sibling_pccb(self) -> None:
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)

            code, stdout, stderr = self._run_cli(
                [
                    "graph",
                    "anchor",
                    "--receipt",
                    str(artifact_root / "scenarios" / "allow" / "execution_receipt.json"),
                    "--dry-run",
                    "--json",
                ]
            )

            self.assertEqual(0, code, stderr)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual("receipt", payload["source"]["kind"])
            self.assertEqual("executed", payload["anchor"]["outcome"])
            self.assertFalse(payload["publication"]["requested"])
            self.assertIn("receipt_digest", payload["anchor"])

    def test_graph_anchor_dry_run_from_refusal_supports_explicit_pccb(self) -> None:
        with TemporaryDirectory() as tempdir:
            scenario_dir = Path(tempdir) / "scenario"
            scenario_dir.mkdir(parents=True, exist_ok=True)
            pccb_payload = {
                "contract": {"name": "pccb", "version": "v1"},
                "pccb_id": "pccb_cli_graph_001",
                "intent_id": "intent_cli_graph_001",
                "issued_at": "2026-04-11T12:00:00Z",
                "not_before": "2026-04-11T12:00:00Z",
                "expires_at": "2026-04-11T12:05:00Z",
                "issuer": {"type": "service", "id": "kernel"},
                "subject": {"type": "service", "id": "actor_123"},
                "tenant": {"tenant_id": "tenant_alpha"},
                "audience": {"type": "service", "id": "refund-endpoint"},
                "action": {
                    "name": "refund.create",
                    "capability": "refund.execute",
                    "parameters": {"amount_minor": 1000, "currency": "USD"},
                },
                "target": {"resource_type": "payment", "resource_id": "pay_001"},
                "scope": {"mode": "exact", "capabilities": ["refund.execute"], "single_use": True},
                "nonce": "nonce_cli_graph_001",
                "action_hash": {
                    "algorithm": "sha-256",
                    "canonicalization": "RFC8785-JCS",
                    "value": "ab" * 32,
                },
                "escrow_reference": {"escrow_id": "esc_cli_graph_001", "single_use": True},
                "signature": {
                    "algorithm": "HS256",
                    "key_id": "local-proof-v1",
                    "encoding": "base64url",
                    "value": "signature_cli_graph_001",
                },
            }
            pccb_path = scenario_dir / "pccb.json"
            pccb_path.write_text(json.dumps(pccb_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            refusal = Refusal(
                refusal_id="rfsl_cli_graph_001",
                category="proof",
                refusal_code="AUDIENCE_MISMATCH",
                message="The proof audience does not match this endpoint.",
                retryable=False,
                refused_at=datetime(2026, 4, 11, 12, 1, tzinfo=timezone.utc),
                intent_id="intent_cli_graph_001",
                tenant=TenantRef(tenant_id="tenant_alpha"),
                subject=PartyRef(type="service", id="actor_123"),
                audience=AudienceRef(type="service", id="wrong-endpoint"),
                action=ActionSpec(
                    name="refund.create",
                    capability="refund.execute",
                    parameters={"amount_minor": 1000, "currency": "USD"},
                ),
                target=TargetRef(resource_type="payment", resource_id="pay_001"),
                correlation=CorrelationRef(
                    pccb_id="pccb_cli_graph_001",
                    escrow_id="esc_cli_graph_001",
                    action_hash=ActionHashSpec(
                        algorithm="sha-256",
                        canonicalization="RFC8785-JCS",
                        value="ab" * 32,
                    ),
                ),
            )
            refusal_path = scenario_dir / "refusal.json"
            refusal_path.write_text(json.dumps(refusal.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

            code, stdout, stderr = self._run_cli(
                [
                    "graph",
                    "anchor",
                    "--refusal",
                    str(refusal_path),
                    "--pccb",
                    str(pccb_path),
                    "--dry-run",
                    "--json",
                ]
            )

            self.assertEqual(0, code, stderr)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual("refusal", payload["source"]["kind"])
            self.assertEqual("refused", payload["anchor"]["outcome"])
            self.assertIn("refusal_digest", payload["anchor"])

    def test_graph_anchor_can_request_publication_via_http_client(self) -> None:
        _RecordingHttpExecutionGraphClient.published_anchors = []
        with TemporaryDirectory() as tempdir:
            artifact_root = Path(tempdir) / "local"
            run_local_proof_demo(artifact_root)

            with patch("actenon.cli.HttpExecutionGraphClient", _RecordingHttpExecutionGraphClient):
                code, stdout, stderr = self._run_cli(
                    [
                        "graph",
                        "anchor",
                        "--receipt",
                        str(artifact_root / "scenarios" / "allow" / "execution_receipt.json"),
                        "--publish-url",
                        "https://graph.example/anchors",
                        "--json",
                    ]
                )

            self.assertEqual(0, code, stderr)
            self.assertEqual("", stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["publication"]["requested"])
            self.assertEqual(1, len(_RecordingHttpExecutionGraphClient.published_anchors))
            endpoint_url, anchor = _RecordingHttpExecutionGraphClient.published_anchors[0]
            self.assertEqual("https://graph.example/anchors", endpoint_url)
            self.assertEqual("executed", anchor.outcome)


if __name__ == "__main__":
    unittest.main()
