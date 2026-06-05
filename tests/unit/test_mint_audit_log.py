from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
from pathlib import Path

from actenon.api.intake import ActionIntentIntakeService
from actenon.demo.portable_local_proof import build_hello_world_action_intent_payload
from actenon.models import AudienceRef, PolicyDecision
from actenon.proof import LocalAppendOnlyAuditLogSink, PCCBMinter, PCCBMintAuditRecord, build_local_proof_signer
from actenon.verifier import VerifierSDK


class _RecordingAuditSink:
    def __init__(self) -> None:
        self.records: list[PCCBMintAuditRecord] = []

    def record_pccb_mint(self, record: PCCBMintAuditRecord) -> None:
        self.records.append(record)


class PCCBMintAuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = build_local_proof_signer()
        self.sdk = VerifierSDK(self.signer)
        self.intent = ActionIntentIntakeService().parse(build_hello_world_action_intent_payload())
        self.context = self.sdk.build_context(
            request_id="req_mint_audit_001",
            audience=AudienceRef(type="service", id="portable-hello-world-endpoint"),
            now=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
            scope_capabilities=("protected_resource.read",),
            parameter_constraints={"exact_message": "portable hello world"},
            resource_selectors=({"resource_id": "hello_resource_demo_001"},),
        )
        self.decision = PolicyDecision(
            outcome="allow",
            summary="Mint audit test allow.",
            rule_evaluations=(),
            reason_codes=("LOCAL_PROOF_ALLOW",),
        )

    def _mint(self, *, audit_sink=None, pccb_id="pccb_mint_audit_001"):
        return PCCBMinter(
            signer=self.signer,
            issuer=self.intent.requester,
            pccb_id_factory=lambda: pccb_id,
            nonce_factory=lambda: f"nonce-{pccb_id}",
            audit_sink=audit_sink,
        ).mint(self.intent, self.decision, self.context, escrow_id=f"esc_{pccb_id}")

    def test_audit_sink_is_invoked_on_mint(self) -> None:
        sink = _RecordingAuditSink()
        pccb = self._mint(audit_sink=sink)

        self.assertEqual(1, len(sink.records))
        record = sink.records[0].to_dict()
        self.assertEqual("pccb_minted", record["event_type"])
        self.assertEqual(pccb.pccb_id, record["pccb_id"])
        self.assertEqual(pccb.intent_id, record["intent_id"])
        self.assertEqual("local-proof-v1", record["signature"]["key_id"])
        self.assertEqual("sha-256", record["tenant_digest"]["algorithm"])

    def test_local_append_only_sink_appends_jsonl_records(self) -> None:
        with TemporaryDirectory() as tempdir:
            audit_path = Path(tempdir) / "nested" / "mint-audit.jsonl"
            sink = LocalAppendOnlyAuditLogSink(audit_path)

            self._mint(audit_sink=sink, pccb_id="pccb_mint_audit_001")
            self._mint(audit_sink=sink, pccb_id="pccb_mint_audit_002")

            lines = audit_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(2, len(lines))
            records = [json.loads(line) for line in lines]
            self.assertEqual("pccb_mint_audit_001", records[0]["pccb_id"])
            self.assertEqual("pccb_mint_audit_002", records[1]["pccb_id"])
            self.assertEqual("pccb_mint_audit_record", records[0]["contract"]["name"])

    def test_audit_record_avoids_plaintext_sensitive_action_material(self) -> None:
        sink = _RecordingAuditSink()
        self._mint(audit_sink=sink)

        record = sink.records[0].to_dict()
        serialized = json.dumps(record, sort_keys=True)
        self.assertNotIn("portable hello world", serialized)
        self.assertNotIn("hello_resource_demo_001", serialized)
        self.assertNotIn("tenant_alpha", serialized)
        self.assertNotIn("actor_123", serialized)
        self.assertIn("action_hash", record)
        self.assertIn("target", record)
        self.assertIn("resource_digest", record["target"])

    def test_no_sink_minting_remains_graceful(self) -> None:
        pccb = self._mint()

        verified = self.sdk.verify(intent=self.intent, pccb=pccb, context=self.context)
        self.assertEqual("pccb_mint_audit_001", verified.pccb.pccb_id)


if __name__ == "__main__":
    unittest.main()
