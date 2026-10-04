"""Path-traversal attacks on file-backed artifact stores and bundles.

Receipt and refusal ids reach the JSON artifact stores from untrusted
input: an agent-supplied ``Action Intent.evidence_refs[].value`` is looked
up with ``get_receipt``. Bundle manifests are attacker-controlled files.
Neither may make the kernel read a file outside the directory it was
pointed at.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from actenon.api import ActionIntentIntakeService, build_refund_action_intent_payload
from actenon.local_runtime import verify_local_runtime_bundle
from actenon.models import (
    ActionSpec,
    AudienceRef,
    CorrelationRef,
    PartyRef,
    Receipt,
    Refusal,
    TargetRef,
    TenantRef,
    receipt_evidence_ref,
)
from actenon.models.runtime import DynamicContextInput
from actenon.policy import ReceiptEvidenceVerificationRule
from actenon.receipts import JsonArtifactReceiptStore, JsonArtifactRefusalStore

NOW = datetime(2026, 4, 11, 15, 0, tzinfo=timezone.utc)


def _receipt(receipt_id: str) -> Receipt:
    return Receipt(
        receipt_id=receipt_id,
        intent_id="intent_forged_source",
        occurred_at=NOW,
        outcome="executed",
        phase="execution",
        tenant=TenantRef(tenant_id="tenant_demo"),
        subject=PartyRef(type="service", id="demo_actor"),
        action=ActionSpec(
            name="refund.create",
            capability="refund.execute",
            parameters={"amount_minor": 1200, "currency": "USD"},
        ),
        target=TargetRef(resource_type="payment", resource_id="pay_demo_001"),
        summary="Forged prior outcome planted outside the receipt store.",
        correlation=CorrelationRef(request_id="req_forged"),
        side_effects={"state": "completed"},
    )


class ReceiptStorePathTraversalTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.store_root = self.root / "runtime" / "outcomes"
        (self.store_root / "receipts").mkdir(parents=True)
        (self.store_root / "refusals").mkdir(parents=True)
        # An attacker who can drop a file anywhere on disk (an upload
        # directory, /tmp, a shared volume) plants a "receipt" there.
        self.planted = self.root / "uploads" / "evil.json"
        self.planted.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_get_receipt_does_not_read_outside_the_store(self) -> None:
        traversal_id = "../../../uploads/evil"
        self.planted.write_text(json.dumps(_receipt(traversal_id).to_dict()), encoding="utf-8")
        store = JsonArtifactReceiptStore(self.store_root)
        self.assertIsNone(store.get_receipt(traversal_id))
        self.assertIsNone(store.get_receipt(str(self.planted.with_suffix(""))))

    def test_get_refusal_does_not_read_outside_the_store(self) -> None:
        traversal_id = "../../../uploads/evil"
        refusal = Refusal(
            refusal_id=traversal_id,
            category="proof",
            reason_code="PROOF_INVALID",
            message="planted",
            retryable=False,
            refused_at=NOW,
        )
        self.planted.write_text(json.dumps(refusal.to_dict()), encoding="utf-8")
        self.assertIsNone(JsonArtifactRefusalStore(self.store_root).get_refusal(traversal_id))

    def test_stored_receipt_must_carry_the_requested_id(self) -> None:
        (self.store_root / "receipts" / "rcpt_a.json").write_text(
            json.dumps(_receipt("rcpt_b").to_dict()), encoding="utf-8"
        )
        self.assertIsNone(JsonArtifactReceiptStore(self.store_root).get_receipt("rcpt_a"))

    def test_legitimate_receipt_still_loads(self) -> None:
        (self.store_root / "receipts" / "rcpt_ok.json").write_text(
            json.dumps(_receipt("rcpt_ok").to_dict()), encoding="utf-8"
        )
        loaded = JsonArtifactReceiptStore(self.store_root).get_receipt("rcpt_ok")
        self.assertIsNotNone(loaded)
        self.assertEqual("rcpt_ok", loaded.receipt_id)

    def test_evidence_policy_rejects_a_planted_receipt(self) -> None:
        traversal_id = "../../../uploads/evil"
        forged = _receipt(traversal_id)
        self.planted.write_text(json.dumps(forged.to_dict()), encoding="utf-8")
        ref = receipt_evidence_ref(forged)
        payload = build_refund_action_intent_payload(
            intent_id="intent_receipt_chain_001",
            tenant_id="tenant_demo",
            requester_id="demo_actor",
            payment_id="pay_demo_001",
            amount_minor=1200,
            currency="USD",
            issued_at=NOW,
            evidence_refs=[ref.to_dict()],
        )
        intent = ActionIntentIntakeService().parse(payload)
        context = DynamicContextInput(
            request_id="req_path_traversal",
            audience=AudienceRef(type="service", id="refund-endpoint"),
            scope_capabilities=("refund.execute",),
            now=NOW,
        )
        evaluation = ReceiptEvidenceVerificationRule(
            receipt_store=JsonArtifactReceiptStore(self.store_root)
        ).evaluate(intent, context)
        self.assertIsNotNone(evaluation)
        self.assertEqual("deny", evaluation.outcome)
        self.assertEqual("RECEIPT_EVIDENCE_MISSING", evaluation.reason_code)


class BundleManifestPathTraversalTests(unittest.TestCase):
    def _bundle(self, tempdir: Path, manifest: dict) -> Path:
        bundle = tempdir / "attack.actenon"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("bundle_manifest.json", json.dumps(manifest))
        return bundle

    def test_manifest_file_hashes_cannot_reference_host_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            secret = root / "host_secret.txt"
            secret.write_text("host-only content", encoding="utf-8")
            import hashlib

            digest = hashlib.sha256(secret.read_bytes()).hexdigest()
            manifest = {
                "format": "actenon-local-runtime-bundle-v1",
                "entries": [],
                "file_hashes": {
                    str(secret): {"algorithm": "sha-256", "value": digest},
                    "../../../../../../../../" + str(secret).lstrip("/"): {"algorithm": "sha-256", "value": digest},
                },
                "evidence_chains": [],
                "decision_records": [],
            }
            from actenon.local_runtime import LOCAL_RUNTIME_BUNDLE_FORMAT

            manifest["format"] = LOCAL_RUNTIME_BUNDLE_FORMAT
            result = verify_local_runtime_bundle(self._bundle(root, manifest))
            self.assertFalse(result["ok"])
            self.assertEqual(0, result["summary"]["verified_file_count"])
            self.assertTrue(any("outside the bundle" in error for error in result["errors"]), result["errors"])

    def test_manifest_chain_artifacts_cannot_reference_host_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            outside = root / "outside_intent.json"
            outside.write_text("{}", encoding="utf-8")
            from actenon.local_runtime import LOCAL_RUNTIME_BUNDLE_FORMAT

            manifest = {
                "format": LOCAL_RUNTIME_BUNDLE_FORMAT,
                "entries": [],
                "file_hashes": {},
                "evidence_chains": [
                    {"intent": {"path": str(outside), "intent_id": "x", "digest": {}}, "pccb": {}, "outcome": {}}
                ],
                "decision_records": [],
            }
            result = verify_local_runtime_bundle(self._bundle(root, manifest))
            self.assertFalse(result["ok"])
            self.assertTrue(any("outside the bundle" in error for error in result["errors"]), result["errors"])


if __name__ == "__main__":
    unittest.main()
