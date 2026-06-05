from __future__ import annotations

import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from actenon.cli import _load_json
from actenon.core.json import DEFAULT_MAX_JSON_BYTES, DuplicateJSONKeyError, JSONInputTooLargeError
from actenon.local_runtime import LOCAL_RUNTIME_BUNDLE_FORMAT, verify_local_runtime_bundle
from actenon.receipts import JsonArtifactReceiptStore, JsonArtifactRefusalStore


class JsonAndArtifactParsingAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_cli_json_loader_fails_closed_on_malformed_duplicate_and_oversized_json(self) -> None:
        malformed = self.root / "malformed.json"
        duplicate = self.root / "duplicate.json"
        oversized = self.root / "oversized.json"
        malformed.write_text('{"contract": ', encoding="utf-8")
        duplicate.write_text('{"contract":{"name":"receipt","name":"shadow"}}', encoding="utf-8")
        oversized.write_text('{"payload":"' + ("a" * DEFAULT_MAX_JSON_BYTES) + '"}', encoding="utf-8")

        with self.assertRaises(json.JSONDecodeError):
            _load_json(str(malformed))
        with self.assertRaises(DuplicateJSONKeyError):
            _load_json(str(duplicate))
        with self.assertRaises(JSONInputTooLargeError):
            _load_json(str(oversized))

    def test_receipt_and_refusal_artifact_stores_reject_duplicate_keys(self) -> None:
        artifact_root = self.root / "artifacts"
        (artifact_root / "receipts").mkdir(parents=True)
        (artifact_root / "refusals").mkdir(parents=True)
        (artifact_root / "receipts" / "rcpt_dup.json").write_text(
            '{"contract":{"name":"receipt","version":"v1"},"receipt_id":"rcpt_dup","receipt_id":"shadow"}',
            encoding="utf-8",
        )
        (artifact_root / "refusals" / "rfsl_dup.json").write_text(
            '{"contract":{"name":"refusal","version":"v1"},"refusal_id":"rfsl_dup","refusal_id":"shadow"}',
            encoding="utf-8",
        )

        with self.assertRaises(DuplicateJSONKeyError):
            JsonArtifactReceiptStore(artifact_root).get_receipt("rcpt_dup")
        with self.assertRaises(DuplicateJSONKeyError):
            JsonArtifactRefusalStore(artifact_root).get_refusal("rfsl_dup")

    def test_local_runtime_bundle_path_traversal_member_does_not_escape_and_fails_closed(self) -> None:
        bundle_path = self.root / "malicious.actenon"
        outside = self.root / "outside.txt"
        manifest = {
            "format": LOCAL_RUNTIME_BUNDLE_FORMAT,
            "artifact_class": "portable_execution_evidence_bundle",
            "entries": ["../outside.txt"],
            "file_hashes": {},
            "evidence_chains": [],
            "decision_records": [],
            "integrity_model": {},
        }
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bundle_manifest.json", json.dumps(manifest))
            archive.writestr("../outside.txt", "traversal payload")

        result = verify_local_runtime_bundle(bundle_path)

        self.assertFalse(outside.exists())
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_public_archive_scripts_reject_private_and_local_path_patterns(self) -> None:
        validation_script = Path("scripts/validate_public_boundary.sh").read_text(encoding="utf-8")
        archive_script = Path("scripts/create_public_release_archive.sh").read_text(encoding="utf-8")
        required_patterns = (
            "AI Agent Execution Control Layer",
            ".actenon",
            ".actenon-scan",
            ".ruff_cache",
            ".pytest_cache",
            "*.sqlite",
            "*.sqlite3",
            "node_modules",
            "__MACOSX",
        )

        for pattern in required_patterns:
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, validation_script)
                self.assertIn(pattern, archive_script)


if __name__ == "__main__":
    unittest.main()
