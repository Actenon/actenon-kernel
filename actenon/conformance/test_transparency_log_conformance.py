"""Transparency-log checks for the packaged conformance suite."""

from __future__ import annotations

import json
import unittest
from importlib.util import find_spec
from pathlib import Path

from actenon.verifier import (
    TransparencyVerificationError,
    verify_checkpoint_signature,
    verify_consistency,
    verify_countersignature,
    verify_countersignature_inclusion,
    verify_inclusion,
    verify_monitor_update,
)


VECTOR_ROOT = (
    Path(__file__).resolve().parents[2]
    / "conformance"
    / "vectors"
    / "transparency_log_v1"
)


def _load(relative_path: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / relative_path).read_text(encoding="utf-8"))


@unittest.skipUnless(
    find_spec("cryptography") is not None,
    "transparency-log conformance requires the 'asymmetric' extra",
)
class TransparencyLogConformanceTests(unittest.TestCase):
    def test_checkpoint_rotation_inclusion_and_consistency_verify_offline(self) -> None:
        trusted_keys = _load("trusted_keys.json")
        old_checkpoint = _load("checkpoint_old.json")
        new_checkpoint = _load("checkpoint_new.json")

        old_verified = verify_checkpoint_signature(old_checkpoint, trusted_keys)
        new_verified = verify_checkpoint_signature(new_checkpoint, trusted_keys)
        inclusion = verify_inclusion(
            _load("leaf_digest.json"),
            _load("inclusion_proof.json"),
            new_checkpoint,
        )
        consistency = verify_consistency(
            old_checkpoint,
            new_checkpoint,
            _load("consistency_proof.json"),
        )

        self.assertEqual("fixture-log-2025", old_verified.key_id)
        self.assertEqual("fixture-log-2026", new_verified.key_id)
        self.assertEqual(2, inclusion.leaf_index)
        self.assertEqual((2, 4), (consistency.old_tree_size, consistency.new_tree_size))

    def test_monitor_accepts_append_only_update(self) -> None:
        update = verify_monitor_update(
            _load("checkpoint_old.json"),
            _load("checkpoint_new.json"),
            _load("consistency_proof.json"),
            _load("trusted_keys.json"),
        )

        self.assertEqual(2, update.previous.tree_size)
        self.assertEqual(4, update.current.tree_size)

    def test_signed_fork_is_detected(self) -> None:
        same_size_proof = {
            "contract": {
                "name": "transparency_consistency_proof",
                "version": "v1",
            },
            "log_id": "actenon-transparency-fixture",
            "hash_algorithm": "sha-256",
            "old_tree_size": 4,
            "new_tree_size": 4,
            "consistency_path": [],
        }
        with self.assertRaises(TransparencyVerificationError) as raised:
            verify_monitor_update(
                _load("checkpoint_new.json"),
                _load("mutations/checkpoint_new_forked.json"),
                same_size_proof,
                _load("trusted_keys.json"),
            )

        self.assertEqual("EQUIVOCATION_DETECTED", raised.exception.code)

    def test_rewind_is_detected(self) -> None:
        with self.assertRaises(TransparencyVerificationError) as raised:
            verify_consistency(
                _load("checkpoint_new.json"),
                _load("checkpoint_old.json"),
                _load("consistency_proof.json"),
            )

        self.assertEqual("REWIND_DETECTED", raised.exception.code)

    def test_unknown_checkpoint_kid_is_rejected(self) -> None:
        with self.assertRaises(TransparencyVerificationError) as raised:
            verify_checkpoint_signature(
                _load("mutations/checkpoint_unknown_kid.json"),
                _load("trusted_keys.json"),
            )

        self.assertEqual("UNKNOWN_KEY_ID", raised.exception.code)

    def test_orphan_countersignature_is_rejected(self) -> None:
        orphan = _load("mutations/countersignature_orphan.json")
        trusted_keys = _load("trusted_keys.json")

        verify_countersignature(orphan["receipt_digest"], orphan, trusted_keys)
        with self.assertRaises(TransparencyVerificationError) as raised:
            verify_countersignature_inclusion(
                orphan,
                _load("inclusion_proof.json"),
                _load("checkpoint_new.json"),
                trusted_keys,
            )

        self.assertEqual("ORPHAN_COUNTERSIGNATURE", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
