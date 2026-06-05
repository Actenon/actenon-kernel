from __future__ import annotations

import json
import unittest

from actenon.models import PCCB
from actenon.proof import build_action_hash_input, canonicalize_bytes, canonicalize_json, sha256_hex
from actenon.proof.signers.base import b64url_decode, b64url_encode


class CanonicalizationInteropTests(unittest.TestCase):
    def test_public_imports_are_stable(self) -> None:
        self.assertTrue(callable(canonicalize_json))
        self.assertTrue(callable(canonicalize_bytes))
        self.assertTrue(callable(sha256_hex))
        self.assertTrue(callable(build_action_hash_input))
        self.assertTrue(callable(PCCB.unsigned_payload))

    def test_nested_dicts_are_deterministic_and_key_sorted(self) -> None:
        left = {"z": {"b": 2, "a": 1}, "a": {"d": 4, "c": 3}}
        right = {"a": {"c": 3, "d": 4}, "z": {"a": 1, "b": 2}}

        self.assertEqual('{"a":{"c":3,"d":4},"z":{"a":1,"b":2}}', canonicalize_json(left))
        self.assertEqual(canonicalize_json(left), canonicalize_json(right))
        self.assertEqual(sha256_hex(left), sha256_hex(right))

    def test_lists_and_tuples_canonicalize_as_arrays(self) -> None:
        self.assertEqual("[1,true,null,\"x\"]", canonicalize_json([1, True, None, "x"]))
        self.assertEqual("[1,true,null,\"x\"]", canonicalize_json((1, True, None, "x")))
        self.assertEqual(canonicalize_bytes([1, 2]), canonicalize_bytes((1, 2)))

    def test_unicode_strings_are_emitted_without_ascii_escaping_or_normalization(self) -> None:
        nfc = "é"
        nfd = "e\u0301"

        self.assertEqual('"é"', canonicalize_json(nfc))
        self.assertEqual('"é"', canonicalize_json(nfd))
        self.assertNotEqual(canonicalize_bytes(nfc), canonicalize_bytes(nfd))
        self.assertNotEqual(sha256_hex(nfc), sha256_hex(nfd))

    def test_booleans_null_and_integers_are_locked(self) -> None:
        self.assertEqual("true", canonicalize_json(True))
        self.assertEqual("false", canonicalize_json(False))
        self.assertEqual("null", canonicalize_json(None))
        self.assertEqual("0", canonicalize_json(0))
        self.assertEqual("-42", canonicalize_json(-42))

    def test_floats_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            canonicalize_json(1.25)
        with self.assertRaises(TypeError):
            canonicalize_json({"amount": 1.25})

    def test_non_string_object_keys_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            canonicalize_json({1: "not-a-json-object-key"})

    def test_duplicate_json_key_vector_is_explicitly_detectable_before_canonicalization(self) -> None:
        raw = '{"amount":100,"amount":200}'

        def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            seen: set[str] = set()
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in seen:
                    raise ValueError(f"duplicate JSON object key {key!r}")
                seen.add(key)
                result[key] = value
            return result

        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            json.loads(raw, object_pairs_hook=reject_duplicate_keys)

    def test_base64url_helpers_emit_unpadded_values_and_round_trip(self) -> None:
        encoded = b64url_encode(b"\xfb\xff\x00")

        self.assertEqual("-_8A", encoded)
        self.assertNotIn("=", encoded)
        self.assertEqual(b"\xfb\xff\x00", b64url_decode(encoded))


if __name__ == "__main__":
    unittest.main()
