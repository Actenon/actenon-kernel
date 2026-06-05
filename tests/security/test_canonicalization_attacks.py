from __future__ import annotations

import unittest

from actenon.core.json import (
    DEFAULT_MAX_JSON_BYTES,
    DEFAULT_MAX_JSON_DEPTH,
    DuplicateJSONKeyError,
    JSONInputTooLargeError,
    JSONNestingDepthError,
    loads_no_duplicate_keys,
)
from actenon.proof import canonicalize_bytes, canonicalize_json, sha256_hex
from actenon.proof.canonical import DEFAULT_MAX_CANONICAL_OUTPUT_BYTES


def _deep_value() -> object:
    value: object = "leaf"
    for _ in range(DEFAULT_MAX_JSON_DEPTH):
        value = [value]
    return value


class CanonicalizationAttackTests(unittest.TestCase):
    def test_key_order_is_invariant(self) -> None:
        left = {"b": 2, "a": {"z": 1, "m": 2}}
        right = {"a": {"m": 2, "z": 1}, "b": 2}

        self.assertEqual(canonicalize_bytes(left), canonicalize_bytes(right))
        self.assertEqual(sha256_hex(left), sha256_hex(right))

    def test_added_field_and_value_mutations_change_digest(self) -> None:
        original = {"amount": 1000, "currency": "USD"}

        self.assertNotEqual(sha256_hex(original), sha256_hex({**original, "extra": "field"}))
        self.assertNotEqual(sha256_hex(original), sha256_hex({"amount": 2000, "currency": "USD"}))

    def test_nested_mutation_changes_digest(self) -> None:
        original = {"outer": {"inner": {"approved": True}}}
        mutated = {"outer": {"inner": {"approved": False}}}

        self.assertNotEqual(sha256_hex(original), sha256_hex(mutated))

    def test_json_types_are_not_collapsed(self) -> None:
        self.assertNotEqual(canonicalize_bytes(True), canonicalize_bytes(1))
        self.assertNotEqual(canonicalize_bytes(False), canonicalize_bytes(0))
        self.assertNotEqual(canonicalize_bytes({"x": None}), canonicalize_bytes({}))
        self.assertNotEqual(canonicalize_bytes(["x"]), canonicalize_bytes("x"))
        self.assertNotEqual(canonicalize_bytes(1), canonicalize_bytes("1"))

    def test_floats_and_non_string_keys_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            canonicalize_bytes({"amount": 1.5})
        with self.assertRaises(TypeError):
            canonicalize_bytes({1: "not-json"})

    def test_duplicate_keys_are_rejected_at_parse_layer(self) -> None:
        with self.assertRaises(DuplicateJSONKeyError):
            loads_no_duplicate_keys('{"amount":1000,"amount":2000}')

    def test_unicode_profile_is_stable_and_does_not_normalize(self) -> None:
        nfc = "é"
        nfd = "e\u0301"

        self.assertEqual('"é"', canonicalize_json(nfc))
        self.assertEqual('"é"', canonicalize_json(nfd))
        self.assertNotEqual(sha256_hex(nfc), sha256_hex(nfd))

    def test_pathological_nesting_is_rejected_safely(self) -> None:
        with self.assertRaises(JSONNestingDepthError):
            canonicalize_bytes({"deep": _deep_value()})

        raw = "[" * 2000 + "0" + "]" * 2000
        with self.assertRaises(JSONNestingDepthError):
            loads_no_duplicate_keys(raw, max_bytes=len(raw) + 1)

    def test_oversized_inputs_are_rejected_safely(self) -> None:
        raw = '{"payload":"' + ("a" * DEFAULT_MAX_JSON_BYTES) + '"}'
        with self.assertRaises(JSONInputTooLargeError):
            loads_no_duplicate_keys(raw)

        with self.assertRaises(JSONInputTooLargeError):
            canonicalize_bytes({"payload": "a" * DEFAULT_MAX_CANONICAL_OUTPUT_BYTES})


if __name__ == "__main__":
    unittest.main()
