"""Published schemas must accept exactly the canonicalization labels the verifier accepts.

New artefacts are minted with ``ACTENON-JCS-STRICT-1``; historical artefacts
carry the legacy ``RFC8785-JCS`` label and must keep validating. A schema that
pins only one of them rejects real artefacts (every freshly minted PCCB failed
``pccb.v1.json``); a schema that allows more than the verifier accepts would
bless artefacts the verifier refuses.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from actenon.proof.canonical import (
    ACCEPTED_CANONICALIZATION_PROFILES,
    CANONICALIZATION_PROFILE,
)

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"


def _canonicalization_constraints(node, path="$"):
    """Yield (json_path, schema) for every property named ``canonicalization``."""

    if isinstance(node, dict):
        for key, value in node.items():
            if (
                key == "properties"
                and isinstance(value, dict)
                and "canonicalization" in value
            ):
                yield f"{path}.properties.canonicalization", value["canonicalization"]
            yield from _canonicalization_constraints(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _canonicalization_constraints(value, f"{path}[{index}]")


def _allowed_values(constraint: dict) -> set[str]:
    if "const" in constraint:
        return {constraint["const"]}
    return set(constraint.get("enum", ()))


class SchemaCanonicalizationLabelTests(unittest.TestCase):
    def test_every_schema_constraint_matches_the_verifier(self) -> None:
        found = 0
        for schema_file in sorted(SCHEMAS.glob("*.json")):
            schema = json.loads(schema_file.read_text(encoding="utf-8"))
            for json_path, constraint in _canonicalization_constraints(schema):
                found += 1
                with self.subTest(schema=schema_file.name, path=json_path):
                    self.assertEqual(
                        set(ACCEPTED_CANONICALIZATION_PROFILES),
                        _allowed_values(constraint),
                    )
        self.assertGreater(
            found, 0, "no canonicalization constraints found; the walker is broken"
        )

    def test_the_label_new_artefacts_are_minted_with_is_accepted(self) -> None:
        self.assertIn(CANONICALIZATION_PROFILE, ACCEPTED_CANONICALIZATION_PROFILES)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
