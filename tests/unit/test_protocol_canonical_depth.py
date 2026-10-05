from __future__ import annotations

import json
from pathlib import Path

import pytest

from actenon.proof.canonical import canonicalize_bytes
from actenon_protocol.canonicalisation import canonicalize_bytes as reference


def test_frozen_protocol_invalid_depth_is_refused():
    path = Path(__file__).resolve().parents[2] / "fixtures/protocol_canonicalisation/deeply_nested_exceeds_limit.json"
    value = json.loads(json.loads(path.read_text())["input_json"])
    with pytest.raises(ValueError):
        reference(value)
    with pytest.raises(ValueError):
        canonicalize_bytes(value)


@pytest.mark.parametrize("depth", [0, 31, 32, 33, 127])
def test_protocol_depth_boundary(depth):
    value = "leaf"
    for _ in range(depth):
        value = {"nested": value}
    if depth <= 32:
        assert canonicalize_bytes(value) == reference(value)
    else:
        with pytest.raises(ValueError):
            canonicalize_bytes(value)
