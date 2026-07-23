from __future__ import annotations

import json
from pathlib import Path

from actenon.proof import PUBLIC_PROOF_REFUSAL_MESSAGES


VECTOR_ROOT = (
    Path(__file__).resolve().parents[2]
    / "actenon"
    / "conformance"
    / "vectors"
    / "verifier_sdk_v1"
)


def test_public_proof_messages_are_generic_and_match_shared_vectors() -> None:
    manifest = json.loads((VECTOR_ROOT / "cases.json").read_text(encoding="utf-8"))
    refused = [
        case["expected"]
        for case in manifest["cases"]
        if case["expected"]["outcome"] == "refused"
    ]

    for expected in refused:
        message = PUBLIC_PROOF_REFUSAL_MESSAGES[expected["reason_code"]]
        assert message == expected["message"]
        assert len(message) <= 96
        lowered = message.lower()
        for forbidden in (
            "secret",
            "credential",
            "signature value",
            "expected hash",
            "supplied hash",
            "traceback",
            "stack trace",
            "exception:",
            "key id",
            "tenant id",
            "subject id",
            "target id",
        ):
            assert forbidden not in lowered


def test_shared_refusal_vectors_do_not_embed_sensitive_fixture_values() -> None:
    manifest = json.loads((VECTOR_ROOT / "cases.json").read_text(encoding="utf-8"))
    fixture_values = (
        "tenant_portable_demo",
        "portable_demo_actor",
        "hello_resource_demo_001",
        "local-proof-v1",
        "0c86e20c2de67ffdd210064fc258f59e525642c4d73c1bc06a60badcb610009b",
    )

    for case in manifest["cases"]:
        message = case["expected"].get("message", "")
        assert all(value not in message for value in fixture_values)
