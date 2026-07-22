from __future__ import annotations

import warnings
from datetime import datetime, timezone

from actenon.gate import GateOutcome
from actenon.models import Refusal


def _refusal(**overrides: object) -> Refusal:
    values: dict[str, object] = {
        "refusal_id": "rfsl_reason_code_001",
        "category": "proof",
        "reason_code": "ACTION_HASH_MISMATCH",
        "message": "The proof is not bound to the submitted action.",
        "retryable": False,
        "refused_at": datetime(2026, 6, 6, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return Refusal(**values)  # type: ignore[arg-type]


def test_gate_outcome_reason_code_matches_refusal_artifact_key() -> None:
    refusal = _refusal()
    outcome = GateOutcome(receipt=None, refusal=refusal)
    artifact = refusal.to_dict()

    assert outcome.reason_code == artifact["reason_code"]
    assert "refusal_code" not in artifact


def test_legacy_refusal_code_alias_is_accepted_for_one_release() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        refusal = Refusal(
            refusal_id="rfsl_legacy_001",
            category="proof",
            refusal_code="AUDIENCE_MISMATCH",
            message="The proof audience does not match.",
            retryable=False,
            refused_at=datetime(2026, 6, 6, tzinfo=timezone.utc),
        )
        assert refusal.refusal_code == "AUDIENCE_MISMATCH"

    assert refusal.reason_code == "AUDIENCE_MISMATCH"
    assert len(caught) == 2
    assert all(item.category is DeprecationWarning for item in caught)


def test_legacy_refusal_json_is_read_but_reemitted_with_reason_code() -> None:
    legacy = _refusal().to_dict()
    legacy["refusal_code"] = legacy.pop("reason_code")

    refusal = Refusal.from_dict(legacy)

    assert refusal.reason_code == "ACTION_HASH_MISMATCH"
    assert refusal.to_dict()["reason_code"] == "ACTION_HASH_MISMATCH"
