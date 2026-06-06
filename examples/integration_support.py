from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from actenon import ActenonGate
from actenon.core import ContractValidationError
from actenon.demo.portable_local_proof import FIXED_BASE_TIME, run_portable_local_proof_demo
from actenon.models import Receipt, Refusal
from actenon.receipts import (
    CompositeOutcomeWriter,
    InMemoryOutcomeWriter,
    JsonArtifactOutcomeWriter,
    ReceiptFactory,
    RefusalFactory,
)
from actenon.replay import ReplayProtector, SqliteReplayStore
from examples.hello_world_protected_resource_python.protected_resource import HelloWorldProtectedResource


DEFAULT_AUDIENCE_ID = "portable-hello-world-endpoint"


@dataclass(frozen=True)
class ProtectedHelloOutcome:
    ok: bool
    protected_response: dict[str, Any] | None
    receipt: Receipt | None
    refusal: Refusal | None
    fixture_root: Path
    outcome_root: Path

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "fixture_root": str(self.fixture_root),
            "outcome_root": str(self.outcome_root),
        }
        if self.protected_response is not None:
            payload["protected_response"] = self.protected_response
        if self.receipt is not None:
            payload["receipt"] = self.receipt.to_dict()
        if self.refusal is not None:
            payload["refusal"] = self.refusal.to_dict()
        return payload


def build_request_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


def ensure_portable_local_proof(example_root: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    fixture_root = example_root / "artifacts" / "portable_local_proof"
    action_intent_path = fixture_root / "action_intent.json"
    pccb_path = fixture_root / "pccb.json"
    if not action_intent_path.exists() or not pccb_path.exists():
        run_portable_local_proof_demo(fixture_root)
    return (
        json.loads(action_intent_path.read_text(encoding="utf-8")),
        json.loads(pccb_path.read_text(encoding="utf-8")),
        fixture_root,
    )


def execute_protected_hello(
    *,
    example_root: Path,
    request_id: str,
    intent_payload: Mapping[str, Any] | None = None,
    pccb_payload: Mapping[str, Any] | None = None,
    audience_id: str = DEFAULT_AUDIENCE_ID,
) -> ProtectedHelloOutcome:
    if intent_payload is None or pccb_payload is None:
        default_intent, default_pccb, fixture_root = ensure_portable_local_proof(example_root)
        intent_payload = intent_payload or default_intent
        pccb_payload = pccb_payload or default_pccb
    else:
        fixture_root = example_root / "artifacts" / "portable_local_proof"

    outcome_root = example_root / "artifacts" / "outcomes"
    memory_writer = InMemoryOutcomeWriter()
    artifact_writer = JsonArtifactOutcomeWriter(outcome_root)
    writer = CompositeOutcomeWriter(memory_writer, artifact_writer)
    receipt_factory = ReceiptFactory(receipt_id_factory=lambda: f"rcpt_{request_id}")
    refusal_factory = RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}")
    gate = ActenonGate.local_dev(
        audience=f"service:{audience_id}",
        replay_protector=ReplayProtector(SqliteReplayStore(example_root / "state" / "replay.sqlite3")),
        receipt_factory=receipt_factory,
        refusal_factory=refusal_factory,
        outcome_writer=writer,
        clock=lambda: FIXED_BASE_TIME,
        request_id_factory=lambda: request_id,
    )

    outcome = gate.protect(
        dict(intent_payload),
        dict(pccb_payload),
        lambda request, _credential: {
            **HelloWorldProtectedResource().handle(request),
            "external_reference": f"hello_local_{request_id}",
        },
    )
    return ProtectedHelloOutcome(
        ok=outcome.ok,
        protected_response=outcome.payload,
        receipt=outcome.receipt,
        refusal=outcome.refusal,
        fixture_root=fixture_root,
        outcome_root=outcome_root,
    )


def parse_optional_json_mapping(raw: str | None, *, field_name: str) -> dict[str, Any] | None:
    if raw is None or not raw.strip():
        return None
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ContractValidationError(f"{field_name} must decode to a JSON object.")
    return parsed
