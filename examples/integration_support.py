from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from actenon.core import ContractValidationError, RefusalException
from actenon.demo.portable_local_proof import FIXED_BASE_TIME, run_portable_local_proof_demo
from actenon.models import AudienceRef, Receipt, Refusal
from actenon.proof import build_local_proof_signer
from actenon.receipts import (
    CompositeOutcomeWriter,
    InMemoryOutcomeWriter,
    JsonArtifactOutcomeWriter,
    ReceiptFactory,
    RefusalFactory,
)
from actenon.verifier import VerifierSDK
from examples.hello_world_protected_resource_python.protected_resource import HelloWorldProtectedResource


DEFAULT_AUDIENCE_ID = "portable-hello-world-endpoint"
DEFAULT_SCOPE_CAPABILITIES = ("protected_resource.read",)
DEFAULT_PARAMETER_CONSTRAINTS = {"exact_message": "portable hello world"}
DEFAULT_RESOURCE_SELECTORS = ({"resource_id": "hello_resource_demo_001"},)


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

    signer = build_local_proof_signer()
    sdk = VerifierSDK(signer)

    try:
        intent = sdk.parse_intent(intent_payload)
        pccb = sdk.parse_pccb(pccb_payload)
    except ValueError as exc:
        raise ContractValidationError(str(exc), details={"request_id": request_id}) from exc

    context = sdk.build_context(
        request_id=request_id,
        audience=AudienceRef(type="service", id=audience_id),
        now=FIXED_BASE_TIME,
        scope_capabilities=DEFAULT_SCOPE_CAPABILITIES,
        parameter_constraints=DEFAULT_PARAMETER_CONSTRAINTS,
        resource_selectors=DEFAULT_RESOURCE_SELECTORS,
    )

    outcome_root = example_root / "artifacts" / "outcomes"
    memory_writer = InMemoryOutcomeWriter()
    artifact_writer = JsonArtifactOutcomeWriter(outcome_root)
    writer = CompositeOutcomeWriter(memory_writer, artifact_writer)
    receipt_factory = ReceiptFactory(receipt_id_factory=lambda: f"rcpt_{request_id}")
    refusal_factory = RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}")

    try:
        verified = sdk.verify(intent=intent, pccb=pccb, context=context)
        protected_response = HelloWorldProtectedResource().handle(verified)
        protected_response = {
            **protected_response,
            "external_reference": f"hello_local_{request_id}",
        }
        receipt = receipt_factory.create_execution_receipt(
            intent=intent,
            context=context,
            pccb_id=pccb.pccb_id,
            escrow_id=pccb.escrow_id,
            payload=protected_response,
        )
        writer.write_receipt(receipt)
        return ProtectedHelloOutcome(
            ok=True,
            protected_response=protected_response,
            receipt=receipt,
            refusal=None,
            fixture_root=fixture_root,
            outcome_root=outcome_root,
        )
    except RefusalException as exc:
        refusal = refusal_factory.create_from_exception(
            exc,
            occurred_at=context.now,
            intent=intent,
            context=context,
            pccb_id=pccb.pccb_id,
            escrow_id=pccb.escrow_id,
        )
        receipt = receipt_factory.create_refused_receipt(intent, context, refusal)
        writer.write_refusal(refusal)
        writer.write_receipt(receipt)
        return ProtectedHelloOutcome(
            ok=False,
            protected_response=None,
            receipt=receipt,
            refusal=refusal,
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
