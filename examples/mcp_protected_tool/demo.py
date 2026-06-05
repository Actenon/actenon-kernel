"""Minimal local MCP protected-tool adoption path.

This file intentionally avoids a live MCP dependency. It models the MCP tool
handler boundary locally so developers can copy the Actenon placement first:
tool call -> proof gate -> simulated side effect -> Receipt/Refusal.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from actenon.core import ProofVerificationError
from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.execution import ProtectedExecutor
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    ExecutionResult,
    PartyRef,
    PolicyDecision,
    ProtectedExecutionRequest,
    TargetRef,
    TenantRef,
)
from actenon.proof import HmacSha256Signer, PCCBMinter, PCCBVerifier
from actenon.receipts import CompositeOutcomeWriter, InMemoryOutcomeWriter, JsonArtifactOutcomeWriter, ReceiptFactory, RefusalFactory


DEMO_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
DEMO_SIGNER = HmacSha256Signer(secret=b"actenon-mcp-protected-tool-demo-secret", key_id="mcp-protected-tool-demo-key")
DEMO_AUDIENCE = AudienceRef(type="service", id="mcp-filesystem-tool")
DEMO_TOOL = "filesystem.delete"
DEMO_CAPABILITY = "filesystem.delete"
DEFAULT_ARTIFACT_ROOT = Path("artifacts/mcp_protected_tool")


@dataclass(frozen=True)
class DemoOutcome:
    scenario: str
    execution: ExecutionResult
    artifact_root: Path
    handler_called: bool

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "scenario": self.scenario,
            "tool_name": DEMO_TOOL,
            "ok": self.execution.refusal is None,
            "handler_called": self.handler_called,
            "side_effect_executed": self.execution.refusal is None,
            "artifact_root": str(self.artifact_root),
            "flow": [
                "agent",
                "MCP tool call",
                "Actenon proof gate",
                "tool executes/refuses",
                "Receipt/Refusal emitted",
            ],
        }
        if self.execution.payload is not None:
            payload["protected_response"] = self.execution.payload
        if self.execution.receipt is not None:
            payload["receipt"] = self.execution.receipt.to_dict()
            payload["receipt_path"] = str(
                self.artifact_root / "outcomes" / "receipts" / f"{self.execution.receipt.receipt_id}.json"
            )
        if self.execution.refusal is not None:
            payload["refusal"] = self.execution.refusal.to_dict()
            payload["refusal_path"] = str(
                self.artifact_root / "outcomes" / "refusals" / f"{self.execution.refusal.refusal_id}.json"
            )
        return payload


def build_intent() -> ActionIntent:
    return ActionIntent(
        intent_id="intent_mcp_delete_stale_cache",
        issued_at=DEMO_NOW,
        expires_at=DEMO_NOW + timedelta(minutes=5),
        tenant=TenantRef(tenant_id="tenant_mcp_quickstart"),
        requester=PartyRef(type="agent", id="local-mcp-agent"),
        action=ActionSpec(
            name=DEMO_TOOL,
            capability=DEMO_CAPABILITY,
            parameters={
                "path": "/tmp/actenon-demo/stale-cache",
                "recursive": True,
                "environment": "sandbox",
            },
        ),
        target=TargetRef(
            resource_type="filesystem_path",
            resource_id="sandbox:/tmp/actenon-demo/stale-cache",
            selectors={"environment": "sandbox"},
        ),
        justification="Delete a stale sandbox cache directory in the MCP quickstart.",
        context={"environment": "sandbox"},
    )


def build_context(intent: ActionIntent, *, request_id: str) -> DynamicContextInput:
    return DynamicContextInput(
        request_id=request_id,
        audience=DEMO_AUDIENCE,
        scope_capabilities=(intent.action.capability,),
        now=DEMO_NOW,
        facts={"mcp_tool": intent.action.name, "environment": "sandbox"},
        parameter_constraints=dict(intent.action.parameters),
        resource_selectors=(intent.target.selectors,),
    )


def build_pccb(intent: ActionIntent, context: DynamicContextInput) -> Any:
    return PCCBMinter(
        signer=DEMO_SIGNER,
        issuer=PartyRef(type="service", id="actenon-mcp-quickstart"),
        pccb_id_factory=lambda: "pccb_mcp_quickstart_allow",
        nonce_factory=lambda: "nonce-mcp-quickstart-allow",
    ).mint(
        intent,
        PolicyDecision(
            outcome="allow",
            summary="Local demo proof minted for the MCP filesystem tool.",
            rule_evaluations=(),
            reason_codes=("MCP_QUICKSTART_ALLOWED",),
        ),
        context,
    )


def build_executor(*, artifact_root: Path, request_id: str) -> ProtectedExecutor:
    writer = CompositeOutcomeWriter(
        InMemoryOutcomeWriter(),
        JsonArtifactOutcomeWriter(artifact_root / "outcomes"),
    )
    return ProtectedExecutor(
        proof_verifier=PCCBVerifier(DEMO_SIGNER),
        credential_broker=InMemoryCredentialBroker(
            ttl=timedelta(seconds=60),
            credential_id_factory=lambda: f"cred_{request_id}",
            secret_reference_prefix="memory://mcp-quickstart-credential",
        ),
        receipt_factory=ReceiptFactory(receipt_id_factory=lambda: f"rcpt_{request_id}"),
        refusal_factory=RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}"),
        outcome_writer=writer,
    )


def simulated_filesystem_delete(request: ProtectedExecutionRequest, credential: BrokeredCredential) -> dict[str, Any]:
    return {
        "external_reference": f"simulated-delete:{request.intent.target.resource_id}",
        "mcp_tool": DEMO_TOOL,
        "simulated_side_effect": {
            "operation": "delete",
            "target": request.intent.target.resource_id,
            "state": "completed",
            "real_filesystem_touched": False,
        },
        "credential_reference": credential.secret_reference,
        "credential_material_exposed": False,
    }


def _refuse_missing_proof(*, intent: ActionIntent, context: DynamicContextInput, artifact_root: Path, request_id: str) -> ExecutionResult:
    writer = CompositeOutcomeWriter(
        InMemoryOutcomeWriter(),
        JsonArtifactOutcomeWriter(artifact_root / "outcomes"),
    )
    refusal = RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}").create_from_exception(
        ProofVerificationError("PCCB_REQUIRED", "The MCP tool call did not include proof."),
        occurred_at=context.now,
        intent=intent,
        context=context,
    )
    receipt = ReceiptFactory(receipt_id_factory=lambda: f"rcpt_{request_id}").create_refused_receipt(intent, context, refusal)
    writer.write_refusal(refusal)
    writer.write_receipt(receipt)
    return ExecutionResult(receipt=receipt, refusal=refusal, payload=None)


def run_demo(*, scenario: str, artifact_root: Path = DEFAULT_ARTIFACT_ROOT) -> DemoOutcome:
    if scenario not in {"missing-proof", "allow"}:
        raise ValueError("scenario must be 'missing-proof' or 'allow'")
    request_id = f"mcp_quickstart_{scenario.replace('-', '_')}"
    intent = build_intent()
    context = build_context(intent, request_id=request_id)
    handler_called = False

    if scenario == "missing-proof":
        execution = _refuse_missing_proof(intent=intent, context=context, artifact_root=artifact_root, request_id=request_id)
        return DemoOutcome(scenario=scenario, execution=execution, artifact_root=artifact_root, handler_called=False)

    pccb = build_pccb(intent, context)
    request = ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)
    protected = build_executor(artifact_root=artifact_root, request_id=request_id)

    def handler(protected_request: ProtectedExecutionRequest, credential: BrokeredCredential) -> dict[str, Any]:
        nonlocal handler_called
        handler_called = True
        return simulated_filesystem_delete(protected_request, credential)

    execution = protected.execute(
        request,
        handler,
        policy_decision=PolicyDecision(
            outcome="allow",
            summary="Sandbox MCP filesystem delete is allowed.",
            rule_evaluations=(),
            reason_codes=("MCP_QUICKSTART_ALLOWED",),
        ),
    )
    return DemoOutcome(scenario=scenario, execution=execution, artifact_root=artifact_root, handler_called=handler_called)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m examples.mcp_protected_tool.demo",
        description="Run the minimal local MCP protected-tool example.",
    )
    parser.add_argument(
        "--scenario",
        choices=("missing-proof", "allow"),
        default="missing-proof",
        help="Run the refused missing-proof path or the allowed proof-bearing path.",
    )
    parser.add_argument(
        "--artifact-root",
        default=str(DEFAULT_ARTIFACT_ROOT),
        help="Directory for emitted Receipt/Refusal artifacts.",
    )
    parser.add_argument("--json", action="store_true", help="Emit structured JSON only.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    outcome = run_demo(scenario=args.scenario, artifact_root=Path(args.artifact_root))
    payload = outcome.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print("Actenon MCP protected-tool quickstart.")
    print("Flow: agent -> MCP tool call -> Actenon proof gate -> tool executes/refuses -> Receipt/Refusal emitted")
    print(f"Tool: {payload['tool_name']}")
    print(f"Scenario: {payload['scenario']}")
    print(f"Outcome: {'ALLOWED' if payload['ok'] else 'REFUSED'}")
    print(f"Handler called: {str(payload['handler_called']).lower()}")
    print(f"Side effect executed: {str(payload['side_effect_executed']).lower()}")
    if "refusal" in payload:
        print(f"Refusal code: {payload['refusal']['refusal_code']}")
        print(f"Refusal artifact: {payload['refusal_path']}")
    if "receipt" in payload:
        print(f"Receipt outcome: {payload['receipt']['outcome']}")
        print(f"Receipt artifact: {payload['receipt_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

