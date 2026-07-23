from __future__ import annotations

import argparse
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from actenon.api import ActionIntentIntakeService, build_refund_action_intent_payload
from actenon.core import ProtectedExecutionKernel
from actenon.escrow import build_sqlite_capability_escrow
from actenon.local_runtime import build_local_runtime_storage, resolve_local_runtime_paths
from actenon.models import AudienceRef, DynamicContextInput, PartyRef, PolicyDecision
from actenon.models.contracts import format_timestamp, parse_timestamp
from actenon.policy import build_refund_policy_engine
from actenon.proof import PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.receipts import JsonArtifactOutcomeWriter, JsonArtifactReceiptStore, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.verifier import LocalAdmissionProtectedEndpoint, PythonProtectedEndpoint, ProtectedEndpointMiddleware

from examples.refund_guard_local.protected_endpoint import LocalProtectedRefundEndpoint


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9898
REFUND_AUDIENCE = AudienceRef(type="service", id="local-refund-endpoint")
REFUND_CAPABILITIES = ("refund.execute",)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class RefundGuardServerStartupInfo:
    base_url: str
    health_url: str
    refunds_url: str
    local_admission_url: str
    runtime_root: str
    state_path: str
    outcomes_root: str
    replay_store_path: str
    escrow_store_path: str

    def to_dict(self) -> dict[str, str]:
        return {
            "base_url": self.base_url,
            "health_url": self.health_url,
            "refunds_url": self.refunds_url,
            "local_admission_url": self.local_admission_url,
            "runtime_root": self.runtime_root,
            "state_path": self.state_path,
            "outcomes_root": self.outcomes_root,
            "replay_store_path": self.replay_store_path,
            "escrow_store_path": self.escrow_store_path,
        }


class ManagedRefundGuardServer:
    def __init__(self, *, server: ThreadingHTTPServer, thread: threading.Thread, startup_info: RefundGuardServerStartupInfo) -> None:
        self.server = server
        self.thread = thread
        self.startup_info = startup_info

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class RefundGuardService:
    def __init__(self, runtime_dir: str | Path | None = None) -> None:
        self.runtime_paths = resolve_local_runtime_paths(runtime_dir)
        self.runtime_storage = build_local_runtime_storage(runtime_dir)
        self.signer = build_local_proof_signer()
        self.receipt_factory = ReceiptFactory()
        self.refusal_factory = RefusalFactory()
        self.outcome_writer = JsonArtifactOutcomeWriter(self.runtime_storage.outcomes_root)
        self.escrow = build_sqlite_capability_escrow(self.runtime_storage.capability_escrow_db_path)
        self.replay_store = SqliteReplayStore(self.runtime_storage.replay_db_path)
        self.state_path = (
            self.runtime_paths.runtime_artifacts_root / "protected_endpoints" / "refund_guard_local" / "state" / "protected_endpoint_state.json"
        )
        self.endpoint = LocalProtectedRefundEndpoint(self.state_path)
        self.executor = PythonProtectedEndpoint(
            signer=self.signer,
            escrow=self.escrow,
            replay_store=self.replay_store,
            outcome_writer=self.outcome_writer,
            receipt_factory=self.receipt_factory,
            refusal_factory=self.refusal_factory,
        )
        self.kernel = ProtectedExecutionKernel(
            intake=ActionIntentIntakeService(),
            policy_engine=build_refund_policy_engine(receipt_store=JsonArtifactReceiptStore(self.runtime_storage.outcomes_root)),
            pccb_minter=PCCBMinter(
                signer=self.signer,
                issuer=PartyRef(type="service", id="local_refund_guard", display_name="Local Refund Guard"),
            ),
            escrow=self.escrow,
            middleware=ProtectedEndpointMiddleware(
                proof_verifier=PCCBVerifier(self.signer),
                escrow=self.escrow,
                receipt_factory=self.receipt_factory,
                refusal_factory=self.refusal_factory,
                outcome_writer=self.outcome_writer,
                replay_protector=ReplayProtector(self.replay_store),
            ),
            receipt_factory=self.receipt_factory,
            refusal_factory=self.refusal_factory,
            outcome_writer=self.outcome_writer,
        )
        self.local_admission = LocalAdmissionProtectedEndpoint(
            kernel=self.kernel,
            normalize_action_intent=self._normalize_local_admission_request,
            build_admission_context=self._build_local_admission_context,
        )

    def health_payload(self, *, base_url: str) -> dict[str, Any]:
        return {
            "ok": True,
            "audience": f"{REFUND_AUDIENCE.type}:{REFUND_AUDIENCE.id}",
            "capabilities": list(REFUND_CAPABILITIES),
            "health_url": f"{base_url}/healthz",
            "refunds_url": f"{base_url}/refunds",
            "local_admission_url": f"{base_url}/refunds/local-admission",
            "runtime_root": str(self.runtime_paths.root),
            "state_path": str(self.state_path),
            "outcomes_root": str(self.runtime_storage.outcomes_root),
            "replay_store_path": str(self.runtime_storage.replay_db_path),
            "escrow_store_path": str(self.runtime_storage.capability_escrow_db_path),
        }

    def _decision_payload(self, decision: PolicyDecision | None) -> dict[str, Any] | None:
        if decision is None:
            return None
        return {
            "outcome": decision.outcome,
            "summary": decision.summary,
            "reason_codes": list(decision.reason_codes),
            "required_evidence": list(decision.required_evidence),
            "approver_types": list(decision.approver_types),
            "rule_evaluations": [
                {
                    "rule_id": item.rule_id,
                    "outcome": item.outcome,
                    "reason_code": item.reason_code,
                    "summary": item.summary,
                    "details": item.details,
                    "required_evidence": list(item.required_evidence),
                    "approver_types": list(item.approver_types),
                }
                for item in decision.rule_evaluations
            ],
        }

    def _load_payment_facts(self, payment_id: str) -> dict[str, Any]:
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        payment = state["payments"].get(payment_id)
        if payment is None:
            raise ValueError(f"unknown payment resource: {payment_id}")
        return {
            "payment_id": payment_id,
            "payment_currency": payment["currency"],
            "remaining_refundable_minor": int(payment["remaining_refundable_minor"]),
        }

    def _normalize_local_admission_request(
        self,
        raw_request: Mapping[str, Any],
        *,
        request_id: str,
        now: datetime,
    ) -> Mapping[str, Any]:
        payment_id = raw_request.get("payment_id")
        amount_minor = raw_request.get("amount_minor")
        currency = raw_request.get("currency")
        requester_id = raw_request.get("requester_id", "framework_agent")
        tenant_id = raw_request.get("tenant_id", "tenant_demo")
        if not isinstance(payment_id, str) or not payment_id:
            raise ValueError("payment_id is required for proof-absent local admission.")
        if not isinstance(amount_minor, int):
            raise ValueError("amount_minor must be an integer for proof-absent local admission.")
        if not isinstance(currency, str) or not currency:
            raise ValueError("currency is required for proof-absent local admission.")
        if not isinstance(requester_id, str) or not requester_id:
            raise ValueError("requester_id must be a non-empty string for proof-absent local admission.")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("tenant_id must be a non-empty string for proof-absent local admission.")
        metadata = dict(raw_request.get("metadata", {})) if isinstance(raw_request.get("metadata"), Mapping) else {}
        metadata["admission_mode"] = "proof-absent-local-admission"
        return build_refund_action_intent_payload(
            intent_id=f"intent_local_admission_{request_id}",
            tenant_id=tenant_id,
            requester_id=requester_id,
            payment_id=payment_id,
            amount_minor=amount_minor,
            currency=currency.upper(),
            issued_at=now,
            justification=raw_request.get("justification") if isinstance(raw_request.get("justification"), str) else None,
            metadata=metadata,
            context={"source": "refund_guard_local", "admission_mode": "proof-absent-local-admission"},
        )

    def _build_local_admission_context(
        self,
        raw_request: Mapping[str, Any],
        *,
        intent_payload: Mapping[str, Any],
        request_id: str,
        now: datetime,
    ) -> DynamicContextInput:
        payment_id = intent_payload["target"]["resource_id"]
        payment_facts = self._load_payment_facts(payment_id)
        risk_level = raw_request.get("risk_level", "normal")
        if not isinstance(risk_level, str) or not risk_level:
            raise ValueError("risk_level must be a non-empty string when provided.")
        return DynamicContextInput(
            request_id=request_id,
            audience=REFUND_AUDIENCE,
            scope_capabilities=REFUND_CAPABILITIES,
            now=now,
            facts={**payment_facts, "risk_level": risk_level},
            parameter_constraints={
                "exact_amount_minor": intent_payload["action"]["parameters"]["amount_minor"],
                "exact_currency": intent_payload["action"]["parameters"]["currency"],
                "target_resource_id": payment_id,
            },
            resource_selectors=({"resource_id": payment_id},),
            required_evidence_types=("external_id",),
            approver_types=("finance-operator",),
        )

    def _write_local_admission_artifacts(
        self,
        *,
        request_id: str,
        normalized_intent_payload: Mapping[str, Any],
        context: DynamicContextInput,
        decision: PolicyDecision | None,
        admission_receipt: Mapping[str, Any] | None,
        execution_receipt: Mapping[str, Any] | None,
        refusal: Mapping[str, Any] | None,
        pccb: Mapping[str, Any] | None,
    ) -> dict[str, str | None]:
        request_dir = (
            self.runtime_paths.runtime_artifacts_root
            / "protected_endpoints"
            / "refund_guard_local"
            / "admissions"
            / request_id
        )
        request_dir.mkdir(parents=True, exist_ok=True)
        (request_dir / "action_intent.json").write_text(json.dumps(normalized_intent_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (request_dir / "context.json").write_text(
            json.dumps(
                {
                    "request_id": context.request_id,
                    "audience": context.audience.to_dict(),
                    "scope_capabilities": list(context.scope_capabilities),
                    "now": format_timestamp(context.now),
                    "facts": context.facts,
                    "parameter_constraints": context.parameter_constraints,
                    "resource_selectors": list(context.resource_selectors),
                    "required_evidence_types": list(context.required_evidence_types),
                    "approver_types": list(context.approver_types),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        if pccb is not None:
            (request_dir / "pccb.json").write_text(json.dumps(pccb, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if admission_receipt is not None:
            (request_dir / "admission_receipt.json").write_text(json.dumps(admission_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if execution_receipt is not None:
            (request_dir / "execution_receipt.json").write_text(json.dumps(execution_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if refusal is not None:
            (request_dir / "refusal.json").write_text(json.dumps(refusal, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary_payload = {
            "mode": "proof-absent-local-admission",
            "request_id": request_id,
            "decision": self._decision_payload(decision),
            "pccb_id": pccb["pccb_id"] if isinstance(pccb, Mapping) and isinstance(pccb.get("pccb_id"), str) else None,
            "admission_receipt_id": admission_receipt["receipt_id"] if isinstance(admission_receipt, Mapping) and isinstance(admission_receipt.get("receipt_id"), str) else None,
            "execution_receipt_id": execution_receipt["receipt_id"] if isinstance(execution_receipt, Mapping) and isinstance(execution_receipt.get("receipt_id"), str) else None,
            "reason_code": (
                refusal.get("reason_code") or refusal.get("refusal_code")
                if isinstance(refusal, Mapping)
                else None
            ),
        }
        (request_dir / "summary.json").write_text(json.dumps(summary_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {
            "request_dir": str(request_dir),
            "action_intent": str(request_dir / "action_intent.json"),
            "context": str(request_dir / "context.json"),
            "pccb": str(request_dir / "pccb.json") if pccb is not None else None,
            "admission_receipt": str(request_dir / "admission_receipt.json") if admission_receipt is not None else None,
            "execution_receipt": str(request_dir / "execution_receipt.json") if execution_receipt is not None else None,
            "refusal": str(request_dir / "refusal.json") if refusal is not None else None,
            "summary": str(request_dir / "summary.json"),
        }

    def execute(self, raw_request: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        raw_intent = raw_request.get("action_intent")
        raw_pccb = raw_request.get("pccb")
        if not isinstance(raw_intent, Mapping):
            raise ValueError("action_intent must be a JSON object.")
        if not isinstance(raw_pccb, Mapping):
            raise ValueError("pccb must be a JSON object.")

        raw_context = raw_request.get("context", {})
        if raw_context is None:
            raw_context = {}
        if not isinstance(raw_context, Mapping):
            raise ValueError("context must be a JSON object when provided.")

        raw_now = raw_context.get("now")
        now = _utc_now() if raw_now is None else parse_timestamp(raw_now, "context.now")
        raw_request_id = raw_context.get("request_id")
        request_id = (
            raw_request_id
            if isinstance(raw_request_id, str) and raw_request_id.strip()
            else f"req_refund_guard_{uuid4().hex[:12]}"
        )

        result = self.executor.execute_payloads(
            intent_payload=raw_intent,
            pccb_payload=raw_pccb,
            request_id=request_id,
            audience=REFUND_AUDIENCE,
            now=now,
            scope_capabilities=REFUND_CAPABILITIES,
            handler=self.endpoint.handle,
        )
        receipt_path = None
        refusal_path = None
        if result.receipt is not None:
            receipt_path = self.runtime_storage.outcomes_root / "receipts" / f"{result.receipt.receipt_id}.json"
        if result.refusal is not None:
            refusal_path = self.runtime_storage.outcomes_root / "refusals" / f"{result.refusal.refusal_id}.json"
        status = HTTPStatus.OK if result.refusal is None else HTTPStatus.FORBIDDEN
        return status, {
            "ok": result.refusal is None,
            "mode": "proof-present-verification",
            "request_id": request_id,
            "audience": f"{REFUND_AUDIENCE.type}:{REFUND_AUDIENCE.id}",
            "capabilities": list(REFUND_CAPABILITIES),
            "protected_response": result.payload,
            "receipt": result.receipt.to_dict() if result.receipt is not None else None,
            "refusal": result.refusal.to_dict() if result.refusal is not None else None,
            "artifacts": {
                "outcomes_root": str(self.runtime_storage.outcomes_root),
                "receipt": str(receipt_path) if receipt_path is not None else None,
                "refusal": str(refusal_path) if refusal_path is not None else None,
                "state_path": str(self.state_path),
            },
        }

    def admit_locally(self, raw_request: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        raw_request_id = raw_request.get("request_id")
        request_id = (
            raw_request_id
            if isinstance(raw_request_id, str) and raw_request_id.strip()
            else f"req_refund_local_admission_{uuid4().hex[:12]}"
        )
        raw_now = raw_request.get("now")
        now = _utc_now() if raw_now is None else parse_timestamp(raw_now, "now")
        normalized_intent_payload = dict(
            self._normalize_local_admission_request(
                raw_request,
                request_id=request_id,
                now=now,
            )
        )
        context = self._build_local_admission_context(
            raw_request,
            intent_payload=normalized_intent_payload,
            request_id=request_id,
            now=now,
        )
        outcome = self.local_admission.admit_and_execute(
            raw_request=raw_request,
            handler=self.endpoint.handle,
            request_id=request_id,
            now=now,
        )
        artifacts = self._write_local_admission_artifacts(
            request_id=request_id,
            normalized_intent_payload=normalized_intent_payload,
            context=context,
            decision=outcome.decision,
            admission_receipt=outcome.admission_receipt.to_dict() if outcome.admission_receipt is not None else None,
            execution_receipt=outcome.execution_receipt.to_dict() if outcome.execution_receipt is not None else None,
            refusal=outcome.refusal.to_dict() if outcome.refusal is not None else None,
            pccb=outcome.pccb.to_dict() if outcome.pccb is not None else None,
        )
        final_receipt = outcome.execution_receipt or outcome.admission_receipt
        status = HTTPStatus.OK if outcome.refusal is None else HTTPStatus.FORBIDDEN
        return status, {
            "ok": outcome.refusal is None,
            "mode": outcome.mode,
            "request_id": request_id,
            "audience": f"{REFUND_AUDIENCE.type}:{REFUND_AUDIENCE.id}",
            "capabilities": list(REFUND_CAPABILITIES),
            "adoption_stage": "edge-only-admission",
            "normalized_action_intent": normalized_intent_payload,
            "decision": self._decision_payload(outcome.decision),
            "escrow_id": outcome.escrow_id,
            "pccb": outcome.pccb.to_dict() if outcome.pccb is not None else None,
            "admission_receipt": outcome.admission_receipt.to_dict() if outcome.admission_receipt is not None else None,
            "receipt": final_receipt.to_dict() if final_receipt is not None else None,
            "execution_receipt": outcome.execution_receipt.to_dict() if outcome.execution_receipt is not None else None,
            "refusal": outcome.refusal.to_dict() if outcome.refusal is not None else None,
            "protected_response": outcome.protected_response,
            "artifacts": {
                **artifacts,
                "outcomes_root": str(self.runtime_storage.outcomes_root),
                "state_path": str(self.state_path),
            },
        }


def _build_handler(service: RefundGuardService) -> type[BaseHTTPRequestHandler]:
    class RefundGuardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/healthz":
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "not found"})
                return
            self._send_json(HTTPStatus.OK, service.health_payload(base_url=self._base_url()))

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in {"/refunds", "/refunds/local-admission"}:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                raw = self.rfile.read(length)
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "ok": False,
                        "reason_code": "SCHEMA_INVALID",
                        "summary": "Request body must be valid JSON.",
                    },
                )
                return
            if not isinstance(payload, Mapping):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "ok": False,
                        "reason_code": "SCHEMA_INVALID",
                        "summary": "Request body must be a JSON object.",
                    },
                )
                return
            try:
                if self.path == "/refunds":
                    status, body = service.execute(payload)
                else:
                    status, body = service.admit_locally(payload)
            except ValueError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "ok": False,
                        "reason_code": "SCHEMA_INVALID",
                        "summary": str(exc),
                    },
                )
                return
            self._send_json(status, body)

        def _base_url(self) -> str:
            return f"http://{self.server.server_address[0]}:{self.server.server_address[1]}"

        def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return RefundGuardHandler


def start_refund_guard_server(
    *,
    runtime_dir: str | Path | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> ManagedRefundGuardServer:
    service = RefundGuardService(runtime_dir=runtime_dir)
    server = ThreadingHTTPServer((host, port), _build_handler(service))
    base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
    startup_info = RefundGuardServerStartupInfo(
        base_url=base_url,
        health_url=f"{base_url}/healthz",
        refunds_url=f"{base_url}/refunds",
        local_admission_url=f"{base_url}/refunds/local-admission",
        runtime_root=str(service.runtime_paths.root),
        state_path=str(service.state_path),
        outcomes_root=str(service.runtime_storage.outcomes_root),
        replay_store_path=str(service.runtime_storage.replay_db_path),
        escrow_store_path=str(service.runtime_storage.capability_escrow_db_path),
    )
    thread = threading.Thread(target=server.serve_forever, name="refund-guard-local-server", daemon=True)
    thread.start()
    return ManagedRefundGuardServer(server=server, thread=thread, startup_info=startup_info)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the tiny local protected refund endpoint example.")
    parser.add_argument("--runtime-dir", default=None, help="Local Actenon runtime root. Defaults to artifacts/local_runtime.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind.")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Port to bind.")
    args = parser.parse_args(argv)

    server = start_refund_guard_server(runtime_dir=args.runtime_dir, host=args.host, port=args.port)
    info = server.startup_info
    print("Local protected refund endpoint is running.")
    print(f"Endpoint URL: {info.refunds_url}")
    print(f"Local admission URL: {info.local_admission_url}")
    print(f"Health URL: {info.health_url}")
    print(f"Runtime root: {info.runtime_root}")
    print(f"Protected state: {info.state_path}")
    print(f"Outcome artifacts: {info.outcomes_root}")
    print(f"Replay store: {info.replay_store_path}")
    print(f"Escrow store: {info.escrow_store_path}")
    print("Next step:")
    print("  curl -s http://127.0.0.1:9898/refunds/local-admission -H 'Content-Type: application/json' -d '{\"payment_id\":\"payment_demo_001\",\"amount_minor\":1500,\"currency\":\"USD\",\"requester_id\":\"framework_agent\",\"risk_level\":\"normal\"}'")
    print("  curl -s http://127.0.0.1:8787/v1/intents ... > /tmp/actenon-issue.json")
    print("  python3 -m examples.refund_guard_local.call_endpoint --issue-response /tmp/actenon-issue.json")
    try:
        server.thread.join()
    except KeyboardInterrupt:
        print("\nStopping local protected refund endpoint.")
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
