from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from actenon.core.redaction import SAFE_HANDLER_EXCEPTION_CODE, SAFE_HANDLER_EXCEPTION_MESSAGE
from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.execution import ProtectedExecutor
from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PartyRef,
    PCCB,
    PolicyDecision,
    ProtectedExecutionRequest,
    TargetRef,
    TenantRef,
)
from actenon.proof import PCCBMinter, PCCBVerifier, VerifierDisclosureMode
from actenon.proof.signers import HmacSha256Signer
from actenon.receipts import InMemoryOutcomeWriter
from actenon.replay import ReplayProtector, SqliteReplayStore, build_action_consumption_claim


class _RecordingBroker(InMemoryCredentialBroker):
    def __init__(self) -> None:
        super().__init__(ttl=timedelta(seconds=45), credential_id_factory=lambda: "cred_exec_001")
        self.acquire_calls = 0

    def acquire(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> BrokeredCredential:
        self.acquire_calls += 1
        return super().acquire(intent, pccb, context)


class _FailingBroker(_RecordingBroker):
    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def acquire(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> BrokeredCredential:
        self.acquire_calls += 1
        raise RuntimeError(self.message)


class _EscrowOrderingBroker(_RecordingBroker):
    def __init__(self, escrow: InMemoryCapabilityEscrow, escrow_id: str) -> None:
        super().__init__()
        self.escrow = escrow
        self.escrow_id = escrow_id
        self.escrow_was_consumed_before_acquire = False

    def acquire(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> BrokeredCredential:
        record = self.escrow.inspect(self.escrow_id)
        self.escrow_was_consumed_before_acquire = record is not None and record.state == "consumed"
        return super().acquire(intent, pccb, context)


class ProtectedExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.signer = HmacSha256Signer(secret=b"protected-executor-secret", key_id="executor-key")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _intent(self) -> ActionIntent:
        return ActionIntent(
            intent_id="intent_exec_001",
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=10),
            tenant=TenantRef(tenant_id="tenant_alpha"),
            requester=PartyRef(type="agent", id="agent_planner"),
            action=ActionSpec(
                name="volume.delete",
                capability="infrastructure.delete",
                parameters={"environment": "sandbox", "resource_id": "sandbox-volume-001"},
            ),
            target=TargetRef(resource_type="volume", resource_id="sandbox-volume-001"),
            justification="Remove disposable sandbox volume.",
        )

    def _context(self, *, audience_id: str = "infra-delete-protected-endpoint") -> DynamicContextInput:
        return DynamicContextInput(
            request_id="req_exec_001",
            audience=AudienceRef(type="service", id=audience_id),
            scope_capabilities=("infrastructure.delete",),
            now=self.now,
        )

    def _allow_decision(self) -> PolicyDecision:
        return PolicyDecision(
            outcome="allow",
            summary="Sandbox infrastructure delete is allowed.",
            rule_evaluations=(),
            reason_codes=("INFRA_DELETE_ALLOWED_SANDBOX",),
        )

    def _deny_decision(self) -> PolicyDecision:
        return PolicyDecision(
            outcome="deny",
            summary="Production destructive infrastructure delete is refused.",
            rule_evaluations=(),
            reason_codes=("INFRA_DELETE_PRODUCTION_DENIED",),
        )

    def _request(self, *, escrow_id: str | None = "esc_exec_001") -> ProtectedExecutionRequest:
        intent = self._intent()
        context = self._context()
        pccb = PCCBMinter(
            signer=self.signer,
            issuer=PartyRef(type="service", id="actenon-kernel"),
            pccb_id_factory=lambda: "pccb_exec_001",
            nonce_factory=lambda: "nonce-exec-001",
        ).mint(intent, self._allow_decision(), context, escrow_id=escrow_id)
        return ProtectedExecutionRequest(intent=intent, pccb=pccb, context=context)

    def _executor(
        self,
        *,
        broker: _RecordingBroker | None = None,
        escrow: InMemoryCapabilityEscrow | None = None,
        writer: InMemoryOutcomeWriter | None = None,
    ) -> ProtectedExecutor:
        return ProtectedExecutor(
            proof_verifier=PCCBVerifier(self.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
            credential_broker=broker or _RecordingBroker(),
            replay_protector=ReplayProtector(SqliteReplayStore(Path(self.tempdir.name) / "replay.sqlite3")),
            escrow=escrow,
            outcome_writer=writer or InMemoryOutcomeWriter(),
        )

    def _handler(self, request: ProtectedExecutionRequest, credential: BrokeredCredential) -> dict[str, Any]:
        if not isinstance(credential, BrokeredCredential):
            raise PermissionError("brokered credential required")
        return {
            "external_reference": f"delete:{request.intent.target.resource_id}",
            "resource_deleted": request.intent.target.resource_id,
            "credential_reference_seen": credential.secret_reference,
        }

    def test_agent_cannot_execute_without_protected_endpoint(self) -> None:
        def destructive_delete(credential: BrokeredCredential | None) -> dict[str, str]:
            if credential is None:
                raise PermissionError("agent has no production credential")
            return {"state": "deleted", "credential_id": credential.credential_id}

        with self.assertRaises(PermissionError):
            destructive_delete(None)

        request = self._request()
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )
        result = self._executor(escrow=escrow).execute(request, lambda _request, credential: destructive_delete(credential))

        self.assertIsNone(result.refusal)
        self.assertIsNotNone(result.receipt)
        assert result.receipt is not None
        self.assertEqual("executed", result.receipt.outcome)

    def test_broker_is_only_called_after_verification_and_escrow_succeed(self) -> None:
        request = self._request()
        broker = _RecordingBroker()
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )
        writer = InMemoryOutcomeWriter()

        result = self._executor(broker=broker, escrow=escrow, writer=writer).execute(request, self._handler)

        self.assertIsNone(result.refusal)
        self.assertEqual(1, broker.acquire_calls)
        self.assertEqual(1, len(broker.issued_credentials))
        self.assertEqual(1, len(broker.released_credentials))
        self.assertEqual(1, len(writer.receipts))
        receipt = writer.receipts[0].to_dict()
        self.assertEqual("memory://brokered-credential/cred_exec_001", receipt["details"]["brokered_credential"]["secret_reference"])
        self.assertNotIn("secret", receipt["details"]["brokered_credential"])
        self.assertNotIn("raw_secret", receipt["details"]["brokered_credential"])

    def test_broker_is_called_after_escrow_consumption(self) -> None:
        request = self._request()
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )
        broker = _EscrowOrderingBroker(escrow, "esc_exec_001")

        result = self._executor(broker=broker, escrow=escrow).execute(request, self._handler)

        self.assertIsNone(result.refusal)
        self.assertEqual(1, broker.acquire_calls)
        self.assertTrue(broker.escrow_was_consumed_before_acquire)

    def test_broker_is_not_called_when_proof_fails(self) -> None:
        request = self._request()
        wrong_context = self._context(audience_id="wrong-endpoint")
        bad_request = ProtectedExecutionRequest(intent=request.intent, pccb=request.pccb, context=wrong_context)
        broker = _RecordingBroker()
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )

        result = self._executor(broker=broker, escrow=escrow).execute(bad_request, self._handler)

        self.assertIsNotNone(result.refusal)
        assert result.refusal is not None
        self.assertEqual("AUDIENCE_MISMATCH", result.refusal.reason_code)
        self.assertEqual(0, broker.acquire_calls)
        self.assertEqual([], broker.issued_credentials)
        record = escrow.inspect("esc_exec_001")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("issued", record.state)

    def test_execution_helper_cannot_execute_without_valid_proof(self) -> None:
        request = self._request()
        missing_signature_pccb = replace(
            request.pccb,
            signature=replace(request.pccb.signature, key_id="wrong-key"),
        )
        missing_proof_request = ProtectedExecutionRequest(
            intent=request.intent,
            pccb=missing_signature_pccb,
            context=request.context,
        )
        broker = _RecordingBroker()

        result = self._executor(broker=broker).execute(missing_proof_request, self._handler)

        self.assertIsNotNone(result.refusal)
        assert result.refusal is not None
        self.assertEqual("SIGNATURE_INVALID", result.refusal.reason_code)
        self.assertEqual(0, broker.acquire_calls)
        self.assertEqual([], broker.issued_credentials)

    def test_broker_is_not_called_when_policy_refuses(self) -> None:
        request = self._request(escrow_id=None)
        broker = _RecordingBroker()

        result = self._executor(broker=broker).execute(request, self._handler, policy_decision=self._deny_decision())

        self.assertIsNotNone(result.refusal)
        assert result.refusal is not None
        self.assertEqual("INFRA_DELETE_PRODUCTION_DENIED", result.refusal.reason_code)
        self.assertEqual(0, broker.acquire_calls)
        self.assertEqual([], broker.issued_credentials)

    def test_policy_refusal_does_not_consume_escrow(self) -> None:
        request = self._request()
        broker = _RecordingBroker()
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )

        result = self._executor(broker=broker, escrow=escrow).execute(
            request,
            self._handler,
            policy_decision=self._deny_decision(),
        )

        self.assertIsNotNone(result.refusal)
        assert result.refusal is not None
        self.assertEqual("INFRA_DELETE_PRODUCTION_DENIED", result.refusal.reason_code)
        self.assertEqual(0, broker.acquire_calls)
        record = escrow.inspect("esc_exec_001")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual("issued", record.state)

    def test_refusal_leaves_credential_unissued_when_escrow_refuses(self) -> None:
        request = self._request()
        broker = _RecordingBroker()
        escrow = InMemoryCapabilityEscrow()

        result = self._executor(broker=broker, escrow=escrow).execute(request, self._handler)

        self.assertIsNotNone(result.refusal)
        assert result.refusal is not None
        self.assertEqual("ESCROW_NOT_FOUND", result.refusal.reason_code)
        self.assertEqual(0, broker.acquire_calls)
        self.assertEqual([], broker.issued_credentials)

    def test_broker_is_not_called_on_replay_refusal(self) -> None:
        request = self._request(escrow_id=None)
        replay = ReplayProtector(SqliteReplayStore(Path(self.tempdir.name) / "replay.sqlite3"))
        first_broker = _RecordingBroker()
        first = ProtectedExecutor(
            proof_verifier=PCCBVerifier(self.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
            credential_broker=first_broker,
            replay_protector=replay,
            outcome_writer=InMemoryOutcomeWriter(),
        ).execute(request, self._handler)
        second_broker = _RecordingBroker()

        second = ProtectedExecutor(
            proof_verifier=PCCBVerifier(self.signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG),
            credential_broker=second_broker,
            replay_protector=replay,
            outcome_writer=InMemoryOutcomeWriter(),
        ).execute(request, self._handler)

        self.assertIsNone(first.refusal)
        self.assertEqual(1, first_broker.acquire_calls)
        self.assertIsNotNone(second.refusal)
        assert second.refusal is not None
        self.assertEqual("DUPLICATE_REPLAY", second.refusal.reason_code)
        self.assertEqual(0, second_broker.acquire_calls)
        self.assertEqual([], second_broker.issued_credentials)

    def test_broker_failure_creates_safe_refusal_without_raw_provider_details(self) -> None:
        fake_provider_secret = "sk_live_SUPER_SECRET_SHOULD_NOT_APPEAR"
        request = self._request()
        replay_path = Path(self.tempdir.name) / "replay.sqlite3"
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )
        broker = _FailingBroker(f"provider refused token {fake_provider_secret}")
        writer = InMemoryOutcomeWriter()

        result = self._executor(broker=broker, escrow=escrow, writer=writer).execute(request, self._handler)

        self.assertEqual(1, broker.acquire_calls)
        self.assertEqual([], broker.released_credentials)
        escrow_record = escrow.inspect("esc_exec_001")
        self.assertIsNotNone(escrow_record)
        assert escrow_record is not None
        self.assertEqual("consumed", escrow_record.state)
        replay_state = SqliteReplayStore(replay_path).inspect(
            build_action_consumption_claim(request.intent, request.pccb, request.context).replay_key,
            now=request.context.now,
        )
        self.assertIsNotNone(replay_state)
        assert replay_state is not None
        self.assertEqual("consumed", replay_state.status)
        self.assertIsNotNone(result.refusal)
        self.assertIsNotNone(result.receipt)
        assert result.refusal is not None
        assert result.receipt is not None
        self.assertEqual("EXECUTION_FAILED", result.refusal.reason_code)
        self.assertEqual(SAFE_HANDLER_EXCEPTION_MESSAGE, result.refusal.message)
        self.assertEqual("RuntimeError", result.refusal.details["exception_type"])
        self.assertEqual(SAFE_HANDLER_EXCEPTION_CODE, result.refusal.details["safe_error_code"])
        serialized = json.dumps(
            {
                "result_refusal": result.refusal.to_dict(),
                "result_receipt": result.receipt.to_dict(),
                "writer_refusals": [refusal.to_dict() for refusal in writer.refusals],
                "writer_receipts": [receipt.to_dict() for receipt in writer.receipts],
            },
            sort_keys=True,
        )
        self.assertNotIn(fake_provider_secret, serialized)
        self.assertNotIn("provider refused token", serialized)
        self.assertIn(SAFE_HANDLER_EXCEPTION_MESSAGE, serialized)

    def test_receipt_and_refusal_artifacts_do_not_contain_raw_secret(self) -> None:
        request = self._request()
        broker = _RecordingBroker()
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )
        writer = InMemoryOutcomeWriter()

        executed = self._executor(broker=broker, escrow=escrow, writer=writer).execute(request, self._handler)
        refused = self._executor(broker=_RecordingBroker()).execute(
            ProtectedExecutionRequest(
                intent=request.intent,
                pccb=request.pccb,
                context=self._context(audience_id="wrong-endpoint"),
            ),
            self._handler,
        )

        self.assertIsNotNone(executed.receipt)
        self.assertIsNotNone(refused.receipt)
        self.assertIsNotNone(refused.refusal)
        serialized = repr(
            {
                "execution_receipt": executed.receipt.to_dict() if executed.receipt else None,
                "refusal_receipt": refused.receipt.to_dict() if refused.receipt else None,
                "refusal": refused.refusal.to_dict() if refused.refusal else None,
            }
        )
        self.assertNotIn("raw_secret", serialized)
        self.assertNotIn("production-secret", serialized)
        self.assertNotIn("provider_api_key", serialized)
        self.assertIn("secret_reference", serialized)

    def test_handler_exception_text_is_redacted_from_artifacts_and_broker_release(self) -> None:
        fake_secret = "sk_live_SUPER_SECRET_SHOULD_NOT_APPEAR"
        request = self._request()
        broker = _RecordingBroker()
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_exec_001",
            pccb_id=request.pccb.pccb_id,
            capability=request.intent.action.capability,
            expires_at=request.pccb.expires_at,
        )
        writer = InMemoryOutcomeWriter()

        def handler_with_secret_exception(
            _request: ProtectedExecutionRequest,
            _credential: BrokeredCredential,
        ) -> dict[str, Any]:
            raise RuntimeError(fake_secret)

        result = self._executor(broker=broker, escrow=escrow, writer=writer).execute(request, handler_with_secret_exception)

        self.assertIsNotNone(result.refusal)
        self.assertIsNotNone(result.receipt)
        assert result.refusal is not None
        assert result.receipt is not None
        self.assertEqual("EXECUTION_FAILED", result.refusal.reason_code)
        self.assertEqual(SAFE_HANDLER_EXCEPTION_MESSAGE, result.refusal.message)
        self.assertEqual("RuntimeError", result.refusal.details["exception_type"])
        self.assertEqual(SAFE_HANDLER_EXCEPTION_CODE, result.refusal.details["safe_error_code"])
        self.assertEqual("execution", result.refusal.details["phase"])
        self.assertEqual(request.context.request_id, result.refusal.details["request_id"])
        self.assertTrue(result.refusal.details["sensitive_details_redacted"])
        self.assertEqual(1, len(broker.released_credentials))
        _, release_result = broker.released_credentials[0]
        self.assertEqual("failed", release_result["outcome"])
        self.assertEqual("RuntimeError", release_result["exception_type"])
        self.assertEqual(SAFE_HANDLER_EXCEPTION_CODE, release_result["safe_error_code"])

        serialized = json.dumps(
            {
                "result_refusal": result.refusal.to_dict(),
                "result_receipt": result.receipt.to_dict(),
                "writer_refusals": [refusal.to_dict() for refusal in writer.refusals],
                "writer_receipts": [receipt.to_dict() for receipt in writer.receipts],
                "broker_release": release_result,
            },
            sort_keys=True,
        )
        self.assertNotIn(fake_secret, serialized)
        self.assertIn(SAFE_HANDLER_EXCEPTION_MESSAGE, serialized)
        self.assertIn(SAFE_HANDLER_EXCEPTION_CODE, serialized)
        self.assertIn("RuntimeError", serialized)


if __name__ == "__main__":
    unittest.main()
