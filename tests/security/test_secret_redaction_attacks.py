from __future__ import annotations

import json
import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from actenon.core.redaction import SAFE_HANDLER_EXCEPTION_CODE, SAFE_HANDLER_EXCEPTION_MESSAGE
from actenon.credentials import BrokeredCredential, InMemoryCredentialBroker
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.execution import ProtectedExecutor
from actenon.models import ActionIntent, DynamicContextInput, PCCB, ProtectedExecutionRequest
from actenon.proof import PCCBVerifier
from actenon.receipts import CompositeOutcomeWriter, InMemoryOutcomeWriter, JsonArtifactOutcomeWriter
from actenon.replay import ReplayProtector, SqliteReplayStore

from .helpers import build_security_context, build_security_intent, mint_security_pccb, security_signer


FAKE_SECRET = "sk_live_SUPER_SECRET_SHOULD_NOT_APPEAR"


class ProviderSDKError(RuntimeError):
    def __str__(self) -> str:
        return f"provider response body included bearer token {FAKE_SECRET}"

    def __repr__(self) -> str:
        return f"ProviderSDKError(traceback='Traceback leaked {FAKE_SECRET}')"


class _SecretHoldingBroker(InMemoryCredentialBroker):
    def __init__(self) -> None:
        super().__init__(ttl=timedelta(seconds=45), credential_id_factory=lambda: "cred_security_001")
        self.raw_material = FAKE_SECRET
        self.acquire_calls = 0

    def acquire(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> BrokeredCredential:
        self.acquire_calls += 1
        return super().acquire(intent, pccb, context)


class SecretRedactionAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.intent = build_security_intent()
        self.context = build_security_context()
        self.pccb = mint_security_pccb(intent=self.intent, context=self.context)
        self.request = ProtectedExecutionRequest(intent=self.intent, pccb=self.pccb, context=self.context)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _executor(
        self,
        *,
        broker: _SecretHoldingBroker,
        memory_writer: InMemoryOutcomeWriter,
        escrow: InMemoryCapabilityEscrow | None = None,
    ) -> ProtectedExecutor:
        return ProtectedExecutor(
            proof_verifier=PCCBVerifier(security_signer()),
            credential_broker=broker,
            replay_protector=ReplayProtector(SqliteReplayStore(self.root / "replay.sqlite3")),
            escrow=escrow,
            outcome_writer=CompositeOutcomeWriter(
                memory_writer,
                JsonArtifactOutcomeWriter(self.root / "artifacts"),
            ),
        )

    def _issued_escrow(self) -> InMemoryCapabilityEscrow:
        escrow = InMemoryCapabilityEscrow()
        escrow.issue(
            escrow_id="esc_security_001",
            pccb_id=self.pccb.pccb_id,
            capability=self.intent.action.capability,
            expires_at=self.pccb.expires_at,
        )
        return escrow

    def _serialized_artifacts(self, memory_writer: InMemoryOutcomeWriter, broker: _SecretHoldingBroker) -> str:
        file_payloads = {
            path.relative_to(self.root).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted((self.root / "artifacts").rglob("*.json"))
        }
        return json.dumps(
            {
                "memory_receipts": [receipt.to_dict() for receipt in memory_writer.receipts],
                "memory_refusals": [refusal.to_dict() for refusal in memory_writer.refusals],
                "broker_releases": [
                    {"credential": credential.to_public_dict(), "result": result}
                    for credential, result in broker.released_credentials
                ],
                "files": file_payloads,
            },
            sort_keys=True,
        )

    def test_handler_exception_and_provider_response_body_are_redacted_from_artifacts(self) -> None:
        broker = _SecretHoldingBroker()
        memory_writer = InMemoryOutcomeWriter()

        def handler(_request: ProtectedExecutionRequest, _credential: BrokeredCredential) -> dict[str, Any]:
            raise ProviderSDKError()

        result = self._executor(broker=broker, memory_writer=memory_writer, escrow=self._issued_escrow()).execute(self.request, handler)
        serialized = self._serialized_artifacts(memory_writer, broker)

        self.assertIsNotNone(result.refusal)
        self.assertIsNotNone(result.receipt)
        assert result.refusal is not None
        self.assertEqual("EXECUTION_FAILED", result.refusal.reason_code)
        self.assertEqual(SAFE_HANDLER_EXCEPTION_MESSAGE, result.refusal.message)
        self.assertEqual("ProviderSDKError", result.refusal.details["exception_type"])
        self.assertEqual(SAFE_HANDLER_EXCEPTION_CODE, result.refusal.details["safe_error_code"])
        self.assertTrue(result.refusal.details["sensitive_details_redacted"])
        self.assertNotIn(FAKE_SECRET, serialized)
        self.assertNotIn("provider response body", serialized)
        self.assertNotIn("Traceback leaked", serialized)
        self.assertNotIn(repr(ProviderSDKError()), serialized)
        self.assertIn(SAFE_HANDLER_EXCEPTION_MESSAGE, serialized)

    def test_reference_broker_raw_material_is_not_persisted_in_success_artifacts(self) -> None:
        broker = _SecretHoldingBroker()
        memory_writer = InMemoryOutcomeWriter()

        def handler(_request: ProtectedExecutionRequest, credential: BrokeredCredential) -> dict[str, Any]:
            return {"credential_reference_seen": credential.secret_reference}

        result = self._executor(broker=broker, memory_writer=memory_writer, escrow=self._issued_escrow()).execute(self.request, handler)
        serialized = self._serialized_artifacts(memory_writer, broker)

        self.assertIsNone(result.refusal)
        self.assertIsNotNone(result.receipt)
        self.assertEqual(1, broker.acquire_calls)
        self.assertNotIn(broker.raw_material, serialized)
        self.assertNotIn("raw_secret", serialized)
        self.assertNotIn("private_key", serialized)
        self.assertIn("secret_reference", serialized)
        self.assertIn("memory://brokered-credential/cred_security_001", serialized)

    def test_release_failure_metadata_for_handler_exception_is_safe(self) -> None:
        broker = _SecretHoldingBroker()
        memory_writer = InMemoryOutcomeWriter()

        def handler(_request: ProtectedExecutionRequest, _credential: BrokeredCredential) -> dict[str, Any]:
            raise RuntimeError(FAKE_SECRET)

        result = self._executor(broker=broker, memory_writer=memory_writer, escrow=self._issued_escrow()).execute(self.request, handler)

        self.assertIsNotNone(result.refusal)
        self.assertEqual(1, len(broker.released_credentials))
        _credential, release_result = broker.released_credentials[0]
        release_json = json.dumps(release_result, sort_keys=True)
        self.assertNotIn(FAKE_SECRET, release_json)
        self.assertEqual("failed", release_result["outcome"])
        self.assertEqual("RuntimeError", release_result["exception_type"])
        self.assertEqual(SAFE_HANDLER_EXCEPTION_CODE, release_result["safe_error_code"])


if __name__ == "__main__":
    unittest.main()
