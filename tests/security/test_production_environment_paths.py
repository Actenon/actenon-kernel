"""The documented production paths must work in a production-like environment.

``ActenonGate(verifier=..., ...)`` is the documented production front door
(docs/guides/HIGH_LEVEL_GATE_API.md). Its executor used to be hard-wired to
``VerifierDisclosureMode.LOCAL_DEBUG``, which the verifier refuses to
construct when ``ACTENON_ENV`` is production-like, so the gate raised
``ValueError`` at construction for every production deployment that set
``ACTENON_ENV``. In a production-like environment the gate must instead
run with the non-debug profile (pre-authentication failures collapse to
``PROOF_INVALID``).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from actenon.escrow import InMemoryCapabilityEscrow
from actenon.gate import ActenonGate
from actenon.models import SignatureSpec
from actenon.proof import VerifierDisclosureMode
from actenon.proof.signers.base import b64url_decode, b64url_encode
from actenon.receipts import InMemoryOutcomeWriter
from actenon.replay import SqliteReplayStore
from actenon.verifier.endpoint import PythonProtectedEndpoint
from tests.security.helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
)


class _Ed25519Signer:
    """Minimal in-process asymmetric signer standing in for KMS custody."""

    algorithm = "EdDSA"

    def __init__(self, key_id: str = "prod-ed25519-2026") -> None:
        self.key_id = key_id
        self._key = Ed25519PrivateKey.generate()

    def sign(self, payload: bytes) -> SignatureSpec:
        return SignatureSpec(self.algorithm, self.key_id, "base64url", b64url_encode(self._key.sign(payload)))

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        if (signature.algorithm, signature.key_id, signature.encoding) != (self.algorithm, self.key_id, "base64url"):
            return False
        try:
            self._key.public_key().verify(b64url_decode(signature.value), payload)
        except Exception:
            return False
        return True


def _gate(signer: _Ed25519Signer, tempdir: str, **kwargs) -> ActenonGate:
    from actenon.replay import ReplayProtector

    return ActenonGate(
        verifier=signer,
        signer=signer,
        audience="service:payments",
        issuer="service:payments-issuer",
        replay_protector=ReplayProtector(SqliteReplayStore(Path(tempdir) / "replay.sqlite3")),
        clock=lambda: NOW,
        **kwargs,
    )


def _action(gate: ActenonGate) -> dict:
    return gate.build_action(
        "payment.release",
        "payment.release",
        {"amount_minor": 1000, "currency": "USD"},
        target_type="payment",
        target_id="payment_001",
        issued_at=NOW,
        intent_id="intent_prod_001",
    )


class ProductionGateTests(unittest.TestCase):
    def test_gate_constructs_and_executes_under_actenon_env_production(self) -> None:
        signer = _Ed25519Signer()
        with mock.patch.dict(os.environ, {"ACTENON_ENV": "production"}), tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(signer, tempdir)
            action = _action(gate)
            proof = gate.mint_proof(action)
            calls = []
            outcome = gate.protect(action, proof, lambda: calls.append(1) or {"ok": True})
            self.assertTrue(outcome.ok, outcome.reason_code)
            self.assertEqual([1], calls)
            replay = gate.protect(action, proof, lambda: calls.append(1))
            self.assertEqual("DUPLICATE_REPLAY", replay.reason_code)
            self.assertEqual([1], calls)

    def test_pre_auth_failures_collapse_to_proof_invalid_in_production(self) -> None:
        signer = _Ed25519Signer()
        with mock.patch.dict(os.environ, {"ACTENON_ENV": "production"}), tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(signer, tempdir)
            action = _action(gate)
            proof = gate.mint_proof(action)
            forged = replace(proof, signature=replace(proof.signature, value=b64url_encode(b"\x00" * 64)))
            outcome = gate.protect(action, forged, lambda: {"ok": True})
            self.assertEqual("PROOF_INVALID", outcome.reason_code)

    def test_local_development_keeps_granular_codes(self) -> None:
        signer = _Ed25519Signer()
        env = {k: v for k, v in os.environ.items() if k != "ACTENON_ENV"}
        with mock.patch.dict(os.environ, env, clear=True), tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(signer, tempdir)
            action = _action(gate)
            proof = gate.mint_proof(action)
            forged = replace(proof, signature=replace(proof.signature, value=b64url_encode(b"\x00" * 64)))
            outcome = gate.protect(action, forged, lambda: {"ok": True})
            self.assertEqual("SIGNATURE_INVALID", outcome.reason_code)

    def test_explicit_disclosure_mode_is_honoured(self) -> None:
        signer = _Ed25519Signer()
        with tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(signer, tempdir, disclosure_mode=VerifierDisclosureMode.PUBLIC_GENERIC)
            action = _action(gate)
            proof = gate.mint_proof(action)
            outcome = gate.protect(action, proof, lambda: {"ok": True}, audience="service:elsewhere")
            self.assertEqual("PROOF_INVALID", outcome.reason_code)

    def test_explicit_local_debug_is_still_refused_in_production(self) -> None:
        signer = _Ed25519Signer()
        with mock.patch.dict(os.environ, {"ACTENON_ENV": "production"}), tempfile.TemporaryDirectory() as tempdir:
            with self.assertRaises(ValueError):
                _gate(signer, tempdir, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG)


class ProductionProtectedEndpointTests(unittest.TestCase):
    def test_python_protected_endpoint_executes_under_actenon_env_production(self) -> None:
        signer = _Ed25519Signer()
        intent = build_security_intent()
        context = build_security_context()
        pccb = mint_security_pccb(intent=intent, context=context, signer=signer, escrow_id=None)
        with mock.patch.dict(os.environ, {"ACTENON_ENV": "production"}), tempfile.TemporaryDirectory() as tempdir:
            endpoint = PythonProtectedEndpoint(
                signer=signer,
                escrow=InMemoryCapabilityEscrow(),
                replay_store=SqliteReplayStore(Path(tempdir) / "replay.sqlite3"),
                outcome_writer=InMemoryOutcomeWriter(),
            )
            request = endpoint.build_request(
                intent=intent,
                pccb=pccb,
                request_id="req_prod_endpoint",
                audience=context.audience,
                now=NOW,
            )
            result = endpoint.execute(request=request, handler=lambda req: {"ok": True})
            # The in-memory escrow has no record for this proof, so the
            # endpoint must refuse — but it must get far enough to decide.
            self.assertIsNotNone(result.refusal)
            self.assertNotEqual("OUTCOME_UNKNOWN", result.refusal.reason_code)


if __name__ == "__main__":
    unittest.main()
