"""Adversarial tests for the resource-boundary verifier (Boundary Kit).

``BoundaryVerifier.verify_boundary`` is the call the Boundary Kit middleware
delegates to before letting a request reach a protected handler. It must
never report ``valid=True`` for something it has not cryptographically
verified against the exact action being performed.
"""

from __future__ import annotations

import base64
import json
import threading
import unittest
from dataclasses import replace

from actenon.boundary import BoundaryVerificationRequest, BoundaryVerifier
from actenon.proof import PCCBVerifier, VerifierDisclosureMode
from actenon.replay import SqliteReplayStore
from tests.security.helpers import (
    NOW,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)

AUDIENCE = "service:payment-release-endpoint"


def _token(pccb) -> str:
    raw = json.dumps(pccb.to_dict(), separators=(",", ":")).encode("utf-8")
    return "v1." + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _verifier(**kwargs) -> BoundaryVerifier:
    return BoundaryVerifier(
        pccb_verifier=PCCBVerifier(
            security_signer(),
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        ),
        **kwargs,
    )


def _request(pccb=None, *, intent=None, token=None, **overrides) -> BoundaryVerificationRequest:
    intent = intent or build_security_intent()
    pccb = pccb or mint_security_pccb(intent=intent)
    fields = {
        "proof_token": token if token is not None else _token(pccb),
        "action_type": intent.action.name,
        "action_hash": pccb.action_hash.value,
        "audience": AUDIENCE,
        "boundary_id": "payments",
        "target": intent.target.resource_id,
        "intent": intent.to_dict(),
        "now": NOW,
    }
    fields.update(overrides)
    return BoundaryVerificationRequest(**fields)


class ArbitraryTokenTests(unittest.TestCase):
    def test_arbitrary_string_is_not_a_valid_proof(self) -> None:
        # Before the fix any string of 16+ characters was reported valid.
        result = BoundaryVerifier().verify_boundary(
            BoundaryVerificationRequest(
                proof_token="AAAAAAAAAAAAAAAA-this-is-not-a-proof",
                action_type="payment.release",
                action_hash="abc123",
                audience=AUDIENCE,
            )
        )
        self.assertFalse(result.valid)

    def test_arbitrary_string_is_refused_even_with_a_trust_root(self) -> None:
        result = _verifier().verify_boundary(_request(token="valid_proof_token_at_least_16_chars"))
        self.assertFalse(result.valid)
        self.assertEqual("PROOF_INVALID", result.refusal_code)

    def test_verifier_without_trust_root_refuses_a_genuine_proof(self) -> None:
        result = BoundaryVerifier().verify_boundary(_request())
        self.assertFalse(result.valid)
        self.assertEqual("ISSUER_UNTRUSTED", result.refusal_code)


class GenuineProofTests(unittest.TestCase):
    def test_genuine_proof_for_the_exact_action_verifies(self) -> None:
        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent)
        result = _verifier().verify_boundary(_request(pccb, intent=intent))
        self.assertTrue(result.valid, result.reason)
        self.assertEqual(pccb.pccb_id, result.proof_id)
        self.assertIsNotNone(result.receipt_id)

    def test_raw_json_and_plain_base64url_tokens_are_accepted_encodings(self) -> None:
        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent)
        raw_json = json.dumps(pccb.to_dict())
        plain = _token(pccb)[len("v1."):]
        self.assertTrue(_verifier().verify_boundary(_request(pccb, intent=intent, token=raw_json)).valid)
        self.assertTrue(_verifier().verify_boundary(_request(pccb, intent=intent, token=plain)).valid)

    def test_forged_signature_is_refused(self) -> None:
        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent)
        forged = replace(pccb, signature=replace(pccb.signature, value="A" * 43))
        result = _verifier().verify_boundary(_request(forged, intent=intent))
        self.assertFalse(result.valid)
        self.assertEqual("PROOF_INVALID", result.refusal_code)

    def test_widened_parameters_are_refused(self) -> None:
        intent = build_security_intent(amount_minor=1000)
        pccb = mint_security_pccb(intent=intent)
        widened = build_security_intent(amount_minor=500_000)
        result = _verifier().verify_boundary(_request(pccb, intent=widened, action_hash=""))
        self.assertFalse(result.valid)

    def test_wrong_audience_is_refused(self) -> None:
        result = _verifier().verify_boundary(_request(audience="service:some-other-endpoint"))
        self.assertFalse(result.valid)
        self.assertEqual("AUDIENCE_MISMATCH", result.refusal_code)

    def test_missing_audience_is_refused(self) -> None:
        result = _verifier().verify_boundary(_request(audience=""))
        self.assertFalse(result.valid)

    def test_route_action_must_match_the_intent(self) -> None:
        result = _verifier().verify_boundary(_request(action_type="account.delete"))
        self.assertFalse(result.valid)
        self.assertEqual("ACTION_MISMATCH", result.refusal_code)

    def test_route_target_must_match_the_intent(self) -> None:
        result = _verifier().verify_boundary(_request(target="payment_999"))
        self.assertFalse(result.valid)
        self.assertEqual("TARGET_MISMATCH", result.refusal_code)

    def test_declared_action_hash_must_match_the_proof(self) -> None:
        result = _verifier().verify_boundary(_request(action_hash="0" * 64))
        self.assertFalse(result.valid)
        self.assertEqual("ACTION_HASH_MISMATCH", result.refusal_code)

    def test_missing_intent_is_refused(self) -> None:
        result = _verifier().verify_boundary(replace(_request(), intent=None))
        self.assertFalse(result.valid)
        self.assertEqual("MALFORMED_REQUEST", result.refusal_code)

    def test_expired_proof_is_refused(self) -> None:
        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent)
        result = _verifier().verify_boundary(_request(pccb, intent=intent, now=pccb.expires_at.replace(year=2027)))
        self.assertFalse(result.valid)
        self.assertEqual("PROOF_EXPIRED", result.refusal_code)

    def test_duplicate_json_keys_in_token_are_refused(self) -> None:
        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent)
        raw = json.dumps(pccb.to_dict())
        duplicated = raw[:-1] + ', "nonce": ' + json.dumps(pccb.nonce) + "}"
        result = _verifier().verify_boundary(_request(pccb, intent=intent, token=duplicated))
        self.assertFalse(result.valid)
        self.assertEqual("PROOF_INVALID", result.refusal_code)


class BoundaryReplayTests(unittest.TestCase):
    def test_second_presentation_is_refused(self) -> None:
        verifier = _verifier()
        request = _request()
        self.assertTrue(verifier.verify_boundary(request).valid)
        second = verifier.verify_boundary(request)
        self.assertFalse(second.valid)
        self.assertEqual("REPLAY_DETECTED", second.refusal_code)

    def test_re_encoding_the_same_proof_does_not_bypass_replay(self) -> None:
        # The old replay key was a hash of the token string, so any
        # re-serialisation of the same proof looked like a fresh proof.
        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent)
        verifier = _verifier()
        self.assertTrue(verifier.verify_boundary(_request(pccb, intent=intent)).valid)
        for token in (json.dumps(pccb.to_dict()), json.dumps(pccb.to_dict(), indent=2), _token(pccb)[3:]):
            result = verifier.verify_boundary(_request(pccb, intent=intent, token=token))
            self.assertFalse(result.valid)
            self.assertEqual("REPLAY_DETECTED", result.refusal_code)

    def test_concurrent_presentations_allow_exactly_one(self) -> None:
        verifier = _verifier()
        request = _request()
        results = []
        barrier = threading.Barrier(16)

        def worker() -> None:
            barrier.wait()
            results.append(verifier.verify_boundary(request))

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, sum(1 for item in results if item.valid))
        self.assertEqual(15, sum(1 for item in results if item.refusal_code == "REPLAY_DETECTED"))

    def test_durable_replay_store_is_honoured_across_verifier_instances(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tempdir:
            db = Path(tempdir) / "boundary-replay.sqlite3"
            request = _request()
            self.assertTrue(_verifier(replay_store=SqliteReplayStore(db)).verify_boundary(request).valid)
            second = _verifier(replay_store=SqliteReplayStore(db)).verify_boundary(request)
            self.assertFalse(second.valid)
            self.assertEqual("REPLAY_DETECTED", second.refusal_code)

    def test_failed_verification_does_not_consume_replay_state(self) -> None:
        verifier = _verifier()
        intent = build_security_intent()
        pccb = mint_security_pccb(intent=intent)
        refused = verifier.verify_boundary(_request(pccb, intent=intent, audience="service:elsewhere"))
        self.assertFalse(refused.valid)
        self.assertTrue(verifier.verify_boundary(_request(pccb, intent=intent)).valid)


if __name__ == "__main__":
    unittest.main()
