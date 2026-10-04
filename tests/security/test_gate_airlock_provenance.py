"""ActenonGate as Airlock calls it: grant allow-list, revocation, forged proof.

Airlock (actenon-airlock pull/3, ``src/actenon_airlock/broker.py``) constructs::

    ActenonGate(
        verifier=Ed25519PublicKeyVerifier(...),
        audience="service:actenon-permit-gateway",
        issuer="service:actenon-permit",
        capabilities=<signed grant allow-list>,
        replay_protector=ReplayProtector(SqliteReplayStore(...)),
        revocation_checker=StoreRevocationChecker(...),
    )

and then calls ``edge.protect(intent, proof, side_effect)``. These tests use
that constructor shape with a test HMAC trust root. A forged signature, a
capability outside the declared allow-list, and a revocation checker that
refuses or raises must not run the side effect.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import pytest
from actenon_protocol import CapabilityError

from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore
from tests.security.helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)

AUDIENCE = "service:actenon-permit-gateway"
CAPABILITY = "payment.release"


def _intent():
    return build_security_intent(capability=CAPABILITY)


def _proof(intent=None, **kwargs):
    intent = intent or _intent()
    context = build_security_context(
        audience_id="actenon-permit-gateway",
        scope_capabilities=(intent.action.capability,),
    )
    return mint_security_pccb(intent=intent, context=context, **kwargs)


def _gate(tmp: Path, *, capabilities=(CAPABILITY,), revocation_checker=None) -> ActenonGate:
    return ActenonGate(
        verifier=security_signer(),
        audience=AUDIENCE,
        issuer="service:actenon-permit",
        capabilities=capabilities,
        replay_protector=ReplayProtector(SqliteReplayStore(tmp / "replay.sqlite3")),
        revocation_checker=revocation_checker,
        clock=lambda: NOW,
    )


class AirlockGateContractTests(unittest.TestCase):
    def test_genuine_proof_for_a_declared_capability_runs_once(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(Path(tempdir))
            intent = _intent()
            proof = _proof(intent)
            calls: list[str] = []

            def side_effect() -> dict[str, str]:
                calls.append("ran")
                return {"status": "done"}

            outcome = gate.protect(intent, proof, side_effect)
            self.assertTrue(outcome.ok, outcome.reason_code)
            self.assertEqual(["ran"], calls)
            replay = gate.protect(intent, proof, side_effect)
            self.assertFalse(replay.ok)
            self.assertEqual(["ran"], calls)

    def test_forged_signature_does_not_run_the_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(Path(tempdir))
            intent = _intent()
            proof = _proof(intent, pccb_id="pccb_forged", nonce="nonce-forged")
            forged = replace(proof, signature=replace(proof.signature, value="A" * 43))
            calls: list[str] = []

            outcome = gate.protect(intent, forged, lambda: calls.append("ran") or {"status": "done"})
            self.assertFalse(outcome.ok)
            self.assertEqual("SIGNATURE_INVALID", outcome.reason_code)
            self.assertEqual([], calls)

    def test_capability_outside_the_grant_allow_list_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(Path(tempdir), capabilities=("filesystem.write",))
            intent = _intent()
            proof = _proof(intent, pccb_id="pccb_other_cap", nonce="nonce-other-cap")
            calls: list[str] = []

            outcome = gate.protect(intent, proof, lambda: calls.append("ran") or {"status": "done"})
            self.assertFalse(outcome.ok)
            self.assertEqual("SCOPE_CAPABILITY_MISMATCH", outcome.reason_code)
            self.assertEqual([], calls)

    def test_revocation_checker_false_refuses(self) -> None:
        self._assert_revoked(lambda _pccb, _context: False, "nonce-revoked-false")

    def test_revocation_checker_error_refuses(self) -> None:
        def explode(_pccb, _context) -> bool:
            raise RuntimeError("revocation source unavailable")

        self._assert_revoked(explode, "nonce-revoked-error")

    def _assert_revoked(self, checker, nonce: str) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            gate = _gate(Path(tempdir), revocation_checker=checker)
            intent = _intent()
            proof = _proof(intent, pccb_id="pccb_" + nonce, nonce=nonce)
            calls: list[str] = []

            def side_effect() -> dict[str, str]:
                calls.append("ran")
                return {"status": "done"}

            outcome = gate.protect(intent, proof, side_effect)
            self.assertFalse(outcome.ok)
            self.assertEqual("AUTHORITY_REVOKED", outcome.reason_code)
            self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()


@pytest.mark.parametrize("scope", [(), ("*",), ("payment.*",), ("payment.release", "*")])
def test_real_minter_never_substitutes_or_widens_a_declared_scope(scope):
    from actenon.models import PartyRef
    from actenon.proof import PCCBMinter
    from tests.security.helpers import _allow_decision

    minter = PCCBMinter(signer=security_signer(), issuer=PartyRef(type="service", id="issuer"))
    context = build_security_context(scope_capabilities=scope)
    with pytest.raises(CapabilityError):
        minter.mint(_intent(), _allow_decision(), context)
