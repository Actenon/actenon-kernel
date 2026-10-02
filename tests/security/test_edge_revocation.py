"""Edge revocation (actenon-protocol protocol/13-edge-binding.md E5).

A proof whose signed authority reference declares the authority revocable
must not execute unless the edge consulted the authority's revocation source
and it said "not revoked". A revoked authority, an unreachable source, or no
configured source all refuse, before any replay claim or side effect.
"""

from __future__ import annotations

import pytest

from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore
from tests.security.test_production_environment_paths import _Ed25519Signer

AUTHORITY = {"issuer": "service:permit", "grant_id": "grant_123", "revocable": True}


def _gate(tmp_path, **kwargs) -> ActenonGate:
    signer = _Ed25519Signer()
    return ActenonGate(
        verifier=signer,
        signer=signer,
        audience="service:payments",
        issuer="service:permit",
        replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.sqlite3")),
        **kwargs,
    )


def _action(gate: ActenonGate) -> dict:
    return gate.build_action(
        "payment.refund", "payment.refund", {"amount_minor": 100},
        target_type="charge", target_id="ch_1", intent_id="intent_rev_1",
    )


def test_minted_authority_reference_is_signed(tmp_path):
    gate = _gate(tmp_path, revocation_checker=lambda pccb, ctx: True)
    action = _action(gate)
    proof = gate.mint_proof(action, authority=AUTHORITY)
    assert proof.extensions["authority"] == AUTHORITY
    tampered = proof.to_dict()
    tampered["extensions"]["authority"]["grant_id"] = "grant_other"
    calls: list[int] = []
    out = gate.protect(action, tampered, lambda: calls.append(1))
    assert out.reason_code in {"SIGNATURE_INVALID", "PROOF_INVALID"}
    assert calls == []


def test_not_revoked_executes_once(tmp_path):
    seen: list[str] = []

    def checker(pccb, ctx):
        seen.append(pccb.extensions["authority"]["grant_id"])
        return True

    gate = _gate(tmp_path, revocation_checker=checker)
    action = _action(gate)
    proof = gate.mint_proof(action, authority=AUTHORITY)
    calls: list[int] = []
    assert gate.protect(action, proof, lambda: calls.append(1)).ok
    assert calls == [1]
    assert seen == ["grant_123"]


def test_revoked_after_minting_does_not_execute(tmp_path):
    revoked: set[str] = set()
    gate = _gate(tmp_path, revocation_checker=lambda pccb, ctx: pccb.extensions["authority"]["grant_id"] not in revoked)
    action = _action(gate)
    proof = gate.mint_proof(action, authority=AUTHORITY)
    revoked.add("grant_123")
    calls: list[int] = []
    out = gate.protect(action, proof, lambda: calls.append(1))
    assert out.reason_code == "AUTHORITY_REVOKED"
    assert calls == []
    # The refusal consumed no single-use state: re-instating the grant lets it run once.
    revoked.clear()
    assert gate.protect(action, proof, lambda: calls.append(1)).ok
    assert calls == [1]


def test_unreachable_revocation_source_refuses(tmp_path):
    def checker(pccb, ctx):
        raise ConnectionError("revocation source unreachable")

    gate = _gate(tmp_path, revocation_checker=checker)
    action = _action(gate)
    calls: list[int] = []
    out = gate.protect(action, gate.mint_proof(action, authority=AUTHORITY), lambda: calls.append(1))
    assert out.reason_code == "AUTHORITY_REVOKED"
    assert calls == []


def test_revocable_proof_without_a_revocation_source_refuses(tmp_path):
    gate = _gate(tmp_path)
    action = _action(gate)
    calls: list[int] = []
    out = gate.protect(action, gate.mint_proof(action, authority=AUTHORITY), lambda: calls.append(1))
    assert out.reason_code == "AUTHORITY_REVOKED"
    assert calls == []


def test_proof_without_revocable_authority_needs_no_source(tmp_path):
    gate = _gate(tmp_path)
    action = _action(gate)
    assert gate.protect(action, gate.mint_proof(action), lambda: None).ok


@pytest.mark.parametrize("authority", [{"revocable": "true"}, {"revocable": 1}, "grant_123", ["x"]])
def test_malformed_authority_reference_refuses(tmp_path, authority):
    gate = _gate(tmp_path, revocation_checker=lambda pccb, ctx: True)
    action = _action(gate)
    calls: list[int] = []
    out = gate.protect(action, gate.mint_proof(action, authority=authority), lambda: calls.append(1))
    assert not out.ok
    assert calls == []
