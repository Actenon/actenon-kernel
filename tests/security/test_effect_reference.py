"""An effect-bearing proof must not execute without its authoritative ledger."""

from dataclasses import replace

from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore
from tests.security.helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import pytest
from actenon.execution.effects import EffectProtector, EffectReference
from actenon.proof.canonical import canonicalize_bytes
from actenon_protocol.effects import EFFECT_PROFILE, effect_identity
from tests.unit.test_protected_executor import _RecordingBroker


def test_signed_effect_is_not_silently_ignored(tmp_path):
    intent = build_security_intent(capability="payment.release")
    proof = mint_security_pccb(
        intent=intent,
        context=build_security_context(
            audience_id="actenon-permit-gateway",
            scope_capabilities=(intent.action.capability,),
        ),
    )
    unsigned = replace(
        proof,
        extensions={
            "effect": {
                "profile": "ACTENON-EFFECT-1",
                "effect_id": "effect_" + "a" * 64,
                "reservation_id": "reservation_" + "b" * 32,
                "owner_attempt_id": "exec_" + "c" * 32,
            }
        },
    )
    from actenon.proof.canonical import canonicalize_bytes

    proof = replace(
        unsigned,
        signature=security_signer().sign(
            canonicalize_bytes(unsigned.unsigned_payload())
        ),
    )
    calls = []
    gate = ActenonGate(
        verifier=security_signer(),
        audience="service:actenon-permit-gateway",
        issuer="service:issuer",
        capabilities=(intent.action.capability,),
        clock=lambda: NOW,
        replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.db")),
    )
    result = gate.protect(intent, proof, lambda: calls.append(True) or {})
    assert not result.ok
    assert calls == []


def _signed(intent, effect=None, authority=True, **mint_kwargs):
    proof = mint_security_pccb(
        intent=intent,
        context=build_security_context(
            audience_id="actenon-permit-gateway",
            scope_capabilities=(intent.action.capability,),
        ),
        **mint_kwargs,
    )
    extensions = {}
    if effect is not None:
        extensions["effect"] = effect
    if authority:
        extensions["authority"] = {
            "issuer": f"{proof.issuer.type}:{proof.issuer.id}",
            "grant_id": "grant-effect",
            "revocable": True,
        }
    unsigned = replace(proof, extensions=extensions)
    return replace(
        unsigned,
        signature=security_signer().sign(
            canonicalize_bytes(unsigned.unsigned_payload())
        ),
    )


def _case(tmp_path, claim=None, builder=None):
    intent = replace(
        build_security_intent(capability="payment.release"),
        intent_id="exec_" + "a" * 32,
    )
    descriptor = {
        "profile": EFFECT_PROFILE,
        "namespace": "merchant:acme",
        "kind": "exact",
        "action_type": intent.action.capability,
        "target": {
            "type": intent.target.resource_type,
            "id": intent.target.resource_id,
        },
        "parameters": intent.action.parameters,
    }
    ref = {
        "profile": EFFECT_PROFILE,
        "effect_id": effect_identity(descriptor),
        "reservation_id": "reservation_" + "b" * 32,
        "owner_attempt_id": intent.intent_id,
    }
    claims = []

    def default_claim(reference, request):
        claims.append((reference, request))
        return True

    broker = _RecordingBroker()
    gate = ActenonGate(
        verifier=security_signer(),
        audience="service:actenon-permit-gateway",
        issuer="service:issuer",
        capabilities=(intent.action.capability,),
        clock=lambda: NOW,
        replay_protector=ReplayProtector(
            SqliteReplayStore(tmp_path / "effects-replay.db")
        ),
        credential_broker=broker,
        revocation_checker=lambda _p, _c: True,
        effect_protector=EffectProtector(
            "merchant:acme", claim or default_claim, builder
        ),
    )
    return intent, ref, descriptor, gate, broker, claims


def test_valid_signed_effect_claim_precedes_credentials_and_execution(tmp_path):
    intent, ref, _, gate, broker, claims = _case(tmp_path)
    calls = []

    def execute(request, credential):
        assert len(claims) == 1
        assert broker.acquire_calls == 1
        assert claims[0][0].to_dict() == ref
        calls.append(True)
        return {
            "effect_evidence": {
                **ref,
                "outcome": "COMMITTED",
                "execution_occurred": True,
                "evidence_hash": "d" * 64,
            }
        }

    result = gate.protect(intent, _signed(intent, ref), execute)
    assert result.ok
    assert calls == [True]
    assert not gate.protect(intent, _signed(intent, ref), execute).ok
    assert len(claims) == 1  # replay checked before a second claim


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "null",
        "extra",
        "unknown-profile",
        "wrong-effect",
        "wrong-attempt",
        "wrong-reservation",
        "missing-authority",
        "forged",
    ],
)
def test_bad_effect_reference_releases_no_credential(tmp_path, change):
    intent, ref, _, gate, broker, claims = _case(tmp_path)
    effect = copy.deepcopy(ref)
    if change == "missing":
        effect = None
    elif change == "null":
        effect = None
    elif change == "extra":
        effect["approval"] = True
    elif change == "unknown-profile":
        effect["profile"] = "ACTENON-EFFECT-2"
    elif change == "wrong-effect":
        effect["effect_id"] = "effect_" + "f" * 64
    elif change == "wrong-attempt":
        effect["owner_attempt_id"] = "exec_" + "f" * 32
    elif change == "wrong-reservation":
        effect["reservation_id"] = "reservation_unknown"
    proof = _signed(intent, effect, authority=change != "missing-authority")
    if change == "null":
        unsigned = replace(proof, extensions={**proof.extensions, "effect": None})
        proof = replace(
            unsigned,
            signature=security_signer().sign(
                canonicalize_bytes(unsigned.unsigned_payload())
            ),
        )
    if change == "forged":
        proof = replace(proof, signature=replace(proof.signature, value="A" * 43))
    calls = []
    result = gate.protect(intent, proof, lambda: calls.append(True) or {})
    assert not result.ok
    assert broker.acquire_calls == 0
    assert calls == []
    assert claims == []


@pytest.mark.parametrize("value", [False, None, 1, "yes"])
def test_claim_must_confirm_atomic_ownership_with_true(tmp_path, value):
    intent, ref, _, gate, broker, _ = _case(tmp_path, claim=lambda _r, _q: value)
    calls = []
    assert not gate.protect(
        intent, _signed(intent, ref), lambda: calls.append(True) or {}
    ).ok
    assert broker.acquire_calls == 0
    assert calls == []


def test_unavailable_ledger_refuses_without_exposing_its_exception(tmp_path):
    def unavailable(_r, _q):
        raise RuntimeError("private-database-password")

    intent, ref, _, gate, broker, _ = _case(tmp_path, claim=unavailable)
    result = gate.protect(intent, _signed(intent, ref), lambda: {"unexpected": True})
    assert not result.ok
    assert broker.acquire_calls == 0
    assert "private-database-password" not in json.dumps(result.to_dict())


@pytest.mark.parametrize(
    "change", ["parameter", "target", "capability", "namespace", "drop-parameter"]
)
def test_signed_effect_cannot_be_detached_from_actual_request(tmp_path, change):
    intent, ref, descriptor, gate, broker, claims = _case(tmp_path)
    if change == "parameter":
        intent = replace(
            intent,
            action=replace(
                intent.action, parameters={**intent.action.parameters, "amount": 9000}
            ),
        )
    elif change == "target":
        intent = replace(
            intent, target=replace(intent.target, resource_id="production-payments")
        )
    elif change == "capability":
        intent = replace(
            intent, action=replace(intent.action, capability="payment.delete")
        )
    else:
        modified = copy.deepcopy(descriptor)
        if change == "namespace":
            modified["namespace"] = "agent-new-namespace"
        else:
            modified["parameters"] = {}
        gate._executor.effect_protector = EffectProtector(
            "merchant:acme", lambda _r, _q: True, lambda _q: modified
        )
    # Even a correctly signed NEW proof cannot excuse an old effect identity.
    result = gate.protect(intent, _signed(intent, ref), lambda: {"unexpected": True})
    assert not result.ok
    assert broker.acquire_calls == 0
    assert claims == []


def test_two_fresh_proofs_for_one_effect_only_one_dispatch(tmp_path):
    lock, owned, calls = Lock(), set(), []

    def claim(reference, _request):
        with lock:
            if reference.effect_id in owned:
                return False
            owned.add(reference.effect_id)
            return True

    intent, ref, _, gate, broker, _ = _case(tmp_path, claim=claim)

    def attempt(index):
        new_intent = replace(intent, intent_id="exec_" + f"{index:032x}")
        new_ref = {**ref, "owner_attempt_id": new_intent.intent_id}
        proof = _signed(
            new_intent,
            new_ref,
            pccb_id=f"pccb_race_{index}",
            nonce=f"nonce-race-{index}",
        )
        return gate.protect(
            new_intent,
            proof,
            lambda: (
                calls.append(index)
                or {
                    "effect_evidence": {
                        **new_ref,
                        "outcome": "COMMITTED",
                        "execution_occurred": True,
                        "evidence_hash": "d" * 64,
                    }
                }
            ),
        ).ok

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, [1, 2])) == [False, True]
    assert len(calls) == 1
    assert broker.acquire_calls == 1


def test_effect_reference_matches_locked_protocol_corpus():
    # Published schema and SDK-independent parser must agree on these shapes.
    from actenon_protocol.types.effects import EffectReference as ProtocolReference
    from pydantic import ValidationError

    cases = [
        {
            "profile": EFFECT_PROFILE,
            "effect_id": "effect_" + "a" * 64,
            "reservation_id": "reservation_" + "b" * 32,
            "owner_attempt_id": "exec_" + "c" * 32,
        },
        None,
        {},
        {"profile": "ACTENON-EFFECT-2"},
    ]
    for raw in cases:
        try:
            expected = ProtocolReference.model_validate(raw).model_dump()
        except ValidationError:
            with pytest.raises(ValueError):
                EffectReference.from_dict(raw)
        else:
            assert EffectReference.from_dict(raw).to_dict() == expected


@pytest.mark.parametrize(
    "response",
    [
        "lost",
        "empty",
        "wrong-effect",
        "invalid-outcome",
        "ambiguous",
        "not-executed",
        "refusal-after-dispatch",
    ],
)
def test_uncertain_dispatch_is_never_reported_as_failed_or_not_executed(
    tmp_path, response
):
    from actenon.core.errors import RefusalException

    intent, ref, _, gate, broker, claims = _case(tmp_path)

    def boundary():
        if response == "lost":
            raise TimeoutError("provider committed but response was lost")
        if response == "refusal-after-dispatch":
            raise RefusalException(
                category="provider",
                refusal_code="PROVIDER_REFUSAL",
                message="error after sending request",
            )
        if response == "empty":
            return {}
        evidence = {
            **ref,
            "outcome": "COMMITTED",
            "execution_occurred": True,
            "evidence_hash": "d" * 64,
        }
        if response == "wrong-effect":
            evidence["effect_id"] = "effect_" + "f" * 64
        if response == "invalid-outcome":
            evidence["outcome"] = "FAILED"
        if response == "ambiguous":
            evidence.update(outcome="AMBIGUOUS", execution_occurred=None)
        if response == "not-executed":
            evidence.update(outcome="NOT_EXECUTED", execution_occurred=False)
        return {"effect_evidence": evidence}

    result = gate.protect(intent, _signed(intent, ref), boundary)
    assert not result.ok
    assert broker.acquire_calls == 1
    assert len(claims) == 1
    effect = result.receipt.extensions["effect"]
    if response == "not-executed":
        assert (
            effect["outcome"] == "NOT_EXECUTED"
            and effect["execution_occurred"] is False
        )
    else:
        assert result.reason_code == "OUTCOME_UNKNOWN"
        assert result.receipt.side_effects["state"] == "unknown"
        assert effect["outcome"] == "AMBIGUOUS" and effect["execution_occurred"] is None
    assert not gate.protect(intent, _signed(intent, ref), boundary).ok
    assert len(claims) == 1
