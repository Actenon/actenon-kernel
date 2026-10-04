"""Mandatory effect constraints cannot disappear through another edge API."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from actenon.boundary import BoundaryVerificationRequest, BoundaryVerifier
from actenon.core.errors import ProofVerificationError
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.execution.effects import EffectProtector
from actenon.models import SignatureSpec
from actenon.models.runtime import ProtectedExecutionRequest
from actenon.proof import PCCBVerifier
from actenon.proof.canonical import canonicalize_bytes
from actenon.proof.signers.base import b64url_decode, b64url_encode
from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.verifier import (
    ProtectedEndpointMiddleware,
    PythonProtectedEndpoint,
    VerifierSDK,
)
from actenon_protocol.effects import EFFECT_PROFILE, effect_identity
from tests.security.helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
)


class PublicVerifier:
    """The edge has a public key only; it cannot mint proof."""

    def __init__(self, public_key):
        self.public_key = public_key

    def verify(self, payload, signature):
        if (signature.algorithm, signature.key_id, signature.encoding) != (
            "EdDSA",
            "effect-edge",
            "base64url",
        ):
            return False
        try:
            self.public_key.verify(b64url_decode(signature.value), payload)
        except Exception:
            return False
        return True


class AuthoritySigner(PublicVerifier):
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        super().__init__(self.private_key.public_key())
        self.algorithm, self.key_id = "EdDSA", "effect-edge"

    def sign(self, payload):
        return SignatureSpec(
            "EdDSA",
            self.key_id,
            "base64url",
            b64url_encode(self.private_key.sign(payload)),
        )


@pytest.fixture
def case():
    signer = AuthoritySigner()
    intent = build_security_intent(intent_id="exec_" + "a" * 32)
    context = build_security_context()
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
    reference = {
        "profile": EFFECT_PROFILE,
        "effect_id": effect_identity(descriptor),
        "reservation_id": "reservation_" + "b" * 32,
        "owner_attempt_id": intent.intent_id,
    }

    def mint(actual=intent, effect=reference, *, revocable=False, nonce="nonce-edge"):
        proof = mint_security_pccb(
            intent=actual, context=context, signer=signer, nonce=nonce
        )
        unsigned = replace(
            proof,
            extensions={
                "effect": effect,
                "authority": {
                    "issuer": f"{proof.issuer.type}:{proof.issuer.id}",
                    "grant_id": "grant-edge",
                    "revocable": revocable,
                },
            },
        )
        return replace(
            unsigned,
            signature=signer.sign(canonicalize_bytes(unsigned.unsigned_payload())),
        )

    return intent, context, reference, PublicVerifier(signer.public_key), mint


def boundary_request(intent, proof):
    return BoundaryVerificationRequest(
        proof_token=json.dumps(proof.to_dict()),
        action_type=intent.action.name,
        action_hash=proof.action_hash.value,
        audience="service:payment-release-endpoint",
        target=intent.target.resource_id,
        intent=intent,
        now=NOW,
    )


@pytest.mark.parametrize("surface", ["boundary", "sdk"])
def test_signed_effect_requires_ownership_at_every_verification_edge(
    tmp_path, case, surface
):
    intent, context, _, verifier, mint = case
    proof = mint()
    provider_calls = []
    if surface == "boundary":
        edge = BoundaryVerifier(
            pccb_verifier=PCCBVerifier(verifier),
            replay_store=SqliteReplayStore(tmp_path / "replay.db"),
        )
        result = edge.verify_boundary(boundary_request(intent, proof))
        if result.valid:
            provider_calls.append("unowned effect dispatched")
        assert not result.valid
        assert result.refusal_code == "POLICY_REFUSAL"
    else:
        with pytest.raises(ProofVerificationError, match="POLICY_REFUSAL"):
            VerifierSDK(verifier).verify(intent=intent, pccb=proof, context=context)
            provider_calls.append("unowned effect dispatched")
    assert provider_calls == []


@pytest.mark.parametrize("surface", ["middleware", "python-endpoint"])
def test_legacy_execution_helpers_refuse_before_escrow_or_provider(
    tmp_path, case, surface
):
    intent, context, _, verifier, mint = case
    proof = mint()
    escrow = InMemoryCapabilityEscrow()
    escrow.issue(
        escrow_id=proof.escrow_id,
        pccb_id=proof.pccb_id,
        capability=intent.action.capability,
        expires_at=proof.expires_at,
    )
    writer, calls = InMemoryOutcomeWriter(), []
    request = ProtectedExecutionRequest(intent, proof, context)
    if surface == "middleware":
        edge = ProtectedEndpointMiddleware(
            proof_verifier=PCCBVerifier(verifier),
            escrow=escrow,
            receipt_factory=ReceiptFactory(),
            refusal_factory=RefusalFactory(),
            outcome_writer=writer,
            replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.db")),
        )
        result = edge.execute(request, lambda _q: calls.append(True) or {})
    else:
        edge = PythonProtectedEndpoint(
            verifier, escrow, SqliteReplayStore(tmp_path / "replay.db"), writer
        )
        result = edge.execute(
            request=request, handler=lambda _q: calls.append(True) or {}
        )
    assert result.refusal is not None
    assert result.refusal.reason_code == "POLICY_REFUSAL"
    assert calls == []
    assert escrow.inspect(proof.escrow_id).state == "issued"


def edge_verify(
    surface,
    tmp_path,
    verifier,
    intent,
    proof,
    context,
    protector,
    revocation=lambda _p, _c: True,
):
    if surface == "sdk":
        try:
            VerifierSDK(
                verifier, effect_protector=protector, revocation_checker=revocation
            ).verify(intent=intent, pccb=proof, context=context)
        except ProofVerificationError:
            return False
        return True
    return (
        BoundaryVerifier(
            pccb_verifier=PCCBVerifier(verifier, revocation_checker=revocation),
            replay_store=SqliteReplayStore(tmp_path / "replay.db"),
            effect_protector=protector,
        )
        .verify_boundary(boundary_request(intent, proof))
        .valid
    )


@pytest.mark.parametrize("surface", ["boundary", "sdk"])
@pytest.mark.parametrize(
    "change",
    [
        "parameter",
        "target",
        "namespace",
        "null",
        "extra",
        "wrong-owner",
        "forged",
        "revoked",
        "ledger-down",
        "not-true",
    ],
)
def test_modified_or_unowned_effect_never_reaches_claimed_dispatch(
    tmp_path, case, surface, change
):
    intent, context, ref, verifier, mint = case
    claims = []
    namespace = "merchant:acme"
    if change == "parameter":
        intent = replace(
            intent,
            action=replace(
                intent.action,
                parameters={**intent.action.parameters, "amount_minor": 9000},
            ),
        )
    if change == "target":
        intent = replace(
            intent, target=replace(intent.target, resource_id="payment-other")
        )
    if change == "namespace":
        namespace = "merchant:other"
    if change == "null":
        ref = None
    if change == "extra":
        ref = {**ref, "agent-approved": True}
    if change == "wrong-owner":
        ref = {**ref, "owner_attempt_id": "exec_" + "f" * 32}
    proof = mint(intent, ref, revocable=True)
    if change == "forged":
        proof = replace(proof, signature=replace(proof.signature, value="A" * 86))

    def claim(reference, request):
        claims.append(reference)
        if change == "ledger-down":
            raise ConnectionError("private credential")
        return 1 if change == "not-true" else True

    protector = EffectProtector(namespace, claim)
    assert not edge_verify(
        surface,
        tmp_path,
        verifier,
        intent,
        proof,
        context,
        protector,
        revocation=lambda _p, _c: change != "revoked",
    )
    assert len(claims) == (1 if change in {"ledger-down", "not-true"} else 0)


def test_fresh_proofs_racing_through_different_edge_apis_dispatch_once(tmp_path, case):
    intent, context, ref, verifier, mint = case
    database = tmp_path / "effect-owner.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE claimed(effect_id TEXT PRIMARY KEY, reservation_id TEXT, owner TEXT)"
        )

    def claim(reference, request):
        assert reference.owner_attempt_id == request.intent.intent_id
        assert request.pccb.extensions["authority"]["grant_id"] == "grant-edge"
        with sqlite3.connect(database) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO claimed VALUES(?,?,?)",
                (
                    reference.effect_id,
                    reference.reservation_id,
                    reference.owner_attempt_id,
                ),
            )
            return cursor.rowcount == 1

    protector = EffectProtector("merchant:acme", claim)
    calls = []

    def attempt(index):
        actual = replace(intent, intent_id="exec_" + f"{index:032x}")
        effect = {
            **ref,
            "owner_attempt_id": actual.intent_id,
            "reservation_id": "reservation_" + f"{index:032x}",
        }
        proof = mint(actual, effect, revocable=True, nonce=f"fresh-{index}")
        allowed = edge_verify(
            "sdk" if index % 2 else "boundary",
            tmp_path,
            verifier,
            actual,
            proof,
            context,
            protector,
        )
        if allowed:
            calls.append(index)
        return allowed

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert sum(pool.map(attempt, range(1, 13))) == 1
    assert len(calls) == 1


@pytest.mark.parametrize(
    "outcome,executed,reported",
    [
        ("COMMITTED", True, "succeeded"),
        ("NOT_EXECUTED", False, "refused"),
        ("AMBIGUOUS", None, "outcome_unknown"),
    ],
)
def test_verification_is_not_a_consequence_receipt(
    tmp_path, case, outcome, executed, reported
):
    intent, _, ref, verifier, mint = case
    edge = BoundaryVerifier(
        pccb_verifier=PCCBVerifier(verifier),
        replay_store=SqliteReplayStore(tmp_path / "replay.db"),
        effect_protector=EffectProtector("merchant:acme", lambda _r, _q: True),
    )
    request = boundary_request(intent, mint())
    result = edge.verify_boundary(request)
    assert result.valid
    with pytest.raises(ValueError, match="not execution evidence"):
        edge.construct_receipt(request, result)
    evidence = {
        **ref,
        "outcome": outcome,
        "execution_occurred": executed,
        "evidence_hash": "d" * 64,
    }
    receipt = edge.construct_receipt(request, result, effect_evidence=evidence)
    assert receipt["outcome"] == reported
    assert receipt["execution_occurred"] is executed
    assert receipt["extensions"]["effect"] == evidence
    with pytest.raises(ValueError, match="differs"):
        edge.construct_receipt(
            replace(request, target="different-payment"),
            result,
            effect_evidence=evidence,
        )
    with pytest.raises(ValueError):
        edge.construct_receipt(
            request,
            result,
            effect_evidence={**evidence, "effect_id": "effect_" + "f" * 64},
        )
    with pytest.raises(ValueError):
        edge.construct_receipt(
            request, result, outcome="failed", effect_evidence=evidence
        )


@pytest.mark.parametrize("surface", ["boundary", "sdk"])
def test_configured_effect_edge_cannot_be_downgraded_by_omitting_reference(
    tmp_path, case, surface
):
    intent, context, _, verifier, mint = case
    claims = []
    proof = mint(effect=None)
    protector = EffectProtector(
        "merchant:acme", lambda _r, _q: claims.append(True) or True
    )
    assert not edge_verify(
        surface, tmp_path, verifier, intent, proof, context, protector
    )
    assert claims == []
