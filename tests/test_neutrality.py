"""WO-9 invariant: verification makes no network calls.

Fable 5 Part 3B: "independent verification at the edge (no network call,
no vendor, fail-closed)" is one of the two properties that does all the
work in the north star. This test makes it executable.

The test runs a FULL successful verification (not a stub) with socket
connect calls monkeypatched to raise AssertionError. If any verification
path attempts a network call, the test fails.

DISCOVERY POINT (from the work order):
  The kernel has a well-known key resolver
  (actenon/proof/signers/well_known.py) that fetches keys over HTTPS.
  If ANY verification path fetches a key over the network, that path is
  not offline-verifiable.

FINDING:
  The symmetric (HMAC) verification path is fully offline — it uses a
  shared secret, no key resolution. The asymmetric (Ed25519) path has
  two modes:
    1. Inline key (the public key is provided directly to the verifier) —
       offline. This test uses a local Ed25519 keypair with a custom
       ExternalManagedSigningBackend that signs/verifies in-process.
    2. Well-known key resolution (the verifier fetches
       https://{issuer}/.well-known/actenon/keys.json) — REQUIRES NETWORK.

  This test covers the offline paths (symmetric HMAC + asymmetric with
  inline key). The well-known resolution path is documented in
  FINDINGS.md as requiring network, and is NOT covered by this test
  (it would fail by design).

  This is the honest answer: the "verify without trusting Actenon" claim
  is true for the offline paths. The well-known resolution path is a
  convenience that trades offline-verification for automatic key
  distribution. Operators who need the offline guarantee must provision
  keys inline (see docs/PRODUCTION_INTEGRATION.md §3.1).
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta

import pytest

from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.models.runtime import PolicyDecision
from actenon.proof import PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.proof.service import DynamicContextInput


def _block_network(monkeypatch):
    """Monkeypatch socket connect to raise AssertionError."""
    def _blocked(*a, **k):
        raise AssertionError("verification attempted a network call")
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)


def _make_intent() -> ActionIntent:
    now = datetime.now(UTC)
    return ActionIntent(
        intent_id="intent_test_offline_001",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        tenant=TenantRef(tenant_id="tenant:test"),
        requester=PartyRef(type="agent", id="agent:local:test"),
        action=ActionSpec(
            name="payment.refund",
            capability="payment.refund",
            parameters={"amount_cents": 2500, "currency": "GBP"},
        ),
        target=TargetRef(resource_type="payment_intent", resource_id="pi_test_001"),
    )


def _make_context() -> DynamicContextInput:
    return DynamicContextInput(
        request_id="req_test_offline_001",
        audience=AudienceRef(type="service", id="service:payments"),
        scope_capabilities=("payment.refund",),
        now=datetime.now(UTC),
    )


def _make_allow_decision() -> PolicyDecision:
    return PolicyDecision(
        outcome="allow",
        summary="Test allow decision for offline verification.",
        rule_evaluations=(),
        reason_codes=("TEST_ALLOW",),
    )


class TestSymmetricVerificationIsOffline:
    """The HMAC (symmetric) verification path must make no network calls."""

    def test_symmetric_verification_makes_no_network_calls(self, monkeypatch):
        _block_network(monkeypatch)

        signer = build_local_proof_signer()
        minter = PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="agent", id="agent:local:test"),
        )
        intent = _make_intent()
        context = _make_context()
        decision = _make_allow_decision()

        pccb = minter.mint(intent, decision, context)

        verifier = PCCBVerifier(signer=signer)
        # This MUST not raise AssertionError from the socket monkeypatch.
        # If it passes, the symmetric path is fully offline.
        verifier.verify(intent, pccb, context)


class TestAsymmetricInlineKeyVerificationIsOffline:
    """The Ed25519 (asymmetric) path with an inline-provided key must
    make no network calls.

    This test uses a local Ed25519 keypair with an in-process
    ExternalManagedSigningBackend. No well-known fetch, no KMS, no
    network. This is the production path for operators who need the
    offline-verification guarantee.
    """

    def test_asymmetric_inline_key_verification_makes_no_network_calls(self, monkeypatch):
        pytest.importorskip("cryptography")  # asymmetric requires the optional extra
        _block_network(monkeypatch)

        from dataclasses import dataclass
        from actenon.proof.signers.external_managed import (
            ACTIVE_KEY_STATUS,
            ExternalManagedSigner,
            ExternalManagedSigningBackend,
            ManagedKeyReference,
            ManagedSigningResult,
            PROOF_ISSUANCE_PURPOSE,
        )
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from actenon.proof.signers.base import b64url_encode

        # Generate a local Ed25519 keypair (no network).
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = "issuer:prod:2026-07"

        @dataclass(frozen=True)
        class LocalEd25519Backend(ExternalManagedSigningBackend):
            """In-process Ed25519 backend — no network, no KMS."""

            priv: object
            pub: object

            def get_key_status(self, *, key):
                return ACTIVE_KEY_STATUS

            def sign_canonical_bytes(self, *, key, payload, audit_metadata):
                sig = self.priv.sign(payload)
                return ManagedSigningResult(
                    algorithm=key.algorithm,
                    key_id=key.key_id,
                    signature=sig,
                    public_key_ref=key.public_key_ref or "local-ed25519",
                    provider_operation_id="local-ed25519-sign",
                )

            def verify_canonical_bytes(self, *, key, payload, signature):
                try:
                    self.pub.verify(signature, payload)
                    return True
                except Exception:
                    return False

        backend = LocalEd25519Backend(priv=private_key, pub=public_key)
        key_ref = ManagedKeyReference(
            provider="local-ed25519",
            provider_key_ref="local-ed25519-key",
            key_id=key_id,
            algorithm="EdDSA",
            purpose=PROOF_ISSUANCE_PURPOSE,
            tenant_id="tenant:test",
            public_key_ref="local-ed25519",
            key_version="2026-07",
            status=ACTIVE_KEY_STATUS,
        )
        signer = ExternalManagedSigner(backend=backend, key=key_ref)

        minter = PCCBMinter(
            signer=signer,
            issuer=PartyRef(type="agent", id="agent:local:test"),
        )
        intent = _make_intent()
        context = _make_context()
        decision = _make_allow_decision()

        pccb = minter.mint(intent, decision, context)

        # The verifier uses the public key directly — no well-known fetch.
        verifier = PCCBVerifier(signer=signer)
        verifier.verify(intent, pccb, context)


class TestWellKnownKeyResolutionRequiresNetwork:
    """The well-known key resolution path REQUIRES network by design.

    This test documents the finding: the WellKnownKeySignatureVerifier
    fetches keys from https://{issuer}/.well-known/actenon/keys.json.
    It is NOT an offline path. Operators who need the offline guarantee
    must provision keys inline.

    This test does NOT run a full verification with network blocked —
    it would fail by design. Instead, it asserts that the resolver class
    exists and documents the network requirement.
    """

    def test_well_known_resolver_exists(self):
        """The well-known resolver is a real class that operators can use."""
        from actenon.proof.signers.well_known import WellKnownKeySignatureVerifier
        assert WellKnownKeySignatureVerifier is not None

    def test_well_known_resolver_imports_urllib(self):
        """The well-known resolver module imports urllib — proof it can fetch."""
        import actenon.proof.signers.well_known as wk
        # The module uses urllib.request.build_opener for HTTPS fetches.
        assert hasattr(wk, "build_opener")
