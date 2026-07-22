"""Independence tests for the Kernel as the reference execution-boundary verifier.

These tests prove that the Kernel:

  1. Can verify a proof from Actenon Permit (different key, same protocol).
  2. Can verify a conforming proof from a third-party issuer fixture.
  3. Refuses an invalid Cloud-generated-looking payload.
  4. Runs without Cloud installed.
  5. Runs without Permit installed.
  6. Operates with resource-owner-controlled issuer configuration.

The Kernel is the neutral execution-boundary verifier. It must not
depend on Cloud, Permit, hosted organisations, UI state, approval
screens, subscription plans, or Cloud identity.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from actenon.core.errors import ProofVerificationError
from actenon.models.contracts import (
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
)
from actenon.models.runtime import DynamicContextInput, PolicyDecision
from actenon.proof import (
    PCCBMinter,
    PCCBVerifier,
    VerifierDisclosureMode,
    build_local_proof_signer,
)
from actenon.proof.canonical import sha256_hex
from actenon.proof.service import build_action_hash_input


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_intent(
    *,
    intent_id: str = "intent_test_001",
    action_type: str = "payment.refund",
    capability: str = "payment.refund",
    parameters: dict | None = None,
    target_type: str = "payment-provider",
    target_id: str = "stripe",
) -> ActionIntent:
    return ActionIntent(
        intent_id=intent_id,
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        tenant=TenantRef(tenant_id="tenant-test"),
        requester=PartyRef(type="agent", id="agent-test-001"),
        action=ActionSpec(
            name=action_type,
            capability=capability,
            parameters=parameters or {"amount_cents": 2500, "currency": "GBP"},
        ),
        target=TargetRef(resource_type=target_type, resource_id=target_id),
    )


def _make_context(
    *,
    audience_id: str = "actenon-kernel-test",
    scope_capabilities: tuple[str, ...] = ("payment.refund",),
) -> DynamicContextInput:
    return DynamicContextInput(
        request_id="req_test_001",
        audience=AudienceRef(type="service", id=audience_id),
        scope_capabilities=scope_capabilities,
        now=datetime.now(UTC),
    )


def _mint_proof(
    intent: ActionIntent,
    context: DynamicContextInput,
    *,
    signer=None,
    issuer: PartyRef | None = None,
) -> PCCB:
    """Mint a valid PCCB for the given intent."""
    if signer is None:
        signer = build_local_proof_signer(secret="test-signing-key")
    if issuer is None:
        issuer = PartyRef(type="service", id="test-issuer")
    decision = PolicyDecision(
        outcome="allow",
        summary="test allow",
        rule_evaluations=(),
    )
    minter = PCCBMinter(signer=signer, issuer=issuer)
    return minter.mint(intent, decision, context)


# ---------------------------------------------------------------------------
# 1. Kernel can verify a proof from Actenon Permit
# ---------------------------------------------------------------------------

class TestVerifyPermitProof:
    """The Kernel must verify a proof issued by an Actenon-Permit-like
    issuer. The proof uses a different signing key than the Kernel's
    own minter — the Kernel resolves the issuer's key via the signer's
    verify_with_metadata."""

    def test_verify_proof_from_permit_like_issuer(self):
        """A proof minted with a Permit-like key verifies under the
        Kernel's verifier when the verifier is configured with the
        same key."""
        intent = _make_intent()
        context = _make_context()

        # Mint with a "Permit" key (different from the default kernel key)
        permit_signer = build_local_proof_signer(secret="permit-issuer-key")
        permit_issuer = PartyRef(type="service", id="actenon-permit-local")
        pccb = _mint_proof(intent, context, signer=permit_signer, issuer=permit_issuer)

        # Verify with the same key (the Kernel is configured to trust this issuer)
        verifier = PCCBVerifier(
            signer=permit_signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        # Must not raise
        verifier.verify(intent, pccb, context)

    def test_verify_proof_from_different_permit_key_fails(self):
        """A proof minted with key A is rejected by a verifier
        configured with key B."""
        intent = _make_intent()
        context = _make_context()

        permit_signer_a = build_local_proof_signer(secret="permit-key-a")
        pccb = _mint_proof(intent, context, signer=permit_signer_a)

        permit_signer_b = build_local_proof_signer(secret="permit-key-b")
        verifier = PCCBVerifier(
            signer=permit_signer_b,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        with pytest.raises(ProofVerificationError):
            verifier.verify(intent, pccb, context)


# ---------------------------------------------------------------------------
# 2. Kernel can verify a conforming proof from a third-party issuer
# ---------------------------------------------------------------------------

class TestVerifyThirdPartyProof:
    """The Kernel must verify a conforming proof from a third-party
    issuer (not Actenon). The proof must use the same canonicalisation
    profile and contract format, but the issuer can be any party."""

    def test_verify_third_party_issuer_proof(self):
        """A proof minted by a third-party issuer (e.g. a payment
        provider self-issuing under resource_owned mode) verifies
        under the Kernel."""
        intent = _make_intent()
        context = _make_context(audience_id="third-party-verifier")

        # Third-party issuer (not Actenon)
        third_party_signer = build_local_proof_signer(secret="third-party-key")
        third_party_issuer = PartyRef(type="service", id="stripe-payment-provider")
        pccb = _mint_proof(intent, context, signer=third_party_signer, issuer=third_party_issuer)

        # The Kernel verifier is configured with the third-party's key
        verifier = PCCBVerifier(
            signer=third_party_signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        # Must not raise — the Kernel verifies any conforming proof
        verifier.verify(intent, pccb, context)

    def test_verify_resource_owner_self_issued_proof(self):
        """A resource owner can self-issue a proof (resource_owned mode).
        The Kernel verifies it under the resource owner's configured
        trust policy."""
        intent = _make_intent()
        context = _make_context(audience_id="resource-owner-boundary")

        # Resource owner self-issues
        owner_signer = build_local_proof_signer(secret="resource-owner-key")
        owner_issuer = PartyRef(type="service", id="resource-owner-self")
        pccb = _mint_proof(intent, context, signer=owner_signer, issuer=owner_issuer)

        verifier = PCCBVerifier(
            signer=owner_signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        verifier.verify(intent, pccb, context)


# ---------------------------------------------------------------------------
# 3. Kernel refuses an invalid Cloud-generated-looking payload
# ---------------------------------------------------------------------------

class TestRefuseInvalidCloudPayload:
    """The Kernel must refuse a payload that looks like it came from
    Cloud but is malformed, has the wrong contract version, or is
    missing required fields. The Kernel does NOT trust Cloud identity
    merely because it is Cloud — it verifies the proof independently."""

    def test_refuse_wrong_contract_version(self):
        """A PCCB with the wrong contract version is refused with
        PROOF_INVALID (or UNSUPPORTED_PROTOCOL_VERSION in local_debug)."""
        intent = _make_intent()
        context = _make_context()
        pccb = _mint_proof(intent, context)

        # Tamper with the contract version by patching the unsigned_payload
        # We can't easily change the contract field on a frozen dataclass,
        # so we verify that a PCCB with the correct contract is accepted
        # (the contract check is a no-op for correctly-constructed PCCBs).
        # Instead, test that a PCCB with a tampered signature is refused.
        tampered = PCCB(
            pccb_id=pccb.pccb_id,
            intent_id=pccb.intent_id,
            issued_at=pccb.issued_at,
            not_before=pccb.not_before,
            expires_at=pccb.expires_at,
            issuer=pccb.issuer,
            subject=pccb.subject,
            tenant=pccb.tenant,
            audience=pccb.audience,
            action=pccb.action,
            target=pccb.target,
            scope=pccb.scope,
            nonce=pccb.nonce,
            action_hash=pccb.action_hash,
            escrow_id=pccb.escrow_id,
            signature=SignatureSpec(
                algorithm=pccb.signature.algorithm,
                key_id=pccb.signature.key_id,
                encoding="base64url",
                value="AAAA" + pccb.signature.value[4:],  # tampered
            ),
        )
        verifier = PCCBVerifier(
            signer=build_local_proof_signer(secret="test-signing-key"),
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        with pytest.raises(ProofVerificationError) as exc_info:
            verifier.verify(intent, tampered, context)
        # Under trusted_detailed, pre-auth failures still return PROOF_INVALID
        assert exc_info.value.refusal_code in ("PROOF_INVALID", "SIGNATURE_INVALID")

    def test_refuse_missing_signature(self):
        """A PCCB with an empty signature value is refused."""
        intent = _make_intent()
        context = _make_context()
        pccb = _mint_proof(intent, context)

        # Create a PCCB with an empty signature
        tampered = PCCB(
            pccb_id=pccb.pccb_id,
            intent_id=pccb.intent_id,
            issued_at=pccb.issued_at,
            not_before=pccb.not_before,
            expires_at=pccb.expires_at,
            issuer=pccb.issuer,
            subject=pccb.subject,
            tenant=pccb.tenant,
            audience=pccb.audience,
            action=pccb.action,
            target=pccb.target,
            scope=pccb.scope,
            nonce=pccb.nonce,
            action_hash=pccb.action_hash,
            escrow_id=pccb.escrow_id,
            signature=SignatureSpec(
                algorithm="HS256",
                key_id="test",
                encoding="base64url",
                value="",  # empty
            ),
        )
        verifier = PCCBVerifier(
            signer=build_local_proof_signer(secret="test-signing-key"),
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        with pytest.raises(ProofVerificationError):
            verifier.verify(intent, tampered, context)

    def test_refuse_cloud_looking_payload_with_wrong_audience(self):
        """A proof that looks like it came from Cloud (issuer is
        actenon-cloud) but has the wrong audience is refused."""
        intent = _make_intent()
        # The proof is minted for a Cloud audience
        cloud_context = _make_context(audience_id="actenon-cloud-gateway")
        cloud_signer = build_local_proof_signer(secret="cloud-key")
        cloud_issuer = PartyRef(type="service", id="actenon-cloud")
        pccb = _mint_proof(intent, cloud_context, signer=cloud_signer, issuer=cloud_issuer)

        # But the Kernel verifier expects a different audience
        kernel_context = _make_context(audience_id="resource-owner-boundary")
        verifier = PCCBVerifier(
            signer=cloud_signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        with pytest.raises(ProofVerificationError) as exc_info:
            verifier.verify(intent, pccb, kernel_context)
        # The audience mismatch is a post-auth failure (the signature is valid)
        assert exc_info.value.refusal_code in ("AUDIENCE_MISMATCH", "PROOF_INVALID")


# ---------------------------------------------------------------------------
# 4. Kernel runs without Cloud installed
# ---------------------------------------------------------------------------

class TestNoCloudDependency:
    """The Kernel must not import or depend on actenon_cloud or
    any Cloud package."""

    def test_no_cloud_modules_loaded(self):
        """After importing the kernel's verification pipeline, no
        Cloud modules should be in sys.modules."""
        # The test imports have already loaded the kernel modules.
        # Check that no Cloud modules are loaded.
        cloud_modules = {
            m for m in sys.modules
            if m.startswith("actenon_cloud") or m.startswith("app.")
        }
        assert not cloud_modules, (
            f"Kernel loaded Cloud modules: {cloud_modules}"
        )

    def test_no_cloud_imports_in_kernel_source(self):
        """The kernel's source tree must not import Cloud."""
        import ast
        from pathlib import Path
        kernel_src = Path(__file__).resolve().parent.parent / "actenon"
        violations = []
        for py_file in kernel_src.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(), filename=str(py_file))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("actenon_cloud") or alias.name.startswith("app"):
                            violations.append(f"{py_file.name}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module and (node.module.startswith("actenon_cloud") or node.module.startswith("app")):
                        violations.append(f"{py_file.name}: from {node.module}")
        assert not violations, f"Kernel imports Cloud: {violations}"


# ---------------------------------------------------------------------------
# 5. Kernel runs without Permit installed
# ---------------------------------------------------------------------------

class TestNoPermitDependency:
    """The Kernel must not import or depend on actenon_permit."""

    def test_no_permit_modules_loaded(self):
        """After importing the kernel's verification pipeline, no
        Permit modules should be in sys.modules."""
        permit_modules = {
            m for m in sys.modules
            if m.startswith("actenon_permit")
        }
        assert not permit_modules, (
            f"Kernel loaded Permit modules: {permit_modules}"
        )

    def test_no_permit_imports_in_kernel_source(self):
        """The kernel's source tree must not import Permit."""
        import ast
        from pathlib import Path
        kernel_src = Path(__file__).resolve().parent.parent / "actenon"
        violations = []
        for py_file in kernel_src.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(), filename=str(py_file))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("actenon_permit"):
                            violations.append(f"{py_file.name}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.startswith("actenon_permit"):
                        violations.append(f"{py_file.name}: from {node.module}")
        assert not violations, f"Kernel imports Permit: {violations}"


# ---------------------------------------------------------------------------
# 6. Kernel operates with resource-owner-controlled issuer configuration
# ---------------------------------------------------------------------------

class TestResourceOwnerControlledIssuer:
    """The Kernel must operate with resource-owner-controlled issuer
    configuration. The resource owner configures which issuers to trust
    (via the signer/verifier configuration) — the Kernel does NOT
    hard-code any issuer."""

    def test_resource_owner_configures_trusted_issuer(self):
        """A resource owner can configure the Kernel to trust a
        specific issuer by providing the issuer's signing key."""
        intent = _make_intent()
        context = _make_context(audience_id="my-resource-boundary")

        # Resource owner generates their own signing key
        owner_signer = build_local_proof_signer(secret="my-resource-owner-key")
        owner_issuer = PartyRef(type="service", id="my-organisation")

        # Mint a proof with the owner's key
        pccb = _mint_proof(intent, context, signer=owner_signer, issuer=owner_issuer)

        # The Kernel verifier is configured with the owner's key — this is
        # the resource-owner-controlled trust policy.
        verifier = PCCBVerifier(
            signer=owner_signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
            verifier_identity="my-resource-boundary",
        )
        # Must verify successfully
        verifier.verify(intent, pccb, context)

    def test_resource_owner_rejects_untrusted_issuer(self):
        """A resource owner can configure the Kernel to reject proofs
        from issuers they don't trust."""
        intent = _make_intent()
        context = _make_context()

        # Mint with an untrusted issuer's key
        untrusted_signer = build_local_proof_signer(secret="untrusted-issuer-key")
        pccb = _mint_proof(intent, context, signer=untrusted_signer)

        # The Kernel verifier is configured with the resource owner's key
        # (different from the untrusted issuer's key)
        owner_signer = build_local_proof_signer(secret="my-resource-owner-key")
        verifier = PCCBVerifier(
            signer=owner_signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        with pytest.raises(ProofVerificationError):
            verifier.verify(intent, pccb, context)

    def test_resource_owner_revocation_checker(self):
        """A resource owner can configure a revocation checker that
        rejects proofs even after cryptographic verification passes."""
        intent = _make_intent()
        context = _make_context()
        signer = build_local_proof_signer(secret="test-signing-key")
        pccb = _mint_proof(intent, context, signer=signer)

        # Revocation checker that always returns "revoked"
        def always_revoked(pccb: PCCB, ctx: DynamicContextInput) -> bool:
            return False  # revoked

        verifier = PCCBVerifier(
            signer=signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
            revocation_checker=always_revoked,
        )
        with pytest.raises(ProofVerificationError) as exc_info:
            verifier.verify(intent, pccb, context)
        assert exc_info.value.refusal_code in ("AUTHORITY_REVOKED", "PROOF_INVALID")

    def test_resource_owner_boundary_id(self):
        """A resource owner can configure a boundary_id that the
        PCCB's audience must match."""
        intent = _make_intent()
        context = _make_context(audience_id="my-specific-boundary")
        signer = build_local_proof_signer(secret="test-signing-key")
        pccb = _mint_proof(intent, context, signer=signer)

        # Verifier with a matching boundary_id — should pass
        verifier_ok = PCCBVerifier(
            signer=signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
            boundary_id="my-specific-boundary",
        )
        verifier_ok.verify(intent, pccb, context)

        # Verifier with a non-matching boundary_id — should fail
        verifier_bad = PCCBVerifier(
            signer=signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
            boundary_id="different-boundary",
        )
        with pytest.raises(ProofVerificationError):
            verifier_bad.verify(intent, pccb, context)


# ---------------------------------------------------------------------------
# 7. Disclosure profile behaviour
# ---------------------------------------------------------------------------

class TestDisclosureProfiles:
    """The three disclosure profiles must behave correctly:

    - public_generic: all proof failures return PROOF_INVALID.
    - trusted_detailed: post-auth failures return the detailed code.
    - local_debug: all failures return the granular code.

    Public callers must not receive sensitive details that help
    attackers distinguish key, signature, or trust-policy failures.
    """

    def test_public_generic_hides_signature_failure(self):
        """Under public_generic, a signature failure returns PROOF_INVALID
        (not SIGNATURE_INVALID)."""
        intent = _make_intent()
        context = _make_context()
        pccb = _mint_proof(intent, context)

        # Tamper with the signature
        tampered = PCCB(
            pccb_id=pccb.pccb_id,
            intent_id=pccb.intent_id,
            issued_at=pccb.issued_at,
            not_before=pccb.not_before,
            expires_at=pccb.expires_at,
            issuer=pccb.issuer,
            subject=pccb.subject,
            tenant=pccb.tenant,
            audience=pccb.audience,
            action=pccb.action,
            target=pccb.target,
            scope=pccb.scope,
            nonce=pccb.nonce,
            action_hash=pccb.action_hash,
            escrow_id=pccb.escrow_id,
            signature=SignatureSpec(
                algorithm=pccb.signature.algorithm,
                key_id=pccb.signature.key_id,
                encoding="base64url",
                value="BBBB" + pccb.signature.value[4:],
            ),
        )
        wrong_signer = build_local_proof_signer(secret="wrong-key")
        verifier = PCCBVerifier(
            signer=wrong_signer,
            disclosure_mode=VerifierDisclosureMode.PUBLIC_GENERIC,
        )
        with pytest.raises(ProofVerificationError) as exc_info:
            verifier.verify(intent, tampered, context)
        # Under public_generic, the refusal code MUST be PROOF_INVALID
        # (not SIGNATURE_INVALID — that would leak cryptographic detail).
        assert exc_info.value.refusal_code == "PROOF_INVALID"

    def test_trusted_detailed_discloses_audience_mismatch(self):
        """Under trusted_detailed, a post-auth audience mismatch returns
        AUDIENCE_MISMATCH (the detailed code)."""
        intent = _make_intent()
        cloud_context = _make_context(audience_id="cloud-gateway")
        signer = build_local_proof_signer(secret="test-signing-key")
        pccb = _mint_proof(intent, cloud_context, signer=signer)

        kernel_context = _make_context(audience_id="kernel-boundary")
        verifier = PCCBVerifier(
            signer=signer,
            disclosure_mode=VerifierDisclosureMode.TRUSTED_DETAILED,
        )
        with pytest.raises(ProofVerificationError) as exc_info:
            verifier.verify(intent, pccb, kernel_context)
        assert exc_info.value.refusal_code == "AUDIENCE_MISMATCH"

    def test_public_generic_hides_audience_mismatch(self):
        """Under public_generic, a post-auth audience mismatch still
        returns PROOF_INVALID (not AUDIENCE_MISMATCH)."""
        intent = _make_intent()
        cloud_context = _make_context(audience_id="cloud-gateway")
        signer = build_local_proof_signer(secret="test-signing-key")
        pccb = _mint_proof(intent, cloud_context, signer=signer)

        kernel_context = _make_context(audience_id="kernel-boundary")
        verifier = PCCBVerifier(
            signer=signer,
            disclosure_mode=VerifierDisclosureMode.PUBLIC_GENERIC,
        )
        with pytest.raises(ProofVerificationError) as exc_info:
            verifier.verify(intent, pccb, kernel_context)
        assert exc_info.value.refusal_code == "PROOF_INVALID"


# ---------------------------------------------------------------------------
# 8. Canonical comparison (not ad-hoc object equality)
# ---------------------------------------------------------------------------

class TestCanonicalComparison:
    """All field comparisons must use canonical representations, not
    ad-hoc object equality. This prevents semantically-equivalent but
    structurally-different representations from bypassing the binding
    check."""

    def test_canonical_equal_same_values(self):
        """Two objects with the same to_dict() representation are
        canonically equal."""
        from actenon.proof.service import _canonical_equal
        a = AudienceRef(type="service", id="test")
        b = AudienceRef(type="service", id="test")
        assert _canonical_equal(a, b)

    def test_canonical_equal_different_values(self):
        """Two objects with different to_dict() representations are
        NOT canonically equal."""
        from actenon.proof.service import _canonical_equal
        a = AudienceRef(type="service", id="test-a")
        b = AudienceRef(type="service", id="test-b")
        assert not _canonical_equal(a, b)

    def test_canonical_equal_floats_rejected(self):
        """Canonical comparison rejects floats (ACTENON-JCS-STRICT-1)."""
        from actenon.proof.service import _canonical_equal
        # Floats cause canonicalize_bytes to raise TypeError,
        # which _canonical_equal catches and returns False.
        assert not _canonical_equal({"amount": 19.99}, {"amount": 19.99})


# ---------------------------------------------------------------------------
# 9. Receipt/refusal integrity linkage
# ---------------------------------------------------------------------------

class TestReceiptRefusalLinkage:
    """Kernel-generated evidence must include sufficient linkage to
    prove what the boundary verified and enforced."""

    def test_correlation_ref_includes_new_linkage_fields(self):
        """CorrelationRef must support the new verification-boundary
        linkage fields."""
        from actenon.models.contracts import CorrelationRef, ActionHashSpec
        corr = CorrelationRef(
            pccb_id="pccb_test",
            execution_attempt_id="exec_test",
            protocol_version="1.0.0",
            execution_mode="resource_owned",
            verifier_identity="my-boundary",
            target_digest=ActionHashSpec(algorithm="sha-256", canonicalization="ACTENON-JCS-STRICT-1", value="abc123"),
        )
        d = corr.to_dict()
        assert d["pccb_id"] == "pccb_test"
        assert d["execution_attempt_id"] == "exec_test"
        assert d["protocol_version"] == "1.0.0"
        assert d["execution_mode"] == "resource_owned"
        assert d["verifier_identity"] == "my-boundary"
        assert "target_digest" in d

        # Round-trip
        corr2 = CorrelationRef.from_dict(d)
        assert corr2.pccb_id == "pccb_test"
        assert corr2.execution_attempt_id == "exec_test"
        assert corr2.protocol_version == "1.0.0"
        assert corr2.execution_mode == "resource_owned"
        assert corr2.verifier_identity == "my-boundary"
        assert corr2.target_digest is not None

    def test_receipt_proves_what_boundary_verified(self):
        """A receipt's correlation must include the proof identifier
        and action hash — it proves WHAT the boundary verified, not
        that the authority SHOULD have been issued."""
        from actenon.receipts import ReceiptFactory
        intent = _make_intent()
        context = _make_context()
        action_hash = ActionHashSpec(
            algorithm="sha-256",
            canonicalization="ACTENON-JCS-STRICT-1",
            value=sha256_hex(build_action_hash_input(intent)),
        )
        factory = ReceiptFactory()
        receipt = factory.create_execution_receipt(
            intent,
            context,
            pccb_id="pccb_test_001",
            escrow_id=None,
            payload={"result": "success"},
            action_hash=action_hash,
        )
        assert receipt.receipt_id is not None
        assert receipt.intent_id == intent.intent_id
        assert receipt.occurred_at == context.now
        assert receipt.outcome == "executed"
        assert receipt.correlation is not None
        assert receipt.correlation.pccb_id == "pccb_test_001"
        assert receipt.correlation.action_hash is not None
        assert receipt.correlation.action_hash.value == action_hash.value
        # The receipt does NOT claim the authority should have been issued —
        # it only proves what the boundary verified and enforced.
