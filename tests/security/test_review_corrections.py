"""Regression tests for F11, R2/F06, R9/F12, and actenon_kernel entrypoint."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from actenon.boundary import BoundaryVerificationRequest, BoundaryVerifier
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.models import ActionSpec
from actenon.proof import PCCBVerifier
from actenon.receipts import InMemoryOutcomeWriter
from actenon.replay import SqliteReplayStore
from actenon.verifier.endpoint import PythonProtectedEndpoint
from actenon_kernel import ActenonGate, verify_pccb
from tests.security.helpers import (
    NOW,
    build_security_context,
    build_security_intent,
    mint_security_pccb,
    security_signer,
)


def _load_coherence_module():
    script_path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "check_version_coherence.py"
    )
    spec = importlib.util.spec_from_file_location("check_version_coherence", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_python_protected_endpoint_refuses_untrusted_intent_capability_fallback(tmp_path: Path) -> None:
    """F11: PythonProtectedEndpoint must never derive scope_capabilities from intent."""
    signer = security_signer()
    intent = build_security_intent(capability="database.drop")
    context = build_security_context(scope_capabilities=("database.drop",))
    pccb = mint_security_pccb(intent=intent, context=context, signer=signer, escrow_id=None)

    endpoint_unscoped = PythonProtectedEndpoint(
        signer=signer,
        escrow=InMemoryCapabilityEscrow(),
        replay_store=SqliteReplayStore(tmp_path / "replay1.db"),
        outcome_writer=InMemoryOutcomeWriter(),
    )
    with pytest.raises(ValueError, match="requires explicit non-empty trusted scope_capabilities"):
        endpoint_unscoped.build_request(
            intent=intent,
            pccb=pccb,
            request_id="req_f11_unscoped",
            audience=context.audience,
            now=NOW,
        )

    # Configured with trusted scope ("payment.release",), a proof for "database.drop" is refused.
    endpoint_scoped = PythonProtectedEndpoint(
        signer=signer,
        escrow=InMemoryCapabilityEscrow(),
        replay_store=SqliteReplayStore(tmp_path / "replay2.db"),
        outcome_writer=InMemoryOutcomeWriter(),
        scope_capabilities=("payment.release",),
    )
    req = endpoint_scoped.build_request(
        intent=intent,
        pccb=pccb,
        request_id="req_f11_scoped",
        audience=context.audience,
        now=NOW,
    )
    assert req.context.scope_capabilities == ("payment.release",)


def test_boundary_verifier_binds_trusted_scope_capabilities_not_intent_capability(tmp_path: Path) -> None:
    """F11: BoundaryVerifier must not inject intent.action.capability as trusted scope."""
    signer = security_signer()
    base_intent = build_security_intent(capability="database.drop")
    # Attacker sets action.name="payment.release" to match boundary action_type,
    # while keeping action.capability="database.drop" and a valid proof for "database.drop".
    spoofed_intent = replace(
        base_intent,
        action=ActionSpec(
            name="payment.release",
            capability="database.drop",
            parameters=base_intent.action.parameters,
            constraints=base_intent.action.constraints,
        ),
    )
    drop_context = build_security_context(scope_capabilities=("database.drop",))
    pccb = mint_security_pccb(
        intent=spoofed_intent,
        context=drop_context,
        signer=signer,
        capabilities=("database.drop",),
    )

    boundary = BoundaryVerifier(
        pccb_verifier=PCCBVerifier(signer),
        replay_store=SqliteReplayStore(tmp_path / "boundary.db"),
        scope_capabilities=("payment.release",),
    )
    request = BoundaryVerificationRequest(
        proof_token=json.dumps(pccb.to_dict()),
        action_type="payment.release",
        action_hash=pccb.action_hash.value,
        audience="service:payment-release-endpoint",
        boundary_id="payments",
        target=spoofed_intent.target.resource_id,
        intent=spoofed_intent.to_dict(),
        now=NOW,
    )
    result = boundary.verify_boundary(request)
    assert result.valid is False
    assert result.refusal_code == "ACTION_MISMATCH"


def test_actenon_kernel_verify_pccb_fails_closed_and_verifies_valid_proof() -> None:
    """actenon_kernel.verify_pccb fails closed on missing/mismatched inputs and verifies valid proof."""
    assert ActenonGate is not None
    with pytest.raises(PermissionError, match="PCCB_REQUIRED"):
        verify_pccb(None, None, action="payment.release")

    signer = security_signer()
    intent = build_security_intent(capability="payment.release")
    context = build_security_context(scope_capabilities=("payment.release",))
    pccb = mint_security_pccb(intent=intent, context=context, signer=signer)

    with pytest.raises(PermissionError, match="ISSUER_UNTRUSTED"):
        verify_pccb(pccb, intent, action="payment.release")

    with pytest.raises(PermissionError, match="ACTION_MISMATCH"):
        verify_pccb(
            pccb,
            intent,
            action="database.drop",
            verifier=signer,
            context=context,
        )

    assert (
        verify_pccb(
            pccb,
            intent,
            action="payment.release",
            verifier=signer,
            context=context,
        )
        is True
    )


def test_kernel_version_coherence_requires_structured_waiver(tmp_path: Path) -> None:
    """R2/F06: FINDINGS.md substring check is replaced by structured version-waiver validation."""
    mod = _load_coherence_module()
    Version = mod.Version
    findings = tmp_path / "FINDINGS.md"
    findings.write_text("Do not publish 1.3.0 yet; 11.3.0 is unrelated.\n", encoding="utf-8")
    ok, _ = mod.validate_staged_candidate_waiver(
        "actenon-kernel",
        Version("1.3.0"),
        Version("1.2.1"),
        findings_path=findings,
        today=date(2026, 10, 28),
    )
    assert ok is False

    repo_findings = Path(__file__).resolve().parents[2] / "FINDINGS.md"
    ok_repo, info_repo = mod.validate_staged_candidate_waiver(
        "actenon-kernel",
        Version("1.3.0"),
        Version("1.2.1"),
        findings_path=repo_findings,
        today=date(2026, 10, 28),
    )
    assert ok_repo is True
    assert isinstance(info_repo, dict)
    assert info_repo["status"] == "RELEASE_BLOCKED"
