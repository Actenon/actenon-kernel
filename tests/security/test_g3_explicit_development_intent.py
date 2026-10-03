"""G3: insecure development behaviour requires explicit development intent.

Without explicit development intent (``ACTENON_ENV`` in
{development, dev, local, test}, or an explicit dev entry point such as
``ActenonGate.local_dev(...)`` / ``actenon-mcp --demo`` /
``actenon-kernel conformance run``) the kernel must NOT silently use:

  1. the public development HMAC secret (``LOCAL_PROOF_SECRET``);
  2. per-process replay state for single-use guarantees;
  3. ``replay_protection="disabled"``;
  4. ``replay_store_failure="fail_open"``.

A production-name denylist is not the boundary: an unset ``ACTENON_ENV``
and an unconventional name such as ``prd`` must fail closed exactly like
``production``. Every refusal names the fix.

These tests set the environment explicitly; they never rely on the
suite-wide ``ACTENON_ENV=test`` declaration.
"""

from __future__ import annotations

import logging
import os
import warnings
from pathlib import Path
from unittest import mock

import pytest

from actenon.gate import ActenonGate
from actenon.proof import PCCBVerifier
from actenon.proof.signers.local import LOCAL_PROOF_SECRET, HmacSha256Signer, build_local_proof_signer
from tests.security.test_production_environment_paths import _Ed25519Signer

# Unset, an unconventional production name, and a known production name.
NO_INTENT_ENVS = [None, "prd", "production"]
NO_INTENT_IDS = ["unset", "prd", "production"]
DEV_ENVS = ["development", "dev", "local", "test", " Development ", "TEST"]
_CONTROLLED = (
    "ACTENON_ENV",
    "ACTENON_REPLAY_DB",
    "ACTENON_LOCAL_HMAC_SECRET",
    "ACTENON_PRODUCTION",
    "ACTENON_CI_RELEASE",
    "ACTENON_RELEASE_BUILD",
    "ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY",
    "ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED",
    "ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN",
)


def _set_env(monkeypatch: pytest.MonkeyPatch, value: str | None, **extra: str) -> None:
    for name in _CONTROLLED:
        monkeypatch.delenv(name, raising=False)
    if value is not None:
        monkeypatch.setenv("ACTENON_ENV", value)
    for name, val in extra.items():
        monkeypatch.setenv(name, val)


def _assert_names_fix(exc: BaseException, *needles: str) -> None:
    text = str(exc)
    for needle in needles:
        assert needle in text, f"refusal does not name {needle!r}: {text}"


def _gate(**kwargs) -> ActenonGate:
    signer = _Ed25519Signer()
    kwargs.setdefault("capabilities", ("payment.release",))
    return ActenonGate(verifier=signer, signer=signer, audience="service:payments", issuer="service:issuer", **kwargs)


def _action(gate: ActenonGate, intent_id: str = "intent_g3_001") -> dict:
    return gate.build_action(
        "payment.release",
        "payment.release",
        {"amount_minor": 1000, "currency": "USD"},
        target_type="payment",
        target_id="payment_001",
        intent_id=intent_id,
    )


# ---------------------------------------------------------------------------
# 1. The public development HMAC secret
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_public_secret_signer_refused_without_development_intent(monkeypatch, env):
    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError) as excinfo:
        build_local_proof_signer()
    if env != "production":
        _assert_names_fix(excinfo.value, "ACTENON_ENV=development")


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_public_secret_passed_explicitly_is_still_refused(monkeypatch, env):
    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError):
        build_local_proof_signer(LOCAL_PROOF_SECRET)
    with pytest.raises(RuntimeError):
        HmacSha256Signer(secret=LOCAL_PROOF_SECRET, key_id="local-proof-v1")


@pytest.mark.parametrize("env", [None, "prd"], ids=["unset", "prd"])
def test_caller_supplied_hmac_secret_is_not_the_public_secret(monkeypatch, env):
    # A secret the caller supplied is not development material; only the
    # public constant needs development intent.
    _set_env(monkeypatch, env)
    signer = build_local_proof_signer(b"operator-supplied-secret-0123456789")
    assert signer.secret != LOCAL_PROOF_SECRET


# ---------------------------------------------------------------------------
# 2. Per-process replay state
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_gate_default_process_local_replay_refused(monkeypatch, env):
    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError) as excinfo:
        _gate()
    _assert_names_fix(excinfo.value, "ACTENON_REPLAY_DB", "ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY")


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_protected_executor_default_process_local_replay_refused(monkeypatch, env):
    from actenon.credentials import InMemoryCredentialBroker
    from actenon.execution import ProtectedExecutor

    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError):
        ProtectedExecutor(proof_verifier=PCCBVerifier(_Ed25519Signer()), credential_broker=InMemoryCredentialBroker())


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_build_default_replay_store_refused(monkeypatch, env):
    from actenon.replay import build_default_replay_store

    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError):
        build_default_replay_store()


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_verifier_middleware_default_replay_refused(monkeypatch, env):
    from actenon.escrow import InMemoryCapabilityEscrow
    from actenon.receipts import InMemoryOutcomeWriter, ReceiptFactory, RefusalFactory
    from actenon.verifier.middleware import ProtectedEndpointMiddleware

    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError):
        ProtectedEndpointMiddleware(
            proof_verifier=PCCBVerifier(_Ed25519Signer()),
            escrow=InMemoryCapabilityEscrow(),
            receipt_factory=ReceiptFactory(),
            refusal_factory=RefusalFactory(),
            outcome_writer=InMemoryOutcomeWriter(),
        )


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_boundary_verifier_in_memory_replay_refused(monkeypatch, env):
    from actenon.boundary import BoundaryVerifier

    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError) as excinfo:
        BoundaryVerifier(pccb_verifier=PCCBVerifier(_Ed25519Signer()))
    _assert_names_fix(excinfo.value, "ACTENON_REPLAY_DB")


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_boundary_verifier_without_trust_root_still_constructs(monkeypatch, env):
    # No trust root means every proof is refused; there is no single-use
    # guarantee to downgrade, so construction stays allowed.
    from actenon.boundary import BoundaryVerifier

    _set_env(monkeypatch, env)
    assert BoundaryVerifier().health()["ok"] is False


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_mcp_server_non_demo_refuses_process_local_replay(monkeypatch, env, tmp_path):
    pytest.importorskip("mcp")
    from actenon import mcp_server

    _set_env(monkeypatch, env)
    key = tmp_path / "key"
    key.write_bytes(b"operator-supplied-mcp-secret-0123456789")
    with mock.patch("mcp.server.fastmcp.FastMCP.run", lambda self, *a, **k: None):
        with pytest.raises(SystemExit) as excinfo:
            mcp_server.main(["--key-file", str(key), "--capability", "payment.refund"])
    if env != "production":
        _assert_names_fix(excinfo.value, "ACTENON_REPLAY_DB")


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_mcp_server_non_demo_refuses_undeclared_capabilities(monkeypatch, env, tmp_path):
    # protocol/13-edge-binding.md E1: the server must say what it lets through.
    pytest.importorskip("mcp")
    from actenon import mcp_server

    _set_env(monkeypatch, env, ACTENON_REPLAY_DB=str(tmp_path / "replay.sqlite3"))
    key = tmp_path / "key"
    key.write_bytes(b"operator-supplied-mcp-secret-0123456789")
    with mock.patch("mcp.server.fastmcp.FastMCP.run", lambda self, *a, **k: None):
        with pytest.raises(SystemExit) as excinfo:
            mcp_server.main(["--key-file", str(key)])
    if env != "production":
        _assert_names_fix(excinfo.value, "--capability", "ACTENON_UNSAFE_ALLOW_UNDECLARED_CAPABILITIES")


# ---------------------------------------------------------------------------
# 3 + 4. replay_protection="disabled" and replay_store_failure="fail_open"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_replay_protection_disabled_refused(monkeypatch, env):
    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError) as excinfo:
        _gate(replay_protection="disabled")
    _assert_names_fix(excinfo.value, "ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED")


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_replay_store_fail_open_refused(monkeypatch, env, tmp_path):
    from actenon.replay import ReplayProtector, SqliteReplayStore

    _set_env(monkeypatch, env)
    with pytest.raises(RuntimeError) as excinfo:
        _gate(
            replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.sqlite3")),
            replay_store_failure="fail_open",
        )
    _assert_names_fix(excinfo.value, "ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN")


# ---------------------------------------------------------------------------
# Explicit development mechanisms keep working
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", DEV_ENVS)
def test_development_env_values_allow_every_dev_behaviour(monkeypatch, env, tmp_path):
    from actenon.boundary import BoundaryVerifier
    from actenon.replay import ReplayProtector, SqliteReplayStore, build_default_replay_store

    _set_env(monkeypatch, env)
    assert build_local_proof_signer().secret == LOCAL_PROOF_SECRET
    build_default_replay_store()
    _gate()
    _gate(replay_protection="disabled")
    _gate(
        replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "r.sqlite3")),
        replay_store_failure="fail_open",
    )
    assert BoundaryVerifier(pccb_verifier=PCCBVerifier(_Ed25519Signer())).health()["replay_store"] == "in_memory_set"


def test_local_dev_constructor_is_explicit_development_intent(monkeypatch):
    _set_env(monkeypatch, None)
    gate = ActenonGate.local_dev(audience="service:payments")
    assert gate.signer.secret == LOCAL_PROOF_SECRET
    assert "process_local_replay" in gate.security_downgrades
    # One action, minted once and presented twice (each _action() call stamps
    # fresh issued_at/expires_at, i.e. a different action hash).
    action = _action(gate)
    proof = gate.mint_proof(action)
    calls: list[int] = []
    assert gate.protect(action, proof, lambda: calls.append(1)).ok
    assert gate.protect(action, proof, lambda: calls.append(1)).reason_code == "DUPLICATE_REPLAY"
    assert calls == [1]


def test_local_dev_scope_does_not_leak(monkeypatch):
    _set_env(monkeypatch, None)
    ActenonGate.local_dev(audience="service:payments")
    with pytest.raises(RuntimeError):
        build_local_proof_signer()
    with pytest.raises(RuntimeError):
        _gate()


def test_local_dev_still_refused_in_production(monkeypatch):
    _set_env(monkeypatch, "production")
    with pytest.raises(RuntimeError):
        ActenonGate.local_dev(audience="service:payments")


def test_development_env_does_not_override_production_flag(monkeypatch):
    _set_env(monkeypatch, "development", ACTENON_PRODUCTION="1")
    with pytest.raises(RuntimeError):
        build_local_proof_signer()
    with pytest.raises(RuntimeError):
        _gate()


@pytest.mark.parametrize("env", [None, "development", "dev", "test"], ids=["unset", "development", "dev", "test"])
def test_mcp_demo_is_explicit_development_intent(monkeypatch, env):
    pytest.importorskip("mcp")
    from actenon import mcp_server

    _set_env(monkeypatch, env)
    with mock.patch("mcp.server.fastmcp.FastMCP.run", lambda self, *a, **k: None):
        assert mcp_server.main(["--demo"]) == 0


@pytest.mark.parametrize("env", ["prd", "production"])
def test_mcp_demo_refused_outside_development(monkeypatch, env):
    pytest.importorskip("mcp")
    from actenon import mcp_server

    _set_env(monkeypatch, env)
    with mock.patch("mcp.server.fastmcp.FastMCP.run", lambda self, *a, **k: None):
        with pytest.raises(SystemExit):
            mcp_server.main(["--demo"])


# ---------------------------------------------------------------------------
# Named unsafe overrides: loud and machine-visible
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", [None, "prd"], ids=["unset", "prd"])
def test_process_local_replay_override_is_loud_and_marked(monkeypatch, env, caplog):
    from actenon.boundary import BoundaryVerifier

    _set_env(monkeypatch, env, ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY="1")
    with warnings.catch_warnings(record=True) as caught, caplog.at_level(logging.WARNING):
        warnings.simplefilter("always")
        gate = _gate()
        boundary = BoundaryVerifier(pccb_verifier=PCCBVerifier(_Ed25519Signer()))
    assert "process_local_replay" in gate.security_downgrades
    assert "process_local_replay" in boundary.health()["security_downgrades"]
    assert any("ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY" in str(w.message) for w in caught)
    assert "ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY" in caplog.text


@pytest.mark.parametrize("env", [None, "prd"], ids=["unset", "prd"])
def test_replay_disabled_and_fail_open_overrides_are_marked(monkeypatch, env, tmp_path):
    from actenon.replay import ReplayProtector, SqliteReplayStore

    _set_env(
        monkeypatch,
        env,
        ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED="1",
        ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN="1",
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        disabled = _gate(replay_protection="disabled")
        fail_open = _gate(
            replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "r.sqlite3")),
            replay_store_failure="fail_open",
        )
    assert "replay_protection_disabled" in disabled.security_downgrades
    assert "replay_store_fail_open" in fail_open.security_downgrades


def test_override_does_not_unlock_the_public_secret(monkeypatch):
    _set_env(
        monkeypatch,
        None,
        ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY="1",
        ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED="1",
        ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN="1",
    )
    with pytest.raises(RuntimeError):
        build_local_proof_signer()


# ---------------------------------------------------------------------------
# A properly configured production deployment works
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_production_config_with_shared_replay_db_enforces_single_use_across_workers(monkeypatch, env, tmp_path):
    _set_env(monkeypatch, env, ACTENON_REPLAY_DB=str(tmp_path / "shared-replay.sqlite3"))
    signer = _Ed25519Signer()
    worker_a = ActenonGate(verifier=signer, signer=signer, audience="service:payments", issuer="service:issuer",
                           capabilities=("payment.release",))
    worker_b = ActenonGate(verifier=signer, audience="service:payments", issuer="service:issuer",
                           capabilities=("payment.release",))
    assert worker_a.security_downgrades == ()
    action = _action(worker_a)
    proof = worker_a.mint_proof(action)
    calls: list[str] = []
    assert worker_a.protect(action, proof, lambda: calls.append("a")).ok
    replay = worker_b.protect(action, proof, lambda: calls.append("b"))
    assert replay.reason_code == "DUPLICATE_REPLAY"
    assert calls == ["a"]


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_production_config_with_explicit_shared_store_works(monkeypatch, env, tmp_path):
    from actenon.replay import ReplayProtector, SqliteReplayStore

    _set_env(monkeypatch, env)
    gate = _gate(replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.sqlite3")))
    assert gate.security_downgrades == ()
    action = _action(gate)
    assert gate.protect(action, gate.mint_proof(action), lambda: None).ok


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_boundary_verifier_honours_actenon_replay_db_across_workers(monkeypatch, env, tmp_path):
    from actenon.boundary import BoundaryVerificationRequest, BoundaryVerifier
    import json

    _set_env(monkeypatch, env, ACTENON_REPLAY_DB=str(tmp_path / "shared-replay.sqlite3"))
    signer = _Ed25519Signer()
    minting_gate = ActenonGate(
        verifier=signer,
        signer=signer,
        audience="service:payments",
        issuer="service:issuer",
        capabilities=("payment.release",),
    )
    action = _action(minting_gate, intent_id="intent_g3_boundary")
    proof = minting_gate.mint_proof(action)

    def present(verifier: BoundaryVerifier):
        return verifier.verify_boundary(
            BoundaryVerificationRequest(
                proof_token=json.dumps(proof.to_dict()),
                intent=action,
                action_type="payment.release",
                target="payment_001",
                action_hash="",
                audience="service:payments",
                boundary_id="g3",
            )
        )

    worker_a = BoundaryVerifier(pccb_verifier=PCCBVerifier(signer))
    worker_b = BoundaryVerifier(pccb_verifier=PCCBVerifier(signer))
    assert worker_a.health()["replay_store"] == "durable"
    assert present(worker_a).valid
    second = present(worker_b)
    assert not second.valid
    assert second.refusal_code == "REPLAY_DETECTED"


def test_suite_declares_test_intent_in_its_own_config():
    # CI must not depend on a developer's shell: the repository's own pytest
    # configuration declares test intent.
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    conftest = (root / "conftest.py").read_text(encoding="utf-8")
    assert 'os.environ["ACTENON_ENV"] = "test"' in conftest


# ---------------------------------------------------------------------------
# CLI entry points
# ---------------------------------------------------------------------------


def _cli_env(value: str | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _CONTROLLED}
    if value is not None:
        env["ACTENON_ENV"] = value
    return env


def test_conformance_run_declares_test_intent_itself(tmp_path):
    # `actenon-kernel conformance run` is a test harness: it must pass with
    # no ACTENON_ENV in the caller's shell (permit CI runs it that way).
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "actenon.cli", "conformance", "run", "--require-complete"],
        cwd=tmp_path,
        env={**_cli_env(None), "PYTHONPATH": str(Path(__file__).resolve().parents[2])},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Mark eligibility: Actenon Verified" in proc.stdout


@pytest.mark.parametrize("env", NO_INTENT_ENVS, ids=NO_INTENT_IDS)
def test_cli_local_verifier_refused_without_development_intent(monkeypatch, env, tmp_path, capsys):
    # `verify-proof --verifier auto` used to verify any proof signed with the
    # public secret and report it valid.
    import json

    from actenon import cli

    _set_env(monkeypatch, "development")
    gate = ActenonGate.local_dev(audience="service:payments")
    action = _action(gate)
    proof = gate.mint_proof(action)
    (tmp_path / "pccb.json").write_text(json.dumps(proof.to_dict()))
    (tmp_path / "intent.json").write_text(json.dumps(action))
    _set_env(monkeypatch, env)
    rc = cli.main(
        [
            "verify-proof",
            "--pccb",
            str(tmp_path / "pccb.json"),
            "--intent",
            str(tmp_path / "intent.json"),
            "--audience",
            "service:payments",
            "--signer",
            "auto",
        ]
    )
    assert rc != 0
    captured = capsys.readouterr()
    if env != "production":
        assert "ACTENON_ENV=development" in captured.err + captured.out
