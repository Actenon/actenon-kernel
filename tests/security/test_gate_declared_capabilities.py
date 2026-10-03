"""An ActenonGate must declare what its side effect performs (protocol 13 E1).

A gate with no declared ``capabilities`` would take the capability from the
presented intent, so E1 ("the intent's capability is one this endpoint
performs") would compare the request with itself. Outside explicit
development intent that is refused at construction; inside it, or under the
named unsafe override, the downgrade is recorded in ``security_downgrades``.
"""

from __future__ import annotations

import pytest

from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon.security_posture import InsecureDefaultRefusedError
from tests.security.test_production_environment_paths import _Ed25519Signer

OVERRIDE = "ACTENON_UNSAFE_ALLOW_UNDECLARED_CAPABILITIES"


def _gate(tmp_path, **kwargs) -> ActenonGate:
    signer = _Ed25519Signer()
    return ActenonGate(
        verifier=signer,
        audience="service:payments",
        issuer="service:permit",
        replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.sqlite3")),
        **kwargs,
    )


@pytest.fixture
def env(monkeypatch):
    for name in ("ACTENON_ENV", "ACTENON_PRODUCTION", "ACTENON_CI_RELEASE", "ACTENON_RELEASE_BUILD", OVERRIDE):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.mark.parametrize("value", [None, "", "production", "prd", "staging"])
def test_undeclared_capabilities_refused_outside_development(env, tmp_path, value):
    if value is not None:
        env.setenv("ACTENON_ENV", value)
    with pytest.raises(InsecureDefaultRefusedError, match="capabilities"):
        _gate(tmp_path)


def test_declared_capabilities_construct_with_no_downgrade(env, tmp_path):
    env.setenv("ACTENON_ENV", "production")
    gate = _gate(tmp_path, capabilities=("payment.refund",))
    assert "undeclared_capabilities" not in gate.security_downgrades


def test_development_intent_records_the_downgrade(env, tmp_path):
    env.setenv("ACTENON_ENV", "development")
    assert "undeclared_capabilities" in _gate(tmp_path).security_downgrades


def test_unsafe_override_is_loud_and_recorded(env, tmp_path):
    env.setenv("ACTENON_ENV", "production")
    env.setenv(OVERRIDE, "1")
    with pytest.warns(RuntimeWarning, match=OVERRIDE):
        gate = _gate(tmp_path)
    assert "undeclared_capabilities" in gate.security_downgrades
