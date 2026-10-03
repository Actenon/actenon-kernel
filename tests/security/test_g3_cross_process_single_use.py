"""G3 / H1 regression: single use across real worker processes and restarts.

Each "worker" is a separate Python interpreter (as with gunicorn/uvicorn
workers, or the same service after a restart). A protected edge built with
no replay configuration must either refuse to start or enforce single use
across all of them; it must never execute one single-use proof once per
worker. A development intent keeps the local demo working, with the
downgrade recorded.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

_ED25519 = textwrap.dedent(
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from actenon.models.contracts import SignatureSpec

    def _e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
    def _d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    class Verifier:
        algorithm = "EdDSA"
        def __init__(self, x, kid):
            self.key_id = kid
            self._pub = ed25519.Ed25519PublicKey.from_public_bytes(_d(x))
        def verify(self, payload, signature):
            if signature.algorithm != "EdDSA" or signature.key_id != self.key_id:
                return False
            try:
                self._pub.verify(_d(signature.value), payload)
                return True
            except Exception:
                return False

    class Signer(Verifier):
        def __init__(self, kid="ed25519-test"):
            self._priv = ed25519.Ed25519PrivateKey.generate()
            raw = self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.x = _e(raw)
            super().__init__(self.x, kid)
        def sign(self, payload):
            return SignatureSpec(algorithm="EdDSA", key_id=self.key_id, encoding="base64url", value=_e(self._priv.sign(payload)))
    """
)

_ISSUER = _ED25519 + textwrap.dedent(
    """
    import json, sys
    from actenon.gate import ActenonGate
    from actenon.replay import ReplayProtector, SqliteReplayStore
    signer = Signer()
    # The issuer itself is configured correctly (its own durable store).
    gate = ActenonGate(verifier=signer, signer=signer, audience="service:payments", issuer="service:issuer",
                       capabilities=("payments.refund",),
                       replay_protector=ReplayProtector(SqliteReplayStore(sys.argv[2])))
    action = gate.build_action("refund", "payments.refund", {"amount": 100}, target_type="charge", target_id="ch_1")
    proof = gate.mint_proof(action)
    json.dump({"x": signer.x, "kid": signer.key_id, "action": action, "proof": proof.to_dict()}, open(sys.argv[1], "w"), default=str)
    """
)

_WORKER = _ED25519 + textwrap.dedent(
    """
    import json, sys
    from actenon.gate import ActenonGate
    d = json.load(open(sys.argv[1]))
    try:
        gate = ActenonGate(verifier=Verifier(d["x"], d["kid"]), audience="service:payments", issuer="service:issuer",
                           capabilities=("payments.refund",))
    except RuntimeError as exc:
        print(json.dumps({"started": False, "error": str(exc)}))
        raise SystemExit(0)
    def side_effect():
        with open(sys.argv[2], "a") as ledger:
            ledger.write("executed\\n")
    out = gate.protect(d["action"], d["proof"], side_effect)
    print(json.dumps({"started": True, "outcome": out.outcome, "reason": out.reason_code,
                      "downgrades": list(getattr(gate, "security_downgrades", ["<no security_downgrades attribute>"]))}))
    """
)

_LOCAL_DEV_WORKER = textwrap.dedent(
    """
    import json, sys
    from actenon.gate import ActenonGate
    gate = ActenonGate.local_dev(audience="service:payments")
    action = gate.build_action("refund", "payments.refund", {"amount": 1}, target_type="charge", target_id="ch_1")
    proof = gate.mint_proof(action)
    first = gate.protect(action, proof, lambda: None)
    second = gate.protect(action, proof, lambda: None)
    print(json.dumps({"first": first.outcome, "second": second.reason_code, "downgrades": list(getattr(gate, "security_downgrades", ["<no security_downgrades attribute>"]))}))
    """
)

_CONTROLLED = (
    "ACTENON_ENV",
    "ACTENON_REPLAY_DB",
    "ACTENON_PRODUCTION",
    "ACTENON_CI_RELEASE",
    "ACTENON_RELEASE_BUILD",
    "ACTENON_LOCAL_HMAC_SECRET",
    "ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY",
    "ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED",
    "ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN",
)


def _env(actenon_env: str | None, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _CONTROLLED}
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONWARNINGS"] = "ignore"
    if actenon_env is not None:
        env["ACTENON_ENV"] = actenon_env
    env.update(extra)
    return env


def _run(script: str, *args: str, env: dict[str, str], cwd: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", script, *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _mint(tmp_path: Path, env: dict[str, str]) -> Path:
    proof_file = tmp_path / "proof.json"
    subprocess.run(
        [sys.executable, "-c", _ISSUER, str(proof_file), str(tmp_path / "issuer-replay.sqlite3")],
        env=env, cwd=tmp_path, check=True, capture_output=True, timeout=120,
    )
    return proof_file


@pytest.mark.parametrize("actenon_env", [None, "", "prd", "production", "live"], ids=["unset", "empty", "prd", "production", "live"])
def test_unconfigured_edge_never_executes_a_single_use_proof_twice_across_processes(tmp_path, actenon_env):
    env = _env(actenon_env)
    proof_file = _mint(tmp_path, env)
    ledger = tmp_path / "ledger.txt"
    results = [
        _run(_WORKER, str(proof_file), str(ledger), env=env, cwd=tmp_path)
        for _ in ("worker-a", "worker-b", "worker-a-restarted")
    ]
    executions = ledger.read_text().count("executed") if ledger.exists() else 0
    assert executions <= 1, f"one single-use proof executed {executions} times: {results}"
    # Without replay configuration the edge refuses to start, naming the fix.
    assert all(not r["started"] for r in results), results
    assert "ACTENON_REPLAY_DB" in results[0]["error"]


@pytest.mark.parametrize("actenon_env", [None, "prd", "production"], ids=["unset", "prd", "production"])
def test_shared_durable_replay_db_enforces_single_use_across_processes(tmp_path, actenon_env):
    env = _env(actenon_env, ACTENON_REPLAY_DB=str(tmp_path / "shared-replay.sqlite3"))
    proof_file = _mint(tmp_path, env)
    ledger = tmp_path / "ledger.txt"
    results = [
        _run(_WORKER, str(proof_file), str(ledger), env=env, cwd=tmp_path)
        for _ in ("worker-a", "worker-b", "worker-a-restarted")
    ]
    assert [r["outcome"] for r in results] == ["executed", "refused", "refused"], results
    assert [r["reason"] for r in results[1:]] == ["DUPLICATE_REPLAY", "DUPLICATE_REPLAY"]
    assert all(r["downgrades"] == [] for r in results)
    assert ledger.read_text().count("executed") == 1


def test_process_local_override_is_visible_and_still_single_use_within_a_process(tmp_path):
    env = _env(None, ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY="1")
    proof_file = _mint(tmp_path, env)
    result = _run(_WORKER, str(proof_file), str(tmp_path / "ledger.txt"), env=env, cwd=tmp_path)
    assert result["started"] and result["outcome"] == "executed"
    assert result["downgrades"] == ["process_local_replay"]


@pytest.mark.parametrize("actenon_env", [None, "development", "dev", "local", "test"])
def test_local_demo_still_works_with_development_intent(tmp_path, actenon_env):
    result = _run(_LOCAL_DEV_WORKER, env=_env(actenon_env), cwd=tmp_path)
    assert result["first"] == "executed"
    assert result["second"] == "DUPLICATE_REPLAY"
    assert "public_development_secret" in result["downgrades"]
    assert "process_local_replay" in result["downgrades"]


@pytest.mark.parametrize("actenon_env", ["prd", "production", "live", "uat"])
def test_local_demo_refused_when_environment_declares_non_development(tmp_path, actenon_env):
    proc = subprocess.run(
        [sys.executable, "-c", _LOCAL_DEV_WORKER], env=_env(actenon_env), cwd=tmp_path, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode != 0
    assert "Error" in proc.stderr
