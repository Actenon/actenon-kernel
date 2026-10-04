"""scripts/release_gate.py: branch protection and publishing share one list of
check names, and that list cannot name a job that does not exist."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release_gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("release_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_configured_check_is_produced_by_a_job():
    pytest.importorskip("yaml")
    gate = _load()
    assert gate.validate() == 0
    config = json.loads((ROOT / ".github" / "required-checks.json").read_text())
    # Everything required to release is also required to merge.
    assert set(config["release"]) <= set(config["pull_request"])


def test_unknown_check_name_is_rejected(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    gate = _load()
    config = json.loads((ROOT / ".github" / "required-checks.json").read_text())
    config["pull_request"].append("A job that does not exist")
    fake = tmp_path / "required-checks.json"
    fake.write_text(json.dumps(config))
    monkeypatch.setattr(gate, "CONFIG", fake)
    assert gate.validate() == 1


def test_matrix_names_are_expanded():
    pytest.importorskip("yaml")
    names = _load().produced_check_names()
    assert {"Python tests (3.10)", "Python tests (3.11)", "Python tests (3.12)"} <= set(names)


def test_coordinated_source_candidate_cannot_publish(monkeypatch, capsys):
    gate = _load()
    monkeypatch.setenv("GITHUB_REF", "refs/tags/v1.3.0")
    monkeypatch.setenv("GITHUB_SHA", "0" * 40)
    monkeypatch.setattr(gate, "_api", lambda _path: pytest.fail("must refuse before reading checks"))
    assert gate.gate("1.3.0", "v") == 1
    assert "registry release refuses coordinated source constraints" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("ref", "version"),
    [("refs/heads/main", "1.3.0"), ("refs/tags/v9.9.9", "1.3.0"), ("refs/tags/verifier-sdk-v1.3.0", "1.3.0")],
)
def test_gate_refuses_anything_but_the_matching_version_tag(ref, version, monkeypatch):
    env = {"PATH": "/usr/bin:/bin", "GITHUB_REF": ref, "GITHUB_SHA": "0" * 40,
           "GITHUB_REPOSITORY": "Actenon/actenon-kernel", "GITHUB_TOKEN": "unused"}
    result = subprocess.run([sys.executable, str(SCRIPT), "gate", "--version", version],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode != 0
    assert "publishing requires the tag refs/tags/v1.3.0" in result.stdout + result.stderr


def test_gate_refuses_a_commit_that_is_not_on_main(tmp_path):
    # A commit that exists only on a side branch of a throwaway repository.
    repo = tmp_path / "r"
    run = lambda *a: subprocess.run(a, cwd=repo, check=True, capture_output=True, text=True)  # noqa: E731
    repo.mkdir()
    run("git", "init", "-q", "-b", "main")
    run("git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "base")
    run("git", "checkout", "-q", "-b", "side")
    run("git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "unreviewed")
    side = run("git", "rev-parse", "HEAD").stdout.strip()
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(bare)], check=True)
    run("git", "remote", "add", "origin", str(bare))
    (repo / "scripts").mkdir()
    (repo / ".github").mkdir()
    (repo / "scripts" / "release_gate.py").write_text(SCRIPT.read_text())
    (repo / ".github" / "required-checks.json").write_text(json.dumps({"branch": "main", "pull_request": [], "release": []}))
    env = {"PATH": "/usr/bin:/bin", "GITHUB_REF": "refs/tags/v1.0.0", "GITHUB_SHA": side,
           "GITHUB_REPOSITORY": "x/y", "GITHUB_TOKEN": "unused", "HOME": str(tmp_path)}
    result = subprocess.run([sys.executable, "scripts/release_gate.py", "gate", "--version", "1.0.0"],
                            cwd=repo, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "is not on origin/main" in result.stdout


def test_unnamed_matrix_jobs_use_github_naming(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    gate = _load()
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: pull_request\njobs:\n  test-python:\n    runs-on: ubuntu-latest\n"
        "    strategy:\n      matrix:\n        python-version: ['3.11', '3.12']\n    steps: []\n"
    )
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    assert set(gate.produced_check_names()) == {"test-python (3.11)", "test-python (3.12)"}
