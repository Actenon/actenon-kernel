from __future__ import annotations

import os
import sys
import textwrap
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from standin import Recorder, make_server  # noqa: E402


@pytest.fixture(autouse=True)
def airlock_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("airlock-home")
    monkeypatch.setenv("AIRLOCK_HOME", str(home))
    monkeypatch.delenv("AIRLOCK_STAND_INS", raising=False)
    for k in ("GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    return home


@pytest.fixture
def standin():
    rec = Recorder()
    srv = make_server(rec)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    rec.port = srv.server_address[1]
    yield rec
    srv.shutdown()


def write_project(root: Path, files: dict[str, str]) -> Path:
    for name, src in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src))
    return root


AGENT = '''
import os, sys, requests

API = "https://api.github.com"
REPO = "acme/support"

def create_issue(title):
    r = requests.post(f"{API}/repos/{REPO}/issues", json={"title": title},
                      headers={"Authorization": f"token {os.environ['GITHUB_TOKEN']}"}, timeout=10)
    print("create_issue", r.status_code)

def write_report(text):
    with open("reports/summary.txt", "w") as f:
        f.write(text)

def post_anywhere(url):
    return requests.post(url, json={})

tools = [post_anywhere]

def main():
    create_issue("Weekly triage")
    write_report("done")

if __name__ == "__main__":
    main()
'''


@pytest.fixture
def agent_project(tmp_path):
    root = write_project(tmp_path / "agent", {"agent.py": AGENT})
    (root / "reports").mkdir()
    return root


@pytest.fixture
def python_exe():
    return sys.executable


@pytest.fixture
def env_without_proxy(monkeypatch):
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    return dict(os.environ)
