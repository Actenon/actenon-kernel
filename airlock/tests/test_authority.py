"""Discovery -> manifest -> diff, and the decision path's fail-closed rules (A3, A4, A5, A8, A10)."""

from __future__ import annotations

import json

import pytest

from actenon_airlock.decision import ActionFacts, Decider, NO_AUTHORITY_SCOPE, body_digest
from actenon_airlock.diff import compute_diff, diff_manifests
from actenon_airlock.discovery import discover
from actenon_airlock.manifest import AuthorityEntry, Manifest, check_seal, seal_approval
from actenon_airlock.receipts import ReceiptStore
from actenon_airlock import render
from conftest import write_project


def test_discovery_produces_exact_action_and_resource(agent_project):
    d = discover(agent_project, env={})
    assert set(d.entries) == {("github.issue.create", "github.com/acme/support"), ("filesystem.write", "./reports/summary.txt")}
    assert len(d.unresolved) == 1 and d.unresolved[0].missing == ["host"]
    assert d.credentials == {"GITHUB_TOKEN": ["api.github.com", "uploads.github.com"]}
    assert d.command == ["python", "agent.py"]


def test_generated_manifest_never_contains_a_wildcard(agent_project):
    m = discover(agent_project, env={}).to_manifest("a", approve=True, at="t", generated_by="test")
    for e in m.authority:
        assert "*" not in e.resource and e.resource.strip()
    assert all(u.decision == "blocked" for u in m.unresolved)


def test_empty_project_has_no_authority(tmp_path):
    write_project(tmp_path, {"main.py": "print('hello')\n"})
    d = discover(tmp_path, env={})
    assert d.entries == {} and d.unresolved == []


def test_uncredentialed_reads_need_no_authority(tmp_path):
    write_project(tmp_path, {"main.py": "import requests\nrequests.get('https://example.com/feed')\n"})
    d = discover(tmp_path, env={})
    assert d.entries == {} and d.reads_skipped == 1


def test_diff_expansion_and_reduction(agent_project):
    m = discover(agent_project, env={}).to_manifest("a", approve=True, at="t", generated_by="test")
    (agent_project / "agent.py").write_text((agent_project / "agent.py").read_text().replace(
        "def main():",
        "def nuke():\n    requests.delete(f'{API}/repos/acme/project')\n\ndef main():",
    ).replace('    write_report("done")\n', ""))
    src = (agent_project / "agent.py").read_text().replace('with open("reports/summary.txt", "w") as f:', "if False:")
    (agent_project / "agent.py").write_text(src)
    diff = compute_diff(m, discover(agent_project, env={}))
    assert [(e.action, e.resource) for e in diff.added] == [("github.repo.delete", "github.com/acme/project")]
    assert [(e.action, e.resource) for e in diff.removed] == [("filesystem.write", "./reports/summary.txt")]
    data = diff.to_dict()
    assert data["schema"] == "airlock/authority-diff/v1" and data["expands_authority"] is True
    assert data["added"][0]["change"] == "NEW POWER" and data["added"][0]["runtime"] == "BLOCKED until approved"
    assert data["removed"][0]["change"] == "REMOVED POWER"
    text = render.diff_terminal(diff)
    assert "NEW POWER DETECTED" in text and "+ github.repo.delete" in text and "- filesystem.write" in text
    md = render.diff_markdown(diff)
    assert "BLOCKED UNTIL APPROVED" in md and "`github.repo.delete`" in md
    json.dumps(data)


def test_approved_template_covers_matching_discovery(tmp_path):
    write_project(tmp_path, {"a.py": "import requests\ndef rm(i):\n    requests.delete(f'https://api.x.com/s/{i}')\nh=[rm]\n"})
    m = Manifest("p", authority=[AuthorityEntry("http.delete", "api.x.com/s/{}")])
    assert compute_diff(m, discover(tmp_path, env={})).empty


def test_manifest_diff_between_revisions():
    base = Manifest("p", authority=[AuthorityEntry("a.x", "r1")])
    head = Manifest("p", authority=[AuthorityEntry("a.x", "r1"), AuthorityEntry("github.repo.delete", "github.com/o/r")])
    d = diff_manifests(base, head)
    assert [(e.action, e.resource) for e in d.added] == [("github.repo.delete", "github.com/o/r")] and not d.removed


def test_seal_detects_changed_approved_authority(tmp_path):
    m = Manifest("p", authority=[AuthorityEntry("a.x", "r1")])
    m.save(tmp_path)
    seal_approval(tmp_path, m)
    assert check_seal(tmp_path, m)[0]
    m.authority.append(AuthorityEntry("github.repo.delete", "github.com/o/r"))
    ok, why = check_seal(tmp_path, m)
    assert not ok and "changed" in why


# --- decision path ---------------------------------------------------------------------------------------


def _decider(tmp_path, entries):
    m = Manifest("p", authority=entries)
    store = ReceiptStore(tmp_path / "run")
    return Decider(m, tmp_path / "run", store, agent_id="test"), store


def _http(action, resource, url, body=b"{}", method="POST"):
    return ActionFacts("http", action, resource, {"method": method, "url": url, "body_sha256": body_digest(body)}, {"url": url})


def test_empty_manifest_denies_everything_and_permit_grant_is_not_allow_all(tmp_path):
    dec, _ = _decider(tmp_path, [])
    assert dec.grant.scopes.allow == [NO_AUTHORITY_SCOPE]
    a = dec.authorize(_http("github.issue.create", "github.com/o/r", "https://api.github.com/repos/o/r/issues"))
    assert not a.allowed and a.pccb is None


@pytest.mark.parametrize("facts,why", [
    (_http("github.repo.delete", "github.com/acme/support", "https://api.github.com/repos/acme/support", method="DELETE"), "not present"),
    (_http("github.issue.create", "github.com/acme/other", "https://api.github.com/repos/acme/other/issues"), "not present"),
    (_http("http.post", "unknown.example.com/x", "https://unknown.example.com/x"), "not present"),
    (ActionFacts("http", "http.post", None, {}, {}), "could not be determined"),
])
def test_unapproved_or_unknown_is_denied(tmp_path, facts, why):
    dec, _ = _decider(tmp_path, [AuthorityEntry("github.issue.create", "github.com/acme/support")])
    a = dec.authorize(facts)
    assert not a.allowed and why in a.reason and a.pccb is None


def test_pending_entry_is_not_authority(tmp_path):
    dec, _ = _decider(tmp_path, [AuthorityEntry("github.issue.create", "github.com/acme/support", status="pending")])
    a = dec.authorize(_http("github.issue.create", "github.com/acme/support", "https://api.github.com/repos/acme/support/issues"))
    assert not a.allowed and "pending" in a.reason


def test_proof_is_bound_to_exact_request(tmp_path):
    url = "https://api.github.com/repos/acme/support/issues"
    dec, _ = _decider(tmp_path, [AuthorityEntry("github.issue.create", "github.com/acme/support")])
    facts = _http("github.issue.create", "github.com/acme/support", url, b'{"title":"a"}')
    auth = dec.authorize(facts)
    assert auth.allowed and auth.pccb is not None
    dec.verify(auth, facts)  # the same request verifies
    for tampered in (
        _http("github.issue.create", "github.com/acme/support", url, b'{"title":"b"}'),  # body changed
        _http("github.issue.create", "github.com/acme/support", url + "?x=1", b'{"title":"a"}'),  # URL changed
        _http("github.issue.create", "github.com/acme/support", url, b'{"title":"a"}', method="PUT"),  # method changed
        _http("github.issue.create", "github.com/acme/other", url, b'{"title":"a"}'),  # target changed
    ):
        with pytest.raises(Exception):
            dec.verify(auth, tampered)


def test_template_entry_allows_one_segment_only(tmp_path):
    dec, _ = _decider(tmp_path, [AuthorityEntry("http.delete", "api.x.com/sessions/{}")])
    ok = dec.authorize(_http("http.delete", "api.x.com/sessions/42", "https://api.x.com/sessions/42", method="DELETE"))
    no = dec.authorize(_http("http.delete", "api.x.com/sessions/42/keys", "https://api.x.com/sessions/42/keys", method="DELETE"))
    assert ok.allowed and not no.allowed


def test_receipts_for_allow_and_deny(tmp_path):
    dec, store = _decider(tmp_path, [AuthorityEntry("github.issue.create", "github.com/acme/support")])
    url = "https://api.github.com/repos/acme/support/issues"
    auth = dec.authorize(_http("github.issue.create", "github.com/acme/support", url))
    r1 = dec.record(auth, executed=True, result={"status": 201}, credentials=["GITHUB_TOKEN"], upstream="real")
    deny = dec.authorize(_http("github.repo.delete", "github.com/acme/support", "https://api.github.com/repos/acme/support", method="DELETE"))
    r2 = dec.record(deny, executed=False, credentials=["GITHUB_TOKEN"])
    assert (r1.decision, r1.credential_released, r1.execution_occurred, bool(r1.proof_id), bool(r1.kernel_receipt_id)) == ("ALLOWED", True, True, True, True)
    assert (r2.decision, r2.credential_released, r2.execution_occurred, r2.credentials) == ("BLOCKED", False, False, [])
    assert (tmp_path / "run" / "kernel" / r1.id / "pccb.json").exists()
    lines = (tmp_path / "run" / "receipts.jsonl").read_text().splitlines()
    assert len(lines) == 2
