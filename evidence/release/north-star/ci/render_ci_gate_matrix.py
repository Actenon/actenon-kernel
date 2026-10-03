"""Render CI-GATE-MATRIX.md from each repo's .github/required-checks.json (the single source of truth for
branch protection and the publish gate), the workflow that produces each name (that repo's
scripts/release_gate.py), OBSERVED-PR-CHECKS.json, and LOCAL (what this session ran itself)."""
import importlib.util, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OBS = json.loads((HERE / "OBSERVED-PR-CHECKS.json").read_text())
REPOS = ["actenon-protocol", "actenon-kernel", "sdk-go", "sdk-rust", "actenon-permit"]
# What this session executed locally for the check's commands (evidence under evidence/release/north-star).
LOCAL = {
    "actenon-protocol": {"Conformance suite (Python 3.10)": "PASS (pytest conformance/python: 290 passed, 20 skipped)", "Conformance suite (Python 3.11)": "PASS", "Conformance suite (Python 3.12)": "PASS",
                         "Lint + format check": "PASS (ruff check/format python/ conformance/python/)", "Verify README claims (machine-enforced)": "PASS (every step, run_wf_steps)",
                         "Required-check names exist": "PASS (release_gate.py validate)"},
    "actenon-kernel": {"Python tests (3.10)": "PASS (894 passed / 5 skipped; skip gate 0 unexpected after the allowlist fix)", "Python tests (3.12)": "PASS (same)",
                       "Replay store on PostgreSQL 16": "PASS (real PostgreSQL 16 server: 3/3 incl. concurrent cold start)", "Required-check names exist": "PASS (release_gate.py validate)",
                       "Verify README claims (machine-enforced)": "PASS except the ecosystem step with PyPI protocol 1.3.0 (release order); PASS with protocol 1.4.0",
                       "Go verifier SDK (standalone, pinned)": "PASS (check_standalone_sdk_fixtures.py; go test against this lock)",
                       "Rust verifier SDK (standalone, pinned)": "PASS (check_standalone_sdk_fixtures.py; cargo test against this lock)"},
    "sdk-go": {"Test (Go 1.22)": "PASS (go vet + go test, Go 1.24 toolchain)", "Test (Go stable)": "PASS", "Vendored kernel vectors match the pinned kernel": "PASS (lock test with the kernel's lock)",
               "Required-check names exist": "PASS (release_gate.py validate)"},
    "sdk-rust": {"fmt + clippy + doc": "PASS (cargo fmt --check, clippy -D warnings)", "Test (Rust stable)": "PASS (37 tests)", "Vendored kernel vectors match the pinned kernel": "PASS",
                 "Required-check names exist": "PASS (release_gate.py validate)"},
    "actenon-permit": {"test-python (3.11)": "PASS (uv run pytest: 558 passed, 1 skipped, kernel pin b1b175d)", "test-python (3.12)": "PASS (same suite)",
                       "Required-check names exist": "PASS (release_gate.py validate)"},
}
NOTES = {
    ("actenon-kernel", "Python tests (3.10)"): "FAILED on 715f4e7 only in the skip gate: test_concurrent_cold_start_creates_the_schema_once (runs in postgres-replay) was not allow-listed; fix committed locally, push pending network",
    ("actenon-kernel", "Python tests (3.11)"): "same as 3.10",
    ("actenon-kernel", "Python tests (3.12)"): "same as 3.10",
    ("actenon-kernel", "Verify README claims (machine-enforced)"): "release order: green once actenon-protocol 1.4.0 is on PyPI (comment on the PR)",
    ("actenon-permit", "Verify README claims (machine-enforced)"): "release order: protocol 1.4.0 renderer, then kernel 1.3.0 on PyPI for `pip install .`",
}
lines = ["# CI gate matrix (north-star)", "",
         "Status legend: **LOCAL** = the check's commands were run by this session; **PR-CI** = conclusion of that check-run on the candidate PR head; "
         "**REQUIRED-CHECK** = enforced by branch protection on `main` (cannot be read or set from this session: OWNER_ACTION_REQUIRED, see OWNER-ACTIONS.md); "
         "**PUBLISH-GATED** = listed in `release` of `.github/required-checks.json`, so `scripts/release_gate.py gate` refuses to publish unless it succeeded on the tagged commit.",
         "", "An unexecuted workflow is never counted as PASS.", ""]
for repo in REPOS:
    root = Path("/home/user") / repo
    cfg = json.loads((root / ".github/required-checks.json").read_text())
    spec = importlib.util.spec_from_file_location(f"rg_{repo}", root / "scripts/release_gate.py"); rg = importlib.util.module_from_spec(spec); spec.loader.exec_module(rg)
    produced = rg.produced_check_names()
    obs = OBS[repo]
    lines += [f"## {repo} — {obs['pr']} @ {obs['head']}", "", "| Check | Workflow | LOCAL | PR-CI | REQUIRED-CHECK | PUBLISH-GATED | Note |", "|---|---|---|---|---|---|---|"]
    names = list(dict.fromkeys(cfg["pull_request"] + cfg["release"]))
    for n in names:
        o = obs["checks"].get(n)
        pr = f"[{o[0].upper()}]({o[1]})" if o else "NOT RUN"
        lines.append(f"| {n} | `{produced.get(n, '??')}` | {LOCAL.get(repo, {}).get(n, 'not run locally')} | {pr} | OWNER_ACTION_REQUIRED | {'yes' if n in cfg['release'] else 'no (PR only)'} | {NOTES.get((repo, n), '')} |")
    extra = [n for n in obs["checks"] if n not in names]
    if extra:
        lines += ["", "Not required (informational): " + ", ".join(f"{n} = {obs['checks'][n][0]}" for n in extra)]
    lines.append("")
lines += ["## Permit: workflows disabled for inactivity", "",
          "`ci.yml`, `link-check.yml`, `protocol-drift.yml`, `version-coherence.yml` and `actenon-scan.yml` in Actenon/actenon-permit are in state "
          "`disabled_inactivity` (GitHub API, 2026-10-03). Every required check they produce is NOT RUN on the candidate. Re-enabling them is an owner action; "
          "until then Permit's PR-CI status is FAIL, not PASS.", ""]
(HERE.parent / "CI-GATE-MATRIX.md").write_text("\n".join(lines) + "\n")
print("wrote", HERE.parent / "CI-GATE-MATRIX.md")
