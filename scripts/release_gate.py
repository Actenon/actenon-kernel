#!/usr/bin/env python3
"""Release gate shared by every Actenon repository (identical copy in each).

Single source of truth: .github/required-checks.json
  {
    "branch": "main",
    "pull_request": [<check-run names required to merge>],
    "release": [<check-run names that must have succeeded on the tagged commit>]
  }

Modes
  validate                     every listed name is produced by a job in .github/workflows
                               (matrix names expanded); exits 1 on an unknown name. Run in CI,
                               so branch protection can never reference a job that does not exist.
  gate (--version V | --version-from FILE)
                               in a publish workflow (FILE: pyproject.toml, package.json or Cargo.toml): the ref is a v-tag equal to V (tag prefix
                               configurable with --tag-prefix), the tagged commit is on
                               origin/<branch>, and every "release" check-run on that exact commit
                               concluded success. Needs GITHUB_TOKEN with checks:read and a checkout
                               with full history.
  print-protection             the branch-protection JSON an owner applies (OWNER-ACTIONS.md).
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - CI installs pyyaml
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".github" / "required-checks.json"
EXPR = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_.-]+)\s*\}\}")


def load_config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _matrix_rows(matrix) -> list[dict]:
    if not isinstance(matrix, dict):
        return [{}]
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude") and isinstance(v, list)}
    rows = [dict(zip(axes, combo)) for combo in itertools.product(*axes.values())] if axes else [{}]
    for extra in matrix.get("include", []) or []:
        rows.append(dict(extra))
    excludes = matrix.get("exclude", []) or []
    return [r for r in rows if not any(all(r.get(k) == v for k, v in ex.items()) for ex in excludes)]


def produced_check_names() -> dict[str, str]:
    """check-run name -> workflow file, for every job in every workflow."""
    if yaml is None:
        sys.exit("release_gate: pyyaml is required (pip install pyyaml)")
    names: dict[str, str] = {}
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        for job_id, job in (doc.get("jobs") or {}).items():
            explicit = "name" in job
            template = str(job.get("name", job_id))
            for row in _matrix_rows((job.get("strategy") or {}).get("matrix")):
                if explicit or not row:
                    name = EXPR.sub(lambda m, row=row: str(row.get(m.group(1), m.group(0))), template)
                else:
                    # GitHub names an unnamed matrix job "<job id> (<values>, ...)".
                    name = f"{job_id} ({', '.join(str(v) for v in row.values())})"
                names[name] = wf.name
    return names


def validate() -> int:
    cfg = load_config()
    produced = produced_check_names()
    bad = [(kind, n) for kind in ("pull_request", "release") for n in cfg.get(kind, []) if n not in produced]
    for kind, n in bad:
        print(f"::error::required-checks.json {kind}: no job produces a check named {n!r}")
    if not bad:
        print(f"required-checks.json OK: {len(cfg.get('pull_request', []))} PR checks, "
              f"{len(cfg.get('release', []))} release checks, all produced by workflow jobs")
    return 1 if bad else 0


def _api(path: str) -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        sys.exit("release_gate: GITHUB_TOKEN is required")
    req = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def gate(version: str, tag_prefix: str) -> int:
    cfg = load_config()
    ref = os.environ.get("GITHUB_REF", "")
    sha = os.environ.get("GITHUB_SHA", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    problems: list[str] = []
    expected_ref = f"refs/tags/{tag_prefix}{version}"
    if ref != expected_ref:
        # Decisive: nothing else is worth checking for a run that is not the release tag.
        print(f"::error::publishing requires the tag {expected_ref}; this run is for {ref or '<no ref>'}")
        return 1
    branch = cfg.get("branch", "main")
    fetched = subprocess.run(["git", "fetch", "--no-tags", "--quiet", "origin", branch], cwd=ROOT)
    on_branch = fetched.returncode == 0 and subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, f"origin/{branch}"], cwd=ROOT).returncode == 0
    if not on_branch:
        print(f"::error::tagged commit {sha} is not on origin/{branch}: release only merged, reviewed history")
        return 1
    for name in cfg.get("release", []):
        try:
            runs = _api(f"repos/{repo}/commits/{sha}/check-runs?per_page=100&check_name={urllib.parse.quote(name)}").get("check_runs", [])
        except Exception as exc:  # an unreadable check state is a refusal, never a pass
            problems.append(f"could not read check {name!r} on {sha}: {exc}")
            continue
        conclusions = [r.get("conclusion") for r in runs]
        if not runs:
            problems.append(f"required check {name!r} never ran on {sha}")
        elif not all(c == "success" for c in conclusions):
            problems.append(f"required check {name!r} on {sha}: {conclusions}")
    for p in problems:
        print(f"::error::{p}")
    if problems:
        return 1
    print(f"release gate OK: {expected_ref} at {sha} is on origin/{branch} and "
          f"{len(cfg.get('release', []))} required checks succeeded on that commit")
    return 0


def print_protection() -> int:
    cfg = load_config()
    print(json.dumps({
        "required_status_checks": {"strict": True, "checks": [{"context": n} for n in cfg.get("pull_request", [])]},
        "enforce_admins": True,
        "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True},
        "restrictions": None,
        "required_linear_history": False,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }, indent=2))
    return 0


def version_from(path: str) -> str:
    """The version declared by pyproject.toml, a package.json, or Cargo.toml."""
    file = ROOT / path
    if file.name == "package.json":
        return json.loads(file.read_text(encoding="utf-8"))["version"]
    import tomllib  # Python >= 3.11 (publish workflows run 3.12)

    data = tomllib.loads(file.read_text(encoding="utf-8"))
    return data["package"]["version"] if file.name == "Cargo.toml" else data["project"]["version"]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("validate", "gate", "print-protection"))
    ap.add_argument("--version")
    ap.add_argument("--version-from")
    ap.add_argument("--tag-prefix", default="v")
    args = ap.parse_args(argv)
    if args.mode == "validate":
        return validate()
    if args.mode == "print-protection":
        return print_protection()
    version = args.version or (version_from(args.version_from) if args.version_from else None)
    if not version:
        ap.error("gate needs --version or --version-from")
    return gate(version, args.tag_prefix)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
