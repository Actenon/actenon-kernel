"""``airlock``: run your AI agent through Airlock.

    airlock init      discover what the agent can do and approve it
    airlock run       run the agent with only that authority
    airlock diff      what new powers does the current code give the agent?
    airlock approve   approve new powers (or an exact target for unresolved ones)
    airlock check     CI / pull-request gate: fail on unapproved new powers
    airlock receipts  what was allowed and blocked, and why
    airlock doctor    find setup problems before they bite
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from . import render as R
from .credentials import Vault, hosts_for
from .diff import AuthorityDiff, compute_diff, diff_manifests
from .discovery import discover
from .manifest import (MANIFEST_NAME, STATE_DIR, AuthorityEntry, Manifest, ManifestError, check_seal, now_iso,
                       resolve_group, seal_approval, sealed_authority)

RUNTIME_DIR = Path(__file__).parent / "runtime"


def _out(s: str = "") -> None:
    print(s, flush=True)


def _err(s: str = "") -> None:
    print(s, file=sys.stderr, flush=True)


def _interactive(args: argparse.Namespace) -> bool:
    return not getattr(args, "yes", False) and sys.stdin.isatty() and sys.stdout.isatty()


def _component_versions() -> dict[str, str]:
    from importlib.metadata import PackageNotFoundError, version

    out = {}
    for pkg in ("actenon-airlock", "actenon-scan", "actenon-permit", "actenon-kernel", "actenon-protocol"):
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = "missing"
    return out


def _root(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "project", None) or ".").resolve()


def _project_env(root: Path) -> dict[str, str]:
    from actenon_scan.authority import load_env_files

    file_env, _ = load_env_files(root)
    return {**file_env, **os.environ}


# --- init --------------------------------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    root = _root(args)
    if (root / MANIFEST_NAME).exists() and not args.force:
        _err(f"{MANIFEST_NAME} already exists. Use `airlock diff` to see what changed, `airlock approve` to accept it,")
        _err("or `airlock init --force` to rediscover from scratch.")
        return 2
    t0 = time.monotonic()
    d = discover(root, env=_project_env(root))
    if d.runtime != "python":
        _err(f"Airlock v1 discovers authority in Python agents; this project looks like: {d.runtime}.")
        _err("Network enforcement still works with `airlock run -- <command>` once you approve authority manually.")
        if d.runtime == "unknown":
            return 2
    if args.command:
        d.command = args.command
    manifest = d.to_manifest(root.name, approve=True, at=now_iso(), generated_by=f"airlock {__version__}")
    for spec in args.resolve or []:
        part, _, value = spec.partition("=")
        err = _validate_exact_target(value) if part != "path" else (None if value and "*" not in value else "wildcards are never accepted")
        if err or not part:
            _err(f"--resolve {spec}: {err or 'expected PART=VALUE'}")
            return 2
        added = resolve_group(manifest, part.strip(), value.strip(), now_iso())
        if not added:
            _err(R.yellow(f"--resolve {spec}: no unresolved {part} to apply it to"))
    if manifest.unresolved and _interactive(args):
        _decide_unresolved(manifest)
    if args.json:
        _out(json.dumps(manifest.to_dict(), indent=2))
    else:
        _out(R.init_summary(manifest, files=d.files_analysed, reads_skipped=d.reads_skipped, unmanaged=d.unmanaged_secrets))
    if d.parse_errors:
        _err(R.yellow(f"{len(d.parse_errors)} file(s) could not be parsed and were not analysed: "
                      + ", ".join(e["file"] for e in d.parse_errors[:5])))
    manifest.save(root)
    seal_approval(root, manifest)
    _err(R.dim(f"wrote {MANIFEST_NAME} ({time.monotonic() - t0:.1f}s). Commit it: it is your agent's approved authority."))
    return 0


def _decide_unresolved(manifest: Manifest) -> None:
    from .manifest import GROUP_LABELS, group_unresolved

    for part, items in group_unresolved(manifest.unresolved).items():
        if len(items) < 2 or part not in ("repository", "path"):
            continue
        label = GROUP_LABELS[part]
        actions = sorted({R.action_label(u.action) for u in items})
        _out("")
        _out(f"Airlock cannot determine the {label} for {len(items)} capabilities: {', '.join(actions)}")
        _out(f"Allow them on one exact {label} (e.g. {'acme/project' if part == 'repository' else './output/'}), or press Enter to keep them blocked:")
        value = input("> ").strip()
        if value and "*" not in value:
            resolve_group(manifest, part, value, now_iso())
    for u in manifest.unresolved:
        if u.decision != "blocked":
            continue
        _out("")
        _out(f"Airlock cannot determine the {R.missing_label(u).replace(' decided at runtime', '')} for:")
        _out(f"  {R.action_label(u.action)}   {u.file}:{u.line} in {u.function}")
        _out("Allow:")
        _out("  [e] an exact target you enter")
        _out("  [d] deny (default)")
        _out("  [m] mark this code path as intentionally dynamic (still blocked; each attempt shows its exact target)")
        choice = input("> ").strip().lower()
        if choice == "e":
            target = input("exact target (e.g. github.com/acme/support or api.example.com/v1/items): ").strip()
            err = _validate_exact_target(target)
            if err:
                _out(R.red(f"not accepted: {err}; left blocked"))
                continue
            manifest.authority.append(AuthorityEntry(u.action, target, origin="user", approved_at=now_iso(),
                                                     note=f"exact target for {u.file}:{u.line}"))
            u.decision = "resolved-by-user"
        elif choice == "m":
            u.decision = "dynamic"


def _validate_exact_target(target: str) -> str | None:
    if not target:
        return "empty target"
    if any(c in target for c in "*?[]"):
        return "wildcards are never accepted; enter one exact target"
    if "://" in target:
        return "enter the target without a scheme (e.g. api.example.com/v1/items)"
    if " " in target:
        return "a target has no spaces"
    return None


# --- diff / approve / check --------------------------------------------------------------------------------


def _load_and_discover(root: Path) -> tuple[Manifest, AuthorityDiff, object]:
    manifest = Manifest.load(root)
    d = discover(root, env=_project_env(root))
    return manifest, compute_diff(manifest, d), d


def cmd_diff(args: argparse.Namespace) -> int:
    root = _root(args)
    manifest, diff, _ = _load_and_discover(root)
    if args.json:
        _out(json.dumps(diff.to_dict(), indent=2))
    elif args.markdown:
        _out(R.diff_markdown(diff))
    else:
        _out(R.diff_terminal(diff))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    root = _root(args)
    manifest = Manifest.load(root)
    if args.target:
        action, target = args.target
        err = _validate_exact_target(target)
        if err:
            _err(f"not accepted: {err}")
            return 2
        if manifest.find(action, target) is None:
            manifest.authority.append(AuthorityEntry(action, target, origin="user", approved_at=now_iso(), note="exact target"))
        manifest.save(root)
        seal_approval(root, manifest)
        _out(f"Approved {R.action_label(action)} {target}.")
        return 0
    d = discover(root, env=_project_env(root))
    diff = compute_diff(manifest, d)
    seal_ok, why = check_seal(root, manifest)
    externally_changed = []
    if not seal_ok:
        before = sealed_authority(root)
        externally_changed = [e for e in manifest.approved() if e.key not in before]
    if diff.empty and seal_ok:
        _out("Nothing to approve: the approved authority matches the code.")
        return 0
    _out(R.diff_terminal(diff))
    if externally_changed:
        _out(R.yellow("airlock.json was changed outside `airlock approve` (" + why + "); it grants:"))
        for e in externally_changed:
            _out(f"  + {R.action_label(e.action)}  {e.resource}")
        _out("")
    if _interactive(args):
        if input("Approve these changes? [y/N] ").strip().lower() not in ("y", "yes"):
            _out("Nothing approved.")
            return 1
    elif not args.yes:
        _err("Not approving without confirmation: re-run with --yes to approve non-interactively.")
        return 1
    at = now_iso()
    for e in diff.added:
        e.status, e.approved_at = "approved", at
        manifest.authority.append(e)
    removed_keys = {e.key for e in diff.removed}
    manifest.authority = [e for e in manifest.authority if e.key not in removed_keys]
    known = {u.id for u in manifest.unresolved}
    manifest.unresolved = [u for u in manifest.unresolved if u.id not in {x.id for x in diff.unresolved_removed}]
    manifest.unresolved += [u for u in d.unresolved if u.id not in known]
    for name, hosts in d.credentials.items():
        manifest.credentials.setdefault(name, hosts)
    manifest.save(root)
    seal_approval(root, manifest)
    _out(f"Approved: {len(diff.added)} new power(s), removed {len(diff.removed)}, "
         f"{len(diff.unresolved_added)} unresolved item(s) recorded as blocked. Commit {MANIFEST_NAME}.")
    return 0


def _base_manifest(root: Path, ref: str) -> Manifest | None:
    try:
        rel = (root / MANIFEST_NAME).relative_to(Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=root, text=True).strip()))
        data = subprocess.check_output(["git", "show", f"{ref}:{rel.as_posix()}"], cwd=root, text=True, stderr=subprocess.DEVNULL)
        return Manifest.from_dict(json.loads(data))
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError, ManifestError, json.JSONDecodeError):
        return None


def cmd_check(args: argparse.Namespace) -> int:
    from .github import annotate, write_summary

    root = _root(args)
    try:
        manifest = Manifest.load(root)
    except ManifestError as exc:
        _err(str(exc))
        return 2
    d = discover(root, env=_project_env(root))
    diff = compute_diff(manifest, d)
    approved_in_pr: list[AuthorityEntry] = []
    if args.base:
        base = _base_manifest(root, args.base)
        if base is not None:
            approved_in_pr = diff_manifests(base, manifest).added
    md = R.diff_markdown(diff, approved_in_pr=approved_in_pr)
    gh = args.github or os.environ.get("GITHUB_ACTIONS") == "true"
    if gh:
        write_summary(md)
        annotate(diff, root)
    if args.json:
        _out(json.dumps({**diff.to_dict(), "approved_in_change": [{"action": e.action, "resource": e.resource} for e in approved_in_pr]}, indent=2))
    else:
        _out(md if args.markdown else R.diff_terminal(diff))
        if approved_in_pr:
            _out("Approved in this change (airlock.json):")
            for e in approved_in_pr:
                _out(f"  + {R.action_label(e.action)}  {e.resource}")
    if diff.expands:
        _err(R.red("Airlock: unapproved new authority. Runtime: BLOCKED UNTIL APPROVED (`airlock approve`, commit airlock.json)."))
        return 1
    return 0


# --- run ---------------------------------------------------------------------------------------------------


def _parse_stand_ins(values: list[str]) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    for v in values:
        host, _, addr = v.partition("=")
        h, _, p = addr.rpartition(":")
        if not host or not p.isdigit():
            raise SystemExit(f"--stand-in expects HOST=127.0.0.1:PORT, got {v!r}")
        out[host.strip().lower()] = (h or "127.0.0.1", int(p))
    return out


def cmd_run(args: argparse.Namespace) -> int:
    from .ca import LocalCA
    from .decision import Decider
    from .edge import Edge, upstream_settings
    from .receipts import ReceiptStore

    root = _root(args)
    try:
        manifest = Manifest.load(root)
    except ManifestError as exc:
        _err(str(exc))
        return 2
    ok, why = check_seal(root, manifest)
    if not ok:
        before = sealed_authority(root)
        _err(R.red("Airlock will not run: ") + why + ".")
        added = [e for e in manifest.approved() if e.key not in before]
        for e in added:
            _err(f"  + {R.action_label(e.action)}  {e.resource}")
        _err("Review it with `airlock approve`.")
        return 3
    command = list(args.cmd or manifest.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _err("No command to run: use `airlock run -- <command>` (for example `airlock run -- python agent.py`).")
        return 2
    if not args.skip_stale_check:
        try:
            diff = compute_diff(manifest, discover(root, env=_project_env(root)))
        except Exception:  # noqa: BLE001 - staleness is advisory
            diff = None
        if diff is not None and diff.expands:
            _err(R.yellow(f"airlock: the code has {len(diff.added) + len(diff.unresolved_added)} power(s) that are not approved; "
                          "they will be blocked. See `airlock diff`."))

    env = _project_env(root)
    names = {n: tuple(h) for n, h in manifest.credentials.items()}
    for n in env:  # every credential whose provider is known is held, discovered or not
        if n not in names and hosts_for(n, env):
            names[n] = hosts_for(n, env)
    vault = Vault.from_environment(names, env)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
    run_dir = root / STATE_DIR / "runs" / run_id
    receipts = ReceiptStore(run_dir, redact=vault.redact)
    decider = Decider(manifest, run_dir, receipts, agent_id=f"airlock:{manifest.project or root.name}")
    ca = LocalCA()
    bundle = ca.bundle_for_agent(run_dir / "airlock-ca.pem")
    proxy, no_proxy, cafile = upstream_settings(dict(os.environ))
    stand_ins = _parse_stand_ins(args.stand_in or [])
    if os.environ.get("AIRLOCK_STAND_INS"):
        stand_ins.update(_parse_stand_ins(os.environ["AIRLOCK_STAND_INS"].split(",")))
    if stand_ins:
        _err(R.yellow("airlock: TEST STAND-INS ACTIVE: " + ", ".join(f"{h} -> {a[0]}:{a[1]}" for h, a in stand_ins.items())))
    token = secrets.token_hex(24)

    def on_event(e: dict) -> None:
        _err(R.event_line(e))

    edge = Edge(decider, vault, ca, control_token=token, upstream_proxy=proxy, no_proxy=no_proxy, upstream_cafile=cafile,
                stand_ins=stand_ins, on_event=on_event)
    port = edge.start()
    proxy_url = f"http://127.0.0.1:{port}"
    child = vault.agent_environment({k: v for k, v in os.environ.items() if not k.startswith("AIRLOCK_")})
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        child[k] = proxy_url
    child["NO_PROXY"] = child["no_proxy"] = "localhost,127.0.0.1,::1"
    for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "HTTPLIB2_CA_CERTS"):
        child[k] = str(bundle)
    child.pop("SSL_CERT_DIR", None)
    child["PYTHONPATH"] = str(RUNTIME_DIR) + (os.pathsep + child["PYTHONPATH"] if child.get("PYTHONPATH") else "")
    child.update({"AIRLOCK_EDGE": f"127.0.0.1:{port}", "AIRLOCK_TOKEN": token, "AIRLOCK_PROJECT_ROOT": str(root),
                  "AIRLOCK_RUN_ID": run_id})
    _err(R.dim(f"airlock: running {' '.join(command)} with {len(manifest.approved())} approved power(s); "
               f"holding {len(vault.placeholders)} credential(s)"))
    try:
        proc = subprocess.Popen(command, cwd=root, env=child)
    except FileNotFoundError:
        _err(f"command not found: {command[0]}")
        edge.stop()
        return 127
    try:
        rc = proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        rc = proc.wait()
    time.sleep(0.2)
    edge.stop()
    _err(R.run_summary(edge.stats, str(run_dir.relative_to(root))))
    return rc


# --- receipts / doctor / version --------------------------------------------------------------------------


def cmd_receipts(args: argparse.Namespace) -> int:
    from .receipts import load_receipts

    root = _root(args)
    runs = sorted((root / STATE_DIR / "runs").glob("*")) if (root / STATE_DIR / "runs").exists() else []
    if not runs:
        _out("No runs yet.")
        return 0
    run = next((r for r in runs if r.name == args.run), None) if args.run else runs[-1]
    if run is None:
        _err(f"no run {args.run}")
        return 2
    items = load_receipts(run)
    if args.blocked:
        items = [r for r in items if r["decision"] == "BLOCKED"]
    if args.json:
        _out(json.dumps(items, indent=2))
    else:
        _out(R.dim(f"run {run.name}") + "\n")
        _out(R.receipts_text(items))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from .doctor import run_doctor

    return run_doctor(_root(args), _component_versions())


def cmd_version(args: argparse.Namespace) -> int:
    v = _component_versions()
    _out(f"airlock {__version__}")
    for k, val in v.items():
        if k != "actenon-airlock":
            _out(f"  {k} {val}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="airlock", description="Run your AI agent through Airlock: it discovers what the agent "
                                "can actually do, gives it only those powers, and blocks anything new until you approve it.")
    p.add_argument("--version", action="store_true", help="show Airlock and component versions")
    p.add_argument("-C", "--project", help="project directory (default: current directory)")
    sub = p.add_subparsers(dest="cmd_name")

    s = sub.add_parser("init", help="discover the agent's authority and approve it")
    s.add_argument("--yes", "-y", action="store_true", help="non-interactive: leave unresolved authority blocked")
    s.add_argument("--force", action="store_true", help="rediscover even if airlock.json exists")
    s.add_argument("--json", action="store_true")
    s.add_argument("--resolve", action="append", metavar="PART=VALUE",
                   help="answer a group of unresolved authority with one exact target: repository=OWNER/REPO, path=./DIR/")
    s.add_argument("--command", nargs=argparse.REMAINDER, help="the command that starts the agent (default: detected)")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("run", help="run the agent with only its approved authority")
    s.add_argument("--stand-in", action="append", metavar="HOST=127.0.0.1:PORT",
                   help="TESTING ONLY: answer for HOST with a local recording server (decisions still use HOST)")
    s.add_argument("--skip-stale-check", action="store_true", help=argparse.SUPPRESS)
    s.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command (default: the command in airlock.json)")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("diff", help="what new powers does the current code give the agent?")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--markdown", action="store_true")
    s.set_defaults(fn=cmd_diff)

    s = sub.add_parser("approve", help="approve new powers, or an exact target for unresolved authority")
    s.add_argument("--yes", "-y", action="store_true")
    s.add_argument("--target", nargs=2, metavar=("ACTION", "TARGET"), help="approve one exact target, e.g. http.post api.example.com/v1/items")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("check", help="CI gate: fail when the code has unapproved new powers")
    s.add_argument("--base", help="git ref of the base (e.g. origin/main) to show approvals made in this change")
    s.add_argument("--github", action="store_true", help="write a GitHub job summary and annotations (automatic in Actions)")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--markdown", action="store_true")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("receipts", help="what was allowed and blocked in the last run")
    s.add_argument("--run")
    s.add_argument("--blocked", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_receipts)

    s = sub.add_parser("doctor", help="check the setup")
    s.set_defaults(fn=cmd_doctor)

    args = p.parse_args(argv)
    if args.version:
        return cmd_version(args)
    if not getattr(args, "fn", None):
        p.print_help()
        return 0
    try:
        return args.fn(args)
    except ManifestError as exc:
        _err(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
