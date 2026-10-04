"""`airlock doctor`: setup problems, each with the fix."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import render as R
from .credentials import KNOWN_CREDENTIALS, environment_secrets

MIN_VERSIONS = {"actenon-scan": (1, 6, 0), "actenon-permit": (2, 0, 0), "actenon-kernel": (1, 3, 0), "actenon-protocol": (1, 4, 0)}


def _v(s: str) -> tuple[int, ...]:
    out = []
    for part in s.split("."):
        num = "".join(c for c in part if c.isdigit())
        if not num:
            break
        out.append(int(num))
        if not part.isdigit():
            break
    return tuple(out)


def run_doctor(root: Path, versions: dict[str, str]) -> int:
    problems = 0
    warnings = 0

    def ok(msg: str) -> None:
        print(f"{R.green('✓')} {msg}")

    def warn(msg: str, fix: str) -> None:
        nonlocal warnings
        warnings += 1
        print(f"{R.yellow('⚠')} {msg}\n    → {fix}")

    def bad(msg: str, fix: str) -> None:
        nonlocal problems
        problems += 1
        print(f"{R.red('✗')} {msg}\n    → {fix}")

    if sys.version_info < (3, 11):
        bad(f"Python {sys.version.split()[0]} runs Airlock", "Airlock needs Python 3.11 or newer")
    else:
        ok(f"Python {sys.version.split()[0]}")

    for pkg, need in MIN_VERSIONS.items():
        have = versions.get(pkg, "missing")
        if have == "missing":
            bad(f"{pkg} is not installed", "reinstall Airlock: pipx install --force actenon-airlock")
        elif _v(have) < need:
            bad(f"{pkg} {have} is older than {'.'.join(map(str, need))}", "upgrade Airlock: pipx upgrade actenon-airlock")
        else:
            ok(f"{pkg} {have}")

    try:
        from .home import grant_key_file, proof_key_file

        grant_key_file()
        os.environ["ACTENON_ED25519_KEY_FILE"] = str(proof_key_file())
        from actenon_permit.ed25519_signer import resolve_signer

        resolve_signer()
        ok("proof signing key (Ed25519) and grant key are usable")
    except Exception as exc:  # noqa: BLE001
        bad(f"signing configuration is invalid: {exc}", "remove the Airlock home's key files to regenerate them (see AIRLOCK_HOME)")

    try:
        from .ca import LocalCA

        LocalCA().server_context("doctor.airlock.invalid")
        ok("local edge certificate authority is usable")
    except Exception as exc:  # noqa: BLE001
        bad(f"the edge cannot create certificates: {exc}", "check that the Airlock home is writable")

    manifest = None
    if not (root / "airlock.json").exists():
        warn(f"no airlock.json in {root}", "run `airlock init` in the agent's directory")
    else:
        from .manifest import Manifest, ManifestError, check_seal

        try:
            manifest = Manifest.load(root)
            ok(f"airlock.json: {len(manifest.approved())} approved power(s), {len(manifest.unresolved)} unresolved (blocked)")
            sealed, why = check_seal(root, manifest)
            if sealed:
                ok("approved authority matches the local approval record")
            else:
                bad(f"airlock run will refuse: {why}", "review the change with `airlock approve`")
        except ManifestError as exc:
            bad(str(exc), "fix or regenerate it with `airlock init --force`")

    if manifest is not None:
        from .diff import compute_diff
        from .discovery import discover

        try:
            d = discover(root)
            if d.runtime != "python":
                warn(f"runtime '{d.runtime}': automatic discovery supports Python agents",
                     "network actions are still enforced; approve authority with `airlock approve --target`")
            diff = compute_diff(manifest, d)
            if diff.expands:
                warn(f"generated authority is stale: the code has {len(diff.added) + len(diff.unresolved_added)} unapproved power(s)",
                     "see `airlock diff`; approve with `airlock approve`")
            else:
                ok("approved authority covers the current code")
            for u in manifest.unresolved:
                if u.decision == "blocked":
                    warn(f"unresolved {R.action_label(u.action)} at {u.file}:{u.line} is blocked",
                         "approve one exact target with `airlock approve --target ACTION TARGET`, or leave it blocked")
            if not manifest.command:
                warn("no agent command recorded", "run with `airlock run -- <command>`")
            env = {**os.environ}
            for name in manifest.credentials:
                if name not in env:
                    from actenon_scan.authority import load_env_files

                    if name not in load_env_files(root)[0]:
                        warn(f"credential {name} is not set", f"export {name}=... (Airlock holds it; the agent sees a placeholder)")
            unmanaged = [n for n in environment_secrets(env) if n not in KNOWN_CREDENTIALS and n in d.unmanaged_secrets]
            for n in unmanaged:
                warn(f"secret {n} is passed to the agent as-is", "Airlock v1 manages well-known credentials only")
        except Exception as exc:  # noqa: BLE001
            bad(f"discovery failed: {exc}", "report this with `airlock --version` output")

    if os.environ.get("AIRLOCK_STAND_INS"):
        warn("AIRLOCK_STAND_INS is set: requests go to local test servers", "unset AIRLOCK_STAND_INS outside tests")
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        ok(f"the edge will reach the internet through {proxy}")

    print()
    if problems:
        print(R.red(f"{problems} problem(s)") + (f", {warnings} warning(s)" if warnings else ""))
        return 1
    print(R.green("Airlock is ready.") + (f" {warnings} warning(s)." if warnings else ""))
    return 0
