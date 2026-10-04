"""GitHub Actions output for `airlock check`: job summary and line annotations on the code that adds powers."""

from __future__ import annotations

import os
from pathlib import Path

from .diff import AuthorityDiff
from .render import action_label


def write_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(markdown + "\n")


def _escape(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(s: str) -> str:
    return _escape(s).replace(":", "%3A").replace(",", "%2C")


def annotate(diff: AuthorityDiff, root: Path) -> None:
    prefix = ""
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        try:
            rel = root.resolve().relative_to(Path(workspace).resolve())
            prefix = "" if str(rel) == "." else rel.as_posix() + "/"
        except ValueError:
            prefix = ""
    for e in diff.added:
        for ev in e.evidence[:3]:
            msg = f"NEW POWER {action_label(e.action)} {e.resource}: not approved. Runtime: BLOCKED UNTIL APPROVED."
            print(f"::error file={_escape_prop(prefix + ev.file)},line={ev.line},title={_escape_prop('Airlock: new power')}::{_escape(msg)}")
    for u in diff.unresolved_added:
        msg = f"{action_label(u.action)} goes to a target Airlock cannot determine ({', '.join(u.missing)}). Runtime: BLOCKED."
        print(f"::warning file={_escape_prop(prefix + u.file)},line={u.line},title={_escape_prop('Airlock: unresolved authority')}::{_escape(msg)}")
    for e in diff.removed:
        print(f"::notice title={_escape_prop('Airlock: removed power')}::{_escape(f'{action_label(e.action)} {e.resource} is no longer used')}")
