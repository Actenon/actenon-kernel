"""Human-facing output: product language first, cryptographic detail available but secondary."""

from __future__ import annotations

import os
import sys
from typing import Any, Iterable

from .diff import AuthorityDiff
from .manifest import AuthorityEntry, Manifest, UnresolvedItem


def _color() -> bool:
    return sys.stderr.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _color() else s


def green(s: str) -> str:
    return _c("32", s)


def red(s: str) -> str:
    return _c("1;31", s)


def yellow(s: str) -> str:
    return _c("33", s)


def bold(s: str) -> str:
    return _c("1", s)


def dim(s: str) -> str:
    return _c("2", s)


def action_label(action: str) -> str:
    if action.startswith("http.") and action != "http.request":
        return "HTTP " + action[5:].upper()
    if action == "http.request":
        return "HTTP request (method decided at runtime)"
    return action


def missing_label(item: UnresolvedItem) -> str:
    m = ", ".join(item.missing)
    kinds = {"host": "destination", "repository": "repository", "owner": "account", "path": "path", "program": "program",
             "target": "target"}
    words = ", ".join(kinds.get(x, x) for x in item.missing)
    return f"{words or m} decided at runtime"


# --- init ------------------------------------------------------------------------------------------------


def init_summary(manifest: Manifest, *, files: int, reads_skipped: int, unmanaged: list[str]) -> str:
    lines = ["Scanning agent...", "", f"Analysed {files} Python file{'s' if files != 1 else ''}.", "", "Detected authority:", ""]
    approved = manifest.approved()
    for e in approved:
        lines.append(f"{green('✓')} {action_label(e.action)}")
        lines.append(f"  {e.resource}")
    for u in manifest.unresolved:
        lines.append(f"{yellow('⚠')} {action_label(u.action)} — {missing_label(u)}")
        lines.append(f"  {dim(f'{u.file}:{u.line} in {u.function}')}")
        lines.append(f"  {red('BLOCKED') if u.decision != 'dynamic' else red('BLOCKED') + dim(' (marked intentionally dynamic)')}")
    if not approved and not manifest.unresolved:
        lines.append(dim("  (no consequential capabilities found)"))
    lines += ["", f"{len(approved)} authorised", f"{len(manifest.unresolved)} blocked (unresolved)"]
    if manifest.credentials:
        lines += ["", "Credentials Airlock will hold (the agent only sees placeholders):",
                  "  " + ", ".join(sorted(manifest.credentials))]
    if unmanaged:
        lines += ["", yellow("Secrets the agent reads that Airlock does not manage (visible to the agent):"), "  " + ", ".join(unmanaged)]
    if reads_skipped:
        lines += ["", dim(f"{reads_skipped} plain read request{'s' if reads_skipped != 1 else ''} without credentials need no authority.")]
    lines += ["", bold("Ready.") + " Run your agent with: " + bold("airlock run" + (" -- <command>" if not manifest.command else ""))]
    return "\n".join(lines)


# --- runtime events ----------------------------------------------------------------------------------------


def event_line(event: dict[str, Any]) -> str:
    r = event["receipt"]
    if event["decision"] == "ALLOWED":
        cred = f" · credential {', '.join(r['credentials'])} released" if r.get("credential_released") else ""
        status = f" · {r['result'].get('status')}" if r.get("result", {}).get("status") else ""
        return dim("airlock ") + green("✓") + f" {action_label(r['action'])} {r['target']}{status}{cred} " + dim(f"[{r['id']}]")
    if event["decision"] == "ERROR":
        return dim("airlock ") + yellow("!") + f" {action_label(r['action'])} {r['target']}: {r['reason']} " + dim(f"[{r['id']}]")
    return block_notice(r)


def block_notice(r: dict[str, Any]) -> str:
    reason = r.get("reason", "")
    reason = reason[:1].upper() + reason[1:] if reason else "Not approved."
    if not reason.endswith("."):
        reason += "."
    return "\n".join([
        "", red("BLOCKED"), "", action_label(r["action"]), r["target"], "", reason, "",
        "Credential released: NO", "Execution occurred: NO", "", f"Receipt: {r['id']}", "",
    ])


def run_summary(stats: dict[str, int], run_dir: str) -> str:
    return dim(f"airlock: {stats['allowed']} allowed, {stats['blocked']} blocked, {stats['passed_reads']} plain reads · receipts: {run_dir}")


# --- diff --------------------------------------------------------------------------------------------------


def _where(e: AuthorityEntry) -> str:
    if not e.evidence:
        return ""
    x = e.evidence[0]
    more = f" (+{len(e.evidence) - 1})" if len(e.evidence) > 1 else ""
    via = f"  ({x.via})" if x.via else ""
    return f"{x.file}:{x.line} in {x.function}{more}{via}"


def diff_terminal(d: AuthorityDiff) -> str:
    lines = [bold("AUTHORITY DIFF"), ""]
    if d.empty:
        lines.append(green("No change: the code needs exactly the approved authority."))
        return "\n".join(lines)
    if d.added:
        lines += [red("NEW POWER DETECTED"), ""]
        for e in d.added:
            lines += [red(f"+ {action_label(e.action)}"), f"  {e.resource}", dim(f"  {_where(e)}")]
        lines += ["", "This authority was not previously approved.", "Runtime: " + red("BLOCKED") + " until approved (airlock approve)", ""]
    if d.unresolved_added:
        lines += [yellow("NEW UNRESOLVED AUTHORITY"), ""]
        for u in d.unresolved_added:
            lines += [yellow(f"+ {action_label(u.action)} — {missing_label(u)}"), dim(f"  {u.file}:{u.line} in {u.function}  ({u.via})")]
        lines += ["", "Airlock cannot tell where these go. Runtime: " + red("BLOCKED") + ".", ""]
    if d.removed:
        lines += [green("REMOVED POWER"), ""]
        for e in d.removed:
            lines += [green(f"- {action_label(e.action)}"), f"  {e.resource}"]
        lines += ["", dim("No longer used by the code; `airlock approve` narrows the manifest."), ""]
    if d.unresolved_removed:
        lines += [dim(f"{len(d.unresolved_removed)} unresolved item(s) no longer present."), ""]
    return "\n".join(lines).rstrip() + "\n"


def diff_markdown(d: AuthorityDiff, *, approved_in_pr: list[AuthorityEntry] | None = None, title: str = "Airlock / Authority Review") -> str:
    lines = [f"### {title}", ""]
    approved_in_pr = approved_in_pr or []
    if d.empty and not approved_in_pr:
        lines.append("No authority change: the code needs exactly the approved authority.")
        return "\n".join(lines) + "\n"
    if d.added or d.unresolved_added:
        lines += ["**This change adds powers that are not approved:**", "", "| | Power | Resource | Code |", "|---|---|---|---|"]
        for e in d.added:
            lines.append(f"| ➕ | `{action_label(e.action)}` | `{e.resource}` | `{_where(e)}` |")
        for u in d.unresolved_added:
            lines.append(f"| ⚠️ | `{action_label(u.action)}` | _{missing_label(u)}_ | `{u.file}:{u.line} in {u.function}` |")
        lines += ["", "**Runtime production authority: BLOCKED UNTIL APPROVED** (`airlock approve`, then commit `airlock.json`).", ""]
    if approved_in_pr:
        lines += ["**Approved in this change (`airlock.json`):**", ""]
        lines += [f"- ➕ `{action_label(e.action)}` `{e.resource}`" for e in approved_in_pr]
        lines.append("")
    if d.removed:
        lines += ["**Removed powers (narrowing):**", ""]
        lines += [f"- ➖ `{action_label(e.action)}` `{e.resource}`" for e in d.removed]
        lines.append("")
    return "\n".join(lines) + "\n"


def receipts_text(receipts: Iterable[dict[str, Any]]) -> str:
    out = []
    for r in receipts:
        head = (green("ALLOWED") if r["decision"] == "ALLOWED" else red("BLOCKED")) + f"  {action_label(r['action'])}  {r['target']}"
        out.append(head)
        out.append(f"  when:      {r['ts']}")
        req = r.get("request", {})
        if req.get("method"):
            out.append(f"  request:   {req['method']} {req.get('url', '')}")
        elif req.get("path"):
            out.append(f"  path:      {req['path']}")
        elif req.get("argv"):
            out.append(f"  command:   {' '.join(req['argv'])}")
        if r["decision"] == "ALLOWED":
            out.append(f"  authority: {r['authority']}  ({r['authority_source']})")
            if r.get("provenance"):
                p = r["provenance"][0]
                out.append(f"  code:      {p['file']}:{p['line']} in {p['function']}")
            if r.get("result"):
                out.append(f"  result:    {', '.join(f'{k}={v}' for k, v in r['result'].items())}")
            out.append(f"  proof:     {r['proof_id']}  receipt: {r['kernel_receipt_id']}")
        else:
            out.append(f"  reason:    {r['reason']}")
        out.append(f"  credential released: {'YES (' + ', '.join(r['credentials']) + ')' if r.get('credential_released') else 'NO'}"
                   f"   execution occurred: {'YES' if r.get('execution_occurred') else 'NO'}")
        out.append(f"  id:        {r['id']}")
        out.append("")
    return "\n".join(out) if out else "No receipts yet."
