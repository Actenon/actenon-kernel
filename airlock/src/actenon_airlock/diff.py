"""Authority diff: what new powers does the code give the agent, compared with what was approved?

NEW POWER (expansion) is anything the code can now do that no approved entry covers: it stays blocked at
runtime until approved. REMOVED POWER (reduction) is approved authority the code no longer uses: it can be
narrowed away safely. New unresolved authority is reported separately: it is blocked and needs a bounded
human decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .discovery import Discovery
from .manifest import AuthorityEntry, Evidence, Manifest, UnresolvedItem

SCHEMA = "airlock/authority-diff/v1"


@dataclass
class AuthorityDiff:
    added: list[AuthorityEntry] = field(default_factory=list)
    removed: list[AuthorityEntry] = field(default_factory=list)
    unresolved_added: list[UnresolvedItem] = field(default_factory=list)
    unresolved_removed: list[UnresolvedItem] = field(default_factory=list)
    unchanged: int = 0

    @property
    def expands(self) -> bool:
        return bool(self.added or self.unresolved_added)

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.unresolved_added or self.unresolved_removed)

    def to_dict(self) -> dict[str, Any]:
        def ent(e: AuthorityEntry, kind: str, runtime: str) -> dict[str, Any]:
            return {"change": kind, "action": e.action, "resource": e.resource, "runtime": runtime,
                    "evidence": [{"file": x.file, "line": x.line, "function": x.function, "via": x.via} for x in e.evidence]}

        def unr(u: UnresolvedItem, kind: str) -> dict[str, Any]:
            return {"change": kind, "action": u.action, "missing": u.missing, "file": u.file, "line": u.line,
                    "function": u.function, "via": u.via, "reason": u.reason, "runtime": "BLOCKED", "id": u.id}

        return {
            "schema": SCHEMA,
            "expands_authority": self.expands,
            "summary": {"new_powers": len(self.added), "removed_powers": len(self.removed),
                        "new_unresolved": len(self.unresolved_added), "resolved_unresolved": len(self.unresolved_removed),
                        "unchanged": self.unchanged},
            "added": [ent(e, "NEW POWER", "BLOCKED until approved") for e in self.added],
            "removed": [ent(e, "REMOVED POWER", "no longer needed") for e in self.removed],
            "unresolved_added": [unr(u, "NEW UNRESOLVED") for u in self.unresolved_added],
            "unresolved_removed": [unr(u, "UNRESOLVED REMOVED") for u in self.unresolved_removed],
        }


def compute_diff(manifest: Manifest, discovery: Discovery) -> AuthorityDiff:
    out = AuthorityDiff()
    approved = manifest.approved()
    for key, entry in sorted(discovery.entries.items()):
        if any(a.matches(entry.action, entry.resource) or a.key == key for a in approved):
            out.unchanged += 1
        else:
            out.added.append(entry)
    discovered_keys = set(discovery.entries)
    for a in approved:
        still_used = a.key in discovered_keys or any(a.matches(k[0], k[1]) for k in discovered_keys)
        if not still_used and a.origin == "discovered":
            out.removed.append(a)
    known_ids = {u.id for u in manifest.unresolved}
    now_ids = {u.id for u in discovery.unresolved}
    from .manifest import group_key, item_resource

    for u in discovery.unresolved:
        if u.id in known_ids:
            continue
        chosen = manifest.resolutions.get(group_key(u))
        if chosen is not None:
            chosen = item_resource(u, group_key(u), chosen)
            # The person already said which target this group acts on: a new capability in the group is a
            # NEW POWER on exactly that target (still blocked until approved).
            if manifest.find(u.action, chosen) is None and all(e.key != (u.action, chosen) for e in out.added):
                out.added.append(AuthorityEntry(u.action, chosen, origin="user", note=f"{group_key(u)} chosen by user",
                                                evidence=[Evidence(u.file, u.line, u.function, u.via)]))
            continue
        out.unresolved_added.append(u)
    out.unresolved_removed = [u for u in manifest.unresolved if u.id not in now_ids]
    return out


def diff_manifests(base: Manifest, head: Manifest) -> AuthorityDiff:
    """Approved authority added/removed between two manifests (e.g. the base and head of a pull request)."""
    out = AuthorityDiff()
    base_keys = {e.key for e in base.approved()}
    head_keys = {e.key for e in head.approved()}
    out.added = [e for e in head.approved() if e.key not in base_keys]
    out.removed = [e for e in base.approved() if e.key not in head_keys]
    out.unchanged = len(base_keys & head_keys)
    return out
