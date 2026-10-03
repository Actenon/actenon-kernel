"""The authority manifest (``airlock.json``) and its approval state.

``airlock.json`` lives in the project and is reviewed like code. It lists the authority the agent is
approved to use (action + resource), the authority Airlock found but could not resolve (always blocked),
and the credentials Airlock manages. Runtime enforcement uses the approved entries and nothing else.

Approval integrity: every time the developer approves (``airlock init`` / ``airlock approve``) a digest of
the approved authority is sealed with a per-user key outside the project (``.airlock/approval.json``).
``airlock run`` refuses a manifest whose approved authority no longer matches its seal (an edit, a pull,
or the agent itself changed it) until the change is reviewed with ``airlock approve``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from actenon_scan.authority import resource_matches

from .home import approval_key

SCHEMA = "airlock/manifest/v1"
MANIFEST_NAME = "airlock.json"
STATE_DIR = ".airlock"


@dataclass
class Evidence:
    file: str
    line: int
    function: str = ""
    via: str = ""

    def where(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class AuthorityEntry:
    action: str
    resource: str
    status: str = "approved"  # approved | pending
    origin: str = "discovered"  # discovered | user
    evidence: list[Evidence] = field(default_factory=list)
    approved_at: str = ""
    note: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.action, self.resource)

    def matches(self, action: str, resource: str) -> bool:
        return action == self.action and resource_matches(self.resource, resource)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not self.note:
            d.pop("note")
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuthorityEntry":
        ev = [Evidence(**e) for e in d.get("evidence", [])]
        return cls(d["action"], d["resource"], d.get("status", "approved"), d.get("origin", "discovered"), ev,
                   d.get("approved_at", ""), d.get("note", ""))


@dataclass
class UnresolvedItem:
    id: str
    action: str
    missing: list[str]
    file: str
    line: int
    function: str
    via: str
    reason: str
    decision: str = "blocked"  # blocked | dynamic (acknowledged as intentionally dynamic; still blocked)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "UnresolvedItem":
        return cls(**{k: d[k] for k in ("id", "action", "missing", "file", "line", "function", "via", "reason")},
                   decision=d.get("decision", "blocked"))


@dataclass
class Manifest:
    project: str
    runtime: str = "python"
    command: list[str] = field(default_factory=list)
    authority: list[AuthorityEntry] = field(default_factory=list)
    unresolved: list[UnresolvedItem] = field(default_factory=list)
    credentials: dict[str, list[str]] = field(default_factory=dict)  # name -> hosts
    generated_by: str = ""

    # --- queries ------------------------------------------------------------------------------------
    def approved(self) -> list[AuthorityEntry]:
        return [e for e in self.authority if e.status == "approved"]

    def find(self, action: str, resource: str, *, approved_only: bool = True) -> AuthorityEntry | None:
        for e in self.authority:
            if (not approved_only or e.status == "approved") and e.matches(action, resource):
                return e
        return None

    def approved_digest(self) -> str:
        body = sorted([e.action, e.resource] for e in self.approved())
        creds = sorted([k, sorted(v)] for k, v in self.credentials.items())
        blob = json.dumps({"authority": body, "credentials": creds}, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    # --- io -----------------------------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "project": self.project,
            "runtime": self.runtime,
            "command": self.command,
            "authority": [e.to_dict() for e in sorted(self.authority, key=lambda e: (e.status != "approved", e.action, e.resource))],
            "unresolved": [u.to_dict() for u in sorted(self.unresolved, key=lambda u: (u.file, u.line, u.action))],
            "credentials": {k: sorted(v) for k, v in sorted(self.credentials.items())},
            "generated_by": self.generated_by,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Manifest":
        if d.get("schema") != SCHEMA:
            raise ManifestError(f"unsupported manifest schema {d.get('schema')!r} (expected {SCHEMA})")
        return cls(
            project=d.get("project", ""),
            runtime=d.get("runtime", "python"),
            command=list(d.get("command", [])),
            authority=[AuthorityEntry.from_dict(e) for e in d.get("authority", [])],
            unresolved=[UnresolvedItem.from_dict(u) for u in d.get("unresolved", [])],
            credentials={k: list(v) for k, v in d.get("credentials", {}).items()},
            generated_by=d.get("generated_by", ""),
        )

    def save(self, root: Path) -> Path:
        path = root / MANIFEST_NAME
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        return path

    @classmethod
    def load(cls, root: Path) -> "Manifest":
        path = root / MANIFEST_NAME
        if not path.exists():
            raise ManifestError(f"no {MANIFEST_NAME} in {root}: run `airlock init` first")
        try:
            return cls.from_dict(json.loads(path.read_text()))
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ManifestError(f"{path} is not a valid Airlock manifest: {exc}") from exc


class ManifestError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --- approval seal -----------------------------------------------------------------------------------


def _seal_path(root: Path) -> Path:
    return root / STATE_DIR / "approval.json"


def seal_approval(root: Path, manifest: Manifest) -> None:
    d = root / STATE_DIR
    d.mkdir(exist_ok=True)
    gi = d / ".gitignore"
    if not gi.exists():
        gi.write_text("*\n")
    digest = manifest.approved_digest()
    mac = hmac.new(approval_key(), f"{root.resolve()}|{digest}".encode(), hashlib.sha256).hexdigest()
    authority = sorted([e.action, e.resource] for e in manifest.approved())
    _seal_path(root).write_text(json.dumps({"digest": digest, "mac": mac, "sealed_at": now_iso(), "authority": authority},
                                           indent=2) + "\n")
    os.chmod(_seal_path(root), 0o600)


def check_seal(root: Path, manifest: Manifest) -> tuple[bool, str]:
    """(ok, explanation). ok means the approved authority equals what this user last approved here."""
    p = _seal_path(root)
    if not p.exists():
        return False, "this manifest has not been approved on this machine yet"
    try:
        rec = json.loads(p.read_text())
    except json.JSONDecodeError:
        return False, "the local approval record is unreadable"
    expected = hmac.new(approval_key(), f"{root.resolve()}|{rec.get('digest', '')}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, rec.get("mac", "")):
        return False, "the local approval record was not written by Airlock on this machine"
    if rec.get("digest") != manifest.approved_digest():
        return False, "the approved authority in airlock.json changed since it was last approved here"
    return True, "approved"


def sealed_authority(root: Path) -> set[tuple[str, str]]:
    """The approved (action, resource) set recorded at the last local approval (empty if none)."""
    try:
        rec = json.loads(_seal_path(root).read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    return {(a, r) for a, r in rec.get("authority", [])}
