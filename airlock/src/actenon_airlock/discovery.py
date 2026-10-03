"""Discovery: turn the agent's code into proposed authority.

Uses actenon-scan's structured authority evidence (action, resource, resolution state, provenance) and
compiles it into authority entries. Rules:

* RESOLVED and TEMPLATE evidence becomes an entry for exactly that (action, resource).
* UNRESOLVED evidence becomes an *unresolved item*: blocked at runtime, shown to the developer, never an
  entry and never a wildcard.
* Plain reads (GET/HEAD/OPTIONS) without a credential are not consequential and are not listed.
* Credentials are the well-known credential variables the code (or the SDKs it uses) reads.
"""

from __future__ import annotations

import ast
import hashlib
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from actenon_scan.authority import AuthorityEvidence, ResourceState, extract_authority, load_env_files

from .credentials import KNOWN_CREDENTIALS, hosts_for, looks_secret
from .manifest import AuthorityEntry, Evidence, Manifest, UnresolvedItem

IMPLICIT_CREDENTIALS = {  # SDKs that read a credential variable without naming it in the code
    "openai.": "OPENAI_API_KEY",
    "langchain_openai.": "OPENAI_API_KEY",
    "anthropic.": "ANTHROPIC_API_KEY",
    "langchain_anthropic.": "ANTHROPIC_API_KEY",
}
ENTRY_CANDIDATES = ("main.py", "agent.py", "app.py", "run.py", "bot.py", "cli.py")


@dataclass
class Discovery:
    root: Path
    runtime: str
    entries: dict[tuple[str, str], AuthorityEntry] = field(default_factory=dict)
    unresolved: list[UnresolvedItem] = field(default_factory=list)
    credentials: dict[str, list[str]] = field(default_factory=dict)
    unmanaged_secrets: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    files_analysed: int = 0
    parse_errors: list[dict] = field(default_factory=list)
    reads_skipped: int = 0
    evidence: list[AuthorityEvidence] = field(default_factory=list)

    def to_manifest(self, project: str, *, approve: bool, at: str, generated_by: str) -> Manifest:
        entries = []
        for e in self.entries.values():
            e.status = "approved" if approve else "pending"
            e.approved_at = at if approve else ""
            entries.append(e)
        return Manifest(project=project, runtime=self.runtime, command=self.command, authority=entries,
                        unresolved=list(self.unresolved), credentials=dict(self.credentials), generated_by=generated_by)


def detect_runtime(root: Path) -> str:
    has_py = any(root.glob("*.py")) or (root / "pyproject.toml").exists() or (root / "setup.py").exists() \
        or (root / "requirements.txt").exists() or any(root.glob("*/*.py"))
    if has_py:
        return "python"
    if (root / "package.json").exists():
        return "node"
    return "unknown"


def detect_command(root: Path) -> list[str]:
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text())
            scripts = data.get("project", {}).get("scripts", {}) or data.get("tool", {}).get("poetry", {}).get("scripts", {})
            if scripts:
                return [sorted(scripts)[0]]
        except (tomllib.TOMLDecodeError, OSError):
            pass
    for name in ENTRY_CANDIDATES:
        if (root / name).is_file():
            return ["python", name]
    for main in sorted(root.glob("*/__main__.py")):
        return ["python", "-m", main.parent.name]
    return []


def _env_names_in_code(root: Path, files: list[str]) -> set[str]:
    names: set[str] = set()
    for rel in files:
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
            continue
        for node in ast.walk(tree):
            # Any upper-case identifier-like string literal is a candidate variable name; only well-known
            # credential names and secret-looking names are used.
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.isupper() \
                    and 3 <= len(node.value) <= 64 and node.value.replace("_", "").isalnum():
                names.add(node.value)
    return names


def _python_files(root: Path) -> list[str]:
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "build", "dist", ".airlock", ".tox"}
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
        for f in filenames:
            if f.endswith(".py"):
                out.append(str((Path(dirpath) / f).relative_to(root)))
    return out


def unresolved_id(ev: AuthorityEvidence) -> str:
    h = hashlib.sha256(f"{ev.file}|{ev.function}|{ev.action}|{ev.via}|{ev.call}".encode()).hexdigest()
    return "u_" + h[:12]


def discover(root: Path, *, env: dict[str, str] | None = None) -> Discovery:
    root = root.resolve()
    runtime = detect_runtime(root)
    d = Discovery(root=root, runtime=runtime, command=detect_command(root))
    if runtime != "python":
        return d
    file_env, _used = load_env_files(root)
    example_env, _ = load_env_files(root, (".env.example", ".env.sample", ".env.template"))
    scan_env = {**file_env, **(env if env is not None else dict(os.environ))}
    report = extract_authority(root, env=scan_env)
    d.files_analysed = report.files_analysed
    d.parse_errors = report.parse_errors
    d.evidence = list(report.evidence)

    # credentials ---------------------------------------------------------------------------------------
    referenced = _env_names_in_code(root, _python_files(root)) | set(example_env) | set(file_env)
    for ev in report.evidence:
        for prefix, name in IMPLICIT_CREDENTIALS.items():
            if ev.via.startswith(prefix):
                referenced.add(name)
    for name in sorted(referenced):
        if name in KNOWN_CREDENTIALS:
            d.credentials[name] = list(hosts_for(name, scan_env))
        elif looks_secret(name):
            d.unmanaged_secrets.append(name)
    credential_hosts = {h for hosts in d.credentials.values() for h in hosts}

    # authority -----------------------------------------------------------------------------------------
    for ev in report.evidence:
        if ev.resource_state is ResourceState.UNRESOLVED:
            d.unresolved.append(UnresolvedItem(
                id=unresolved_id(ev), action=ev.action, missing=list(ev.unresolved_parts) or ["target"], file=ev.file,
                line=ev.line, function=ev.function, via=ev.via, reason=ev.reason))
            continue
        assert ev.resource is not None
        if ev.action.startswith("http.") and ev.method in ("get", "head", "options"):
            host = ev.resource.split("/", 1)[0]
            if host not in credential_hosts:
                d.reads_skipped += 1
                continue
        key = (ev.action, ev.resource)
        entry = d.entries.get(key)
        if entry is None:
            entry = d.entries[key] = AuthorityEntry(ev.action, ev.resource)
        evid = Evidence(ev.file, ev.line, ev.function, ev.via)
        if all((x.file, x.line) != (evid.file, evid.line) for x in entry.evidence):
            entry.evidence.append(evid)
    return d
