from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REQUIRED_GITIGNORE_ENTRIES = [
    "node_modules/",
    "build/",
    "dist/",
    "artifacts/",
    ".actenon/",
    ".claude/",
    ".pytest_cache/",
    "__MACOSX/",
    ".DS_Store",
    "._*",
    "*.sqlite",
    "*.sqlite3",
    "*.sqlite3-shm",
    "*.sqlite3-wal",
]

FORBIDDEN_DIR_PARTS = {
    ".actenon",
    ".claude",
    ".git",
    ".maintainers",
    ".pytest_cache",
    "__MACOSX",
    "artifacts",
    "build",
    "dist",
    "docs/maintainer-notes",
    "node_modules",
}

FORBIDDEN_SUFFIXES = (
    ".sqlite",
    ".sqlite-shm",
    ".sqlite-wal",
    ".sqlite3",
    ".sqlite3-shm",
    ".sqlite3-wal",
    ".db",
    ".db-shm",
    ".db-wal",
)

FORBIDDEN_REPORT_SUFFIXES = (
    "_ACCEPTANCE.md",
    "_AUDIT.md",
    "_CHECK.md",
    "_CHECKLIST.md",
    "_REPORT.md",
)


def _tracked_files() -> list[str]:
    tracked = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return [path for path in tracked if Path(path).exists()]


def _forbidden_hits(paths: list[str]) -> list[str]:
    hits: list[str] = []
    for path_text in paths:
        path = Path(path_text)
        parts = path.parts
        name = path.name
        normalized = path_text.replace("\\", "/")
        if any(part in FORBIDDEN_DIR_PARTS for part in parts):
            hits.append(path_text)
            continue
        if normalized.startswith("docs/maintainer-notes/"):
            hits.append(path_text)
            continue
        if name.endswith(FORBIDDEN_SUFFIXES):
            hits.append(path_text)
            continue
        if name.endswith(FORBIDDEN_REPORT_SUFFIXES):
            hits.append(path_text)
            continue
        if name == ".DS_Store" or name.startswith("._"):
            hits.append(path_text)
    return hits


def _missing_gitignore_entries() -> list[str]:
    text = Path(".gitignore").read_text(encoding="utf-8")
    return [entry for entry in REQUIRED_GITIGNORE_ENTRIES if entry not in text]


def main() -> int:
    hits = _forbidden_hits(_tracked_files())
    missing_gitignore = _missing_gitignore_entries()

    if not hits and not missing_gitignore:
        print("Public hygiene audit passed.")
        return 0

    if hits:
        print("Forbidden tracked paths:")
        for hit in hits:
            print(hit)
    if missing_gitignore:
        print("Missing .gitignore entries:")
        for entry in missing_gitignore:
            print(entry)
    return 1


if __name__ == "__main__":
    sys.exit(main())
