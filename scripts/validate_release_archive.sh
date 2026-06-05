#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s <archive.zip>\n' "${BASH_SOURCE[0]}" >&2
  exit 64
fi

ARCHIVE_PATH="$1"

python3 - "$ARCHIVE_PATH" <<'PY'
import fnmatch
import sys
import zipfile
from pathlib import Path

archive_path = Path(sys.argv[1]).resolve()
if not archive_path.exists():
    raise SystemExit(f"Archive not found: {archive_path}")

forbidden = []
forbidden_dir_parts = {
    ".actenon",
    ".git",
    ".maintainers",
    ".pytest_cache",
    "__MACOSX",
    "artifacts",
    "build",
    "dist",
    "node_modules",
}
forbidden_prefixes = (
    "docs/maintainer-notes/",
    "docs/project-history/",
)
forbidden_patterns = (
    "*_ACCEPTANCE.md",
    "*_AUDIT.md",
    "*_CHECK.md",
    "*_CHECKLIST.md",
    "*_REPORT.md",
    "FINAL_*",
    "LAUNCH_*",
    "PUBLIC_*",
    "*_LAUNCH_NOTES.md",
    "*.sqlite",
    "*.sqlite-shm",
    "*.sqlite-wal",
    "*.sqlite3",
    "*.sqlite3-shm",
    "*.sqlite3-wal",
    "*.db",
    "*.db-shm",
    "*.db-wal",
)
with zipfile.ZipFile(archive_path) as archive:
    names = archive.namelist()

    for name in names:
        normalized = name.strip("/")
        parts = normalized.split("/")
        base = parts[-1]
        if (
            any(part in forbidden_dir_parts for part in parts)
            or any(normalized.startswith(prefix) for prefix in forbidden_prefixes)
            or base == ".DS_Store"
            or base.startswith("._")
            or any(fnmatch.fnmatchcase(base, pattern) for pattern in forbidden_patterns)
        ):
            forbidden.append(name)

print(f"Validated archive: {archive_path}")
print(f"Archive entries: {len(names)}")
print(f"Forbidden path count: {len(forbidden)}")

if forbidden:
    print("Forbidden paths:")
    for path in forbidden:
        print(path)
    raise SystemExit(1)

print("Forbidden paths: none")
PY
