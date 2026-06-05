#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${1:-$ROOT_DIR/dist/actenon-kernel-release.zip}"

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - "$ROOT_DIR" "$OUTPUT_PATH" <<'PY'
import fnmatch
import os
import stat
import sys
import zipfile
from pathlib import Path

root_dir = Path(sys.argv[1]).resolve()
output_path = Path(sys.argv[2]).resolve()

excluded_dir_names = {
    ".actenon",
    ".git",
    ".maintainers",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "__MACOSX",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "node_modules",
    "venv",
}
excluded_file_names = {".DS_Store"}
excluded_prefixes = (
    ".maintainers/",
    "docs/maintainer-notes/",
    "docs/project-history/",
)
excluded_file_patterns = (
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
fixed_timestamp = (2026, 1, 1, 0, 0, 0)


def is_excluded(relative_path: str) -> bool:
    normalized = relative_path.replace(os.sep, "/")
    parts = normalized.split("/")
    if any(part in excluded_dir_names for part in parts[:-1]):
        return True
    if any(normalized.startswith(prefix) for prefix in excluded_prefixes):
        return True
    basename = parts[-1]
    if basename in excluded_file_names or basename.startswith("._"):
        return True
    if any(fnmatch.fnmatchcase(basename, pattern) for pattern in excluded_file_patterns):
        return True
    return False


archive_members: list[tuple[str, Path]] = []
for path in sorted(root_dir.rglob("*")):
    if not path.is_file():
        continue
    relative_path = path.relative_to(root_dir).as_posix()
    if is_excluded(relative_path):
        continue
    archive_members.append((relative_path, path))

with zipfile.ZipFile(output_path, "w") as archive:
    for relative_path, source_path in archive_members:
        mode = source_path.stat().st_mode
        permissions = stat.S_IMODE(mode)
        zip_info = zipfile.ZipInfo(relative_path, date_time=fixed_timestamp)
        zip_info.compress_type = zipfile.ZIP_DEFLATED
        zip_info.create_system = 3
        zip_info.external_attr = (permissions & 0xFFFF) << 16
        zip_info.flag_bits |= 0x800
        archive.writestr(zip_info, source_path.read_bytes())

print(f"Built clean release archive: {output_path}")
print(f"Archive member count: {len(archive_members)}")
PY

bash "$ROOT_DIR/scripts/validate_release_archive.sh" "$OUTPUT_PATH"
