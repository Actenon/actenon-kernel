#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${1:-$ROOT_DIR/dist/actenon-kernel-public.tar.gz}"

if [[ "${ACTENON_RELEASE_GATE_PASSED:-}" != "1" && "${ACTENON_INTERNAL_PUBLIC_BOUNDARY_VALIDATION:-}" != "1" ]]; then
  printf 'Refusing to build public release archive before release gates pass.\n' >&2
  printf 'Run: bash scripts/verify_release_gate.sh\n' >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - "$ROOT_DIR" "$OUTPUT_PATH" <<'PY'
from __future__ import annotations

import fnmatch
import io
import os
import stat
import sys
import tarfile
from pathlib import Path

root_dir = Path(sys.argv[1]).resolve()
output_path = Path(sys.argv[2]).resolve()

allowed_dirs = (
    ".github",
    "actenon",
    "sdk",
    "examples",
    "schemas",
    "spec",
    "conformance",
    "tests",
    "docs",
    "scripts",
)

allowed_root_files = {
    "ADOPTION_DECISION_RECORD_TEMPLATE.md",
    "CATEGORY.md",
    "CODE_OF_CONDUCT.md",
    "COMPLIANCE_MAPPING.md",
    "CONFORMANCE.md",
    "CONTRIBUTING.md",
    "CROSS_REPO_WIRE_CONTRACTS.md",
    "GOVERNANCE.md",
    "INCIDENT_ANALYSIS_TEMPLATE.md",
    "INTEGRATIONS.md",
    "KERNEL_GUARANTEES.md",
    "LICENSE",
    "MCP_HERO_PATH.md",
    "MULTI_AGENT_EXECUTION_MODEL.md",
    "Makefile",
    "OPEN_SOURCE_BOUNDARY.md",
    "PUBLIC_REPO_BOUNDARY.md",
    "QUICKSTART.md",
    "README.md",
    "REVOCATION_AND_RECEIPT_DURABILITY.md",
    "SDK_SELECTION_GUIDE.md",
    "SECURITY.md",
    "SPEC_INDEX.md",
    "SUPPORT_AND_COMPATIBILITY_STATUS.md",
    "THE_EXECUTION_GAP.md",
    "THREAT_MODEL.md",
    "TRACE_VIEWER.md",
    "VERSIONING_POLICY.md",
    "pyproject.toml",
}

forbidden_dir_parts = {
    ".actenon",
    ".actenon-scan",
    ".git",
    ".maintainers",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__MACOSX",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "venv",
}

forbidden_prefixes = (
    "AI Agent Execution Control Layer/",
    "actenon-cloud/",
    "docs/maintainer-notes/",
    "docs/project-history/",
    "apps/",
    "var/",
)

forbidden_file_patterns = (
    ".coverage",
    ".coverage.*",
    ".*.swp",
    "*_ACCEPTANCE.md",
    "*_AUDIT.md",
    "*_CHECK.md",
    "*_CHECKLIST.md",
    "*_REPORT.md",
    "FINAL_*",
    "LAUNCH_*",
    "PUBLIC_LAUNCH_READINESS.md",
    "*_LAUNCH_NOTES.md",
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "*.egg",
    "*.egg-info",
    "*.sqlite",
    "*.sqlite-shm",
    "*.sqlite-wal",
    "*.sqlite3",
    "*.sqlite3-shm",
    "*.sqlite3-wal",
)

private_text_patterns = (
    "*SOW*",
    "*STATEMENT_OF_WORK*",
    "*PRICING*",
    "*ICP*",
    "*OBJECTION*",
    "*GTM*",
    "*DESIGN_PARTNER*",
    "*COMMERCIAL_MODEL*",
    "*COMMERCIAL_PROPOSAL*",
)

fixed_mtime = 1_704_067_200  # 2024-01-01T00:00:00Z


def is_forbidden(relative_path: str) -> bool:
    normalized = relative_path.replace(os.sep, "/")
    parts = normalized.split("/")
    basename = parts[-1]
    upper_name = basename.upper()
    if any(part in forbidden_dir_parts or part.endswith(".egg-info") for part in parts[:-1]):
        return True
    if any(normalized.startswith(prefix) for prefix in forbidden_prefixes):
        return True
    if basename == ".DS_Store" or basename.startswith("._"):
        return True
    if any(fnmatch.fnmatchcase(basename, pattern) for pattern in forbidden_file_patterns):
        return True
    if any(fnmatch.fnmatchcase(upper_name, pattern) for pattern in private_text_patterns):
        return True
    return False


def is_allowed(relative_path: str) -> bool:
    normalized = relative_path.replace(os.sep, "/")
    if "/" not in normalized:
        return normalized in allowed_root_files
    return normalized.split("/", 1)[0] in allowed_dirs


def iter_members() -> list[tuple[str, Path]]:
    members: list[tuple[str, Path]] = []
    for path in sorted(root_dir.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(root_dir).as_posix()
        if not is_allowed(relative_path):
            continue
        if is_forbidden(relative_path):
            continue
        members.append((relative_path, path))
    return members


archive_members = iter_members()
with tarfile.open(output_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
    for relative_path, source_path in archive_members:
        data = source_path.read_bytes()
        info = tarfile.TarInfo(relative_path)
        info.size = len(data)
        info.mtime = fixed_mtime
        info.mode = stat.S_IMODE(source_path.stat().st_mode)
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        archive.addfile(info, io.BytesIO(data))

print(f"Built public release archive: {output_path}")
print(f"Archive member count: {len(archive_members)}")
PY
