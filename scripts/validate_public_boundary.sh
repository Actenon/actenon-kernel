#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/actenon-public-boundary.XXXXXX")"
ARCHIVE_PATH="$TMP_ROOT/actenon-kernel-public.tar.gz"
BUILD_OUT="$TMP_ROOT/package-build"

cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

note() {
  printf 'NOTE: %s\n' "$1"
}

cd "$ROOT_DIR"

"$PYTHON_BIN" - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import fnmatch
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()

private_patterns = (
    "AI Agent Execution Control Layer/*",
    "actenon-cloud/*",
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

local_state_patterns = (
    ".actenon/*",
    "*/.actenon/*",
    ".actenon-scan/*",
    "*/.actenon-scan/*",
    ".ruff_cache/*",
    "*/.ruff_cache/*",
    ".pytest_cache/*",
    "*/.pytest_cache/*",
    ".mypy_cache/*",
    "*/.mypy_cache/*",
    ".coverage",
    ".coverage.*",
    "*/.coverage",
    "*/.coverage.*",
    "htmlcov/*",
    "*/htmlcov/*",
    "__MACOSX/*",
    "*/__MACOSX/*",
    "*.sqlite",
    "*.sqlite-shm",
    "*.sqlite-wal",
    "*.sqlite3",
    "*.sqlite3-shm",
    "*.sqlite3-wal",
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "node_modules/*",
    "*/node_modules/*",
    "build/*",
    "*/build/*",
    "dist/*",
    "*/dist/*",
    "*.egg-info/*",
    "*/*.egg-info/*",
    "*/.DS_Store",
    ".DS_Store",
    "._*",
    "*/._*",
)

tracked = subprocess.run(["git", "ls-files"], check=True, capture_output=True, text=True).stdout.splitlines()
private_hits: list[str] = []
local_hits: list[str] = []
for path in tracked:
    normalized = path.replace("\\", "/")
    upper_path = normalized.upper()
    exists = (root / path).exists()
    if any(fnmatch.fnmatchcase(normalized, pattern) or fnmatch.fnmatchcase(upper_path, pattern.upper()) for pattern in private_patterns):
        private_hits.append(path)
    if exists and any(
        fnmatch.fnmatchcase(normalized, pattern) or fnmatch.fnmatchcase(upper_path, pattern.upper())
        for pattern in local_state_patterns
    ):
        local_hits.append(path)

if private_hits:
    print("Tracked private Cloud/GTM material:")
    for hit in private_hits:
        print(hit)
    raise SystemExit(1)

if local_hits:
    print("Tracked local runtime/archive material present in working tree:")
    for hit in local_hits:
        print(hit)
    raise SystemExit(1)

print("Tracked private Cloud/GTM material: none")
print("Tracked local runtime/archive material present in working tree: none")
PY
pass "git-tracked public boundary check"

if [[ -d "$ROOT_DIR/AI Agent Execution Control Layer" ]]; then
  note "local nested Cloud checkout exists but is not part of the public allowlist"
fi
if [[ -d "$ROOT_DIR/.actenon" ]]; then
  note "local .actenon runtime state exists but is not part of the public allowlist"
fi
if find "$ROOT_DIR" -maxdepth 3 \( -name ".DS_Store" -o -name "__MACOSX" -o -name "node_modules" -o -name "dist" -o -name "build" \) -print -quit | grep -q .; then
  note "local generated/archive debris exists; validation verifies it is not tracked, packaged, or archived"
fi

if "$PYTHON_BIN" -m build --version >/dev/null 2>&1; then
  "$PYTHON_BIN" -m build "$ROOT_DIR" --outdir "$BUILD_OUT" >/dev/null
else
  fail "python build module is unavailable; install with: $PYTHON_BIN -m pip install build"
fi

"$PYTHON_BIN" - "$BUILD_OUT" <<'PY'
from __future__ import annotations

import fnmatch
import tarfile
import sys
import zipfile
from pathlib import Path

build_out = Path(sys.argv[1]).resolve()

forbidden_patterns = (
    "AI Agent Execution Control Layer/*",
    "actenon-cloud/*",
    ".actenon/*",
    "*/.actenon/*",
    ".actenon-scan/*",
    "*/.actenon-scan/*",
    ".ruff_cache/*",
    "*/.ruff_cache/*",
    ".pytest_cache/*",
    "*/.pytest_cache/*",
    ".mypy_cache/*",
    "*/.mypy_cache/*",
    ".coverage",
    ".coverage.*",
    "*/.coverage",
    "*/.coverage.*",
    "htmlcov/*",
    "*/htmlcov/*",
    "*.sqlite",
    "*.sqlite-shm",
    "*.sqlite-wal",
    "*.sqlite3",
    "*.sqlite3-shm",
    "*.sqlite3-wal",
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "*/.DS_Store",
    ".DS_Store",
    "__MACOSX/*",
    "*/__MACOSX/*",
    "*/.git/*",
    ".git/*",
    "*/node_modules/*",
    "node_modules/*",
    "*/build/*",
    "build/*",
    "*/dist/*",
    "dist/*",
    "*/artifacts/*",
    "artifacts/*",
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


def names_for(path: Path) -> list[str]:
    if path.suffix == ".whl" or path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if path.name.endswith(".tar.gz") or path.name.endswith(".tgz"):
        with tarfile.open(path) as archive:
            return archive.getnames()
    return []


hits: list[tuple[str, str]] = []
artifacts = sorted(build_out.glob("*"))
if not artifacts:
    raise SystemExit("No package build artifacts found")
for artifact in artifacts:
    for name in names_for(artifact):
        normalized = name.strip("/")
        upper_name = normalized.upper()
        if any(fnmatch.fnmatchcase(normalized, pattern) or fnmatch.fnmatchcase(upper_name, pattern) for pattern in forbidden_patterns):
            hits.append((artifact.name, name))

if hits:
    print("Forbidden package build members:")
    for artifact, member in hits:
        print(f"{artifact}: {member}")
    raise SystemExit(1)

print(f"Package build artifacts checked: {len(artifacts)}")
PY
pass "package build excludes private/local material"

ACTENON_INTERNAL_PUBLIC_BOUNDARY_VALIDATION=1 bash "$ROOT_DIR/scripts/create_public_release_archive.sh" "$ARCHIVE_PATH" >/dev/null

"$PYTHON_BIN" - "$ARCHIVE_PATH" <<'PY'
from __future__ import annotations

import fnmatch
import sys
import tarfile
from pathlib import Path

archive_path = Path(sys.argv[1]).resolve()

allowed_top_level_dirs = {
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
}

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

forbidden_patterns = (
    "AI Agent Execution Control Layer/*",
    "actenon-cloud/*",
    ".actenon/*",
    "*/.actenon/*",
    ".actenon-scan/*",
    "*/.actenon-scan/*",
    ".git/*",
    "*/.git/*",
    ".ruff_cache/*",
    "*/.ruff_cache/*",
    ".pytest_cache/*",
    "*/.pytest_cache/*",
    ".mypy_cache/*",
    "*/.mypy_cache/*",
    ".coverage",
    ".coverage.*",
    "*/.coverage",
    "*/.coverage.*",
    "htmlcov/*",
    "*/htmlcov/*",
    "__MACOSX/*",
    "*/__MACOSX/*",
    ".DS_Store",
    "*/.DS_Store",
    "._*",
    "*/._*",
    "*/node_modules/*",
    "node_modules/*",
    "*/build/*",
    "build/*",
    "*/dist/*",
    "dist/*",
    "*/artifacts/*",
    "artifacts/*",
    "*.egg-info/*",
    "*/*.egg-info/*",
    "*.sqlite",
    "*.sqlite-shm",
    "*.sqlite-wal",
    "*.sqlite3",
    "*.sqlite3-shm",
    "*.sqlite3-wal",
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "*_ACCEPTANCE.md",
    "*_AUDIT.md",
    "*_CHECK.md",
    "*_CHECKLIST.md",
    "*_REPORT.md",
    "FINAL_*",
    "LAUNCH_*",
    "PUBLIC_LAUNCH_READINESS.md",
    "*_LAUNCH_NOTES.md",
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

with tarfile.open(archive_path) as archive:
    names = [name.strip("/") for name in archive.getnames()]

forbidden_hits: list[str] = []
outside_allowlist: list[str] = []
for name in names:
    upper_name = name.upper()
    if any(fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(upper_name, pattern) for pattern in forbidden_patterns):
        forbidden_hits.append(name)
    if "/" in name:
        top = name.split("/", 1)[0]
        if top not in allowed_top_level_dirs:
            outside_allowlist.append(name)
    elif name not in allowed_root_files:
        outside_allowlist.append(name)

if forbidden_hits:
    print("Forbidden release archive members:")
    for hit in forbidden_hits:
        print(hit)
    raise SystemExit(1)

if outside_allowlist:
    print("Members outside public release allowlist:")
    for hit in outside_allowlist:
        print(hit)
    raise SystemExit(1)

print(f"Release archive entries checked: {len(names)}")
PY
pass "public release archive excludes private/local/generated material"

printf '\nPASS: Public repository boundary validation completed.\n'
