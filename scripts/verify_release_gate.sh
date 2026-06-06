#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
ARCHIVE_PATH="${1:-$ROOT_DIR/dist/actenon-kernel-public.tar.gz}"

KEYSTONE_TESTS=(
  "tests/integration/test_cloud_invoice_payment_conformance_vector.py"
  "tests/unit/test_outcome_attestation.py"
  "tests/unit/test_external_anchors.py"
  "tests/unit/test_canonicalization_interop.py"
  "tests/conformance"
  "actenon/conformance/test_outcome_attestation_conformance.py"
)

RUFF_TARGETS=(
  "actenon/anchors"
  "actenon/conformance"
  "actenon/proof/signers/well_known.py"
  "actenon/receipts/attestation.py"
  "conformance"
  "tests/conformance"
  "tests/integration/test_cloud_invoice_payment_conformance_vector.py"
  "tests/unit/test_canonicalization_interop.py"
  "tests/unit/test_external_anchors.py"
  "tests/unit/test_outcome_attestation.py"
  "scripts/public_hygiene_audit.py"
)

run_step() {
  local label="$1"
  shift
  printf '\n==> %s\n' "$label"
  "$@"
}

run_ruff() {
  if "$PYTHON_BIN" -m ruff --version >/dev/null 2>&1; then
    run_step "ruff check" "$PYTHON_BIN" -m ruff check "${RUFF_TARGETS[@]}"
    return
  fi
  if command -v ruff >/dev/null 2>&1; then
    run_step "ruff check" ruff check "${RUFF_TARGETS[@]}"
    return
  fi
  printf 'FAIL: ruff is required for the release gate; install ruff or run with PYTHON pointing at an environment that has it.\n' >&2
  exit 1
}

validate_public_archive() {
  local archive_path="$1"
  "$PYTHON_BIN" - "$archive_path" <<'PY'
from __future__ import annotations

import fnmatch
import sys
import tarfile
from pathlib import Path

archive_path = Path(sys.argv[1]).resolve()
if not archive_path.exists():
    raise SystemExit(f"release archive was not produced: {archive_path}")

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
    "*/.ruff_cache/*",
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

if not names:
    raise SystemExit("release archive is empty")

hits: list[str] = []
for name in names:
    upper_name = name.upper()
    if any(fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(upper_name, pattern) for pattern in forbidden_patterns):
        hits.append(name)

if hits:
    print("Forbidden release archive members:")
    for hit in hits:
        print(hit)
    raise SystemExit(1)

print(f"Release archive entries checked: {len(names)}")
PY
}

cd "$ROOT_DIR"

run_step "consequential action coverage matrix" "$PYTHON_BIN" -m actenon.cli coverage run
run_step "focused keystone suite" "$PYTHON_BIN" -m pytest "${KEYSTONE_TESTS[@]}" -q
run_step "full kernel test suite" "$PYTHON_BIN" -m pytest tests/ -q
run_ruff
run_step "public boundary validation" env ACTENON_INTERNAL_PUBLIC_BOUNDARY_VALIDATION=1 "$ROOT_DIR/scripts/validate_public_boundary.sh"
run_step "public release archive creation" env ACTENON_RELEASE_GATE_PASSED=1 "$ROOT_DIR/scripts/create_public_release_archive.sh" "$ARCHIVE_PATH"
run_step "public release archive validation" validate_public_archive "$ARCHIVE_PATH"

printf '\nPASS: Release gate completed. Coverage matrix, keystone, full suite, ruff, public boundary, and archive checks are green.\n'
printf 'Release gate command: bash scripts/verify_release_gate.sh\n'
