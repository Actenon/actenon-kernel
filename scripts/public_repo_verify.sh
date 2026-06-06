#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0
TMP_BASE="${TMPDIR:-/var/tmp}"
if [[ ! -d "$TMP_BASE" || ! -w "$TMP_BASE" ]]; then
  TMP_BASE="/var/tmp"
fi
TEMP_ROOT="$(mktemp -d "$TMP_BASE/actenon-public-verify.XXXXXX")"
VENV_DIR="$TEMP_ROOT/venv"
RELEASE_ARCHIVE="$TEMP_ROOT/actenon-kernel-release.zip"

cleanup() {
  rm -rf "$TEMP_ROOT"
}

trap cleanup EXIT

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}

require_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    pass "file exists: ${path#$ROOT_DIR/}"
  else
    fail "missing file: ${path#$ROOT_DIR/}"
  fi
}

require_contains() {
  local path="$1"
  local needle="$2"
  local description="$3"
  if grep -Fiq "$needle" "$path"; then
    pass "$description"
  else
    fail "$description (missing '$needle' in ${path#$ROOT_DIR/})"
  fi
}

run_with_venv() {
  TMPDIR="$TMP_BASE" PATH="$VENV_DIR/bin:$PATH" "$@"
}

main() {
  local required_files=(
    "$ROOT_DIR/README.md"
    "$ROOT_DIR/CATEGORY.md"
    "$ROOT_DIR/SPEC_INDEX.md"
    "$ROOT_DIR/KERNEL_GUARANTEES.md"
    "$ROOT_DIR/THREAT_MODEL.md"
    "$ROOT_DIR/CONFORMANCE.md"
    "$ROOT_DIR/INTEGRATIONS.md"
    "$ROOT_DIR/MCP_HERO_PATH.md"
    "$ROOT_DIR/SDK_SELECTION_GUIDE.md"
    "$ROOT_DIR/SUPPORT_AND_COMPATIBILITY_STATUS.md"
    "$ROOT_DIR/pyproject.toml"
    "$ROOT_DIR/Makefile"
    "$ROOT_DIR/CONTRIBUTING.md"
    "$ROOT_DIR/SECURITY.md"
    "$ROOT_DIR/CODE_OF_CONDUCT.md"
    "$ROOT_DIR/LICENSE"
    "$ROOT_DIR/.gitignore"
    "$ROOT_DIR/QUICKSTART.md"
    "$ROOT_DIR/docs/README.md"
    "$ROOT_DIR/docs/guides/FIRST_10_MINUTES.md"
    "$ROOT_DIR/docs/guides/INTEGRATION_QUICKSTART.md"
    "$ROOT_DIR/docs/reference/verifier/VERIFIER_SDK_REFERENCE.md"
    "$ROOT_DIR/docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md"
    "$ROOT_DIR/OPEN_SOURCE_BOUNDARY.md"
    "$ROOT_DIR/.github/workflows/ci.yml"
    "$ROOT_DIR/.github/actions/execution-gap-scan/emit_scan_outputs.py"
    "$ROOT_DIR/scripts/public_repo_verify.sh"
    "$ROOT_DIR/scripts/create_release_archive.sh"
    "$ROOT_DIR/scripts/validate_release_archive.sh"
  )

  printf 'Running public repo verification from %s\n' "$ROOT_DIR"

  for file_path in "${required_files[@]}"; do
    require_file "$file_path"
  done

  require_contains "$ROOT_DIR/README.md" "No valid proof, no execution" "readme states the core principle"
  require_contains "$ROOT_DIR/README.md" "See it in 60 seconds" "readme documents local try-it path"
  require_contains "$ROOT_DIR/README.md" "FIRST_10_MINUTES" "readme links the first 10 minutes guide"
  require_contains "$ROOT_DIR/README.md" "MCP_HERO_PATH" "readme links the MCP hero path"
  require_contains "$ROOT_DIR/README.md" "SDK_SELECTION_GUIDE" "readme links the SDK selection guide"
  require_contains "$ROOT_DIR/QUICKSTART.md" "python3 -m pip install -e" "quickstart documents install"
  require_contains "$ROOT_DIR/QUICKSTART.md" "make public-verify" "quickstart documents public verification"
  require_contains "$ROOT_DIR/docs/guides/FIRST_10_MINUTES.md" "bash ./scripts/first_run.sh" "first 10 minutes documents the first command"
  require_contains "$ROOT_DIR/docs/guides/INTEGRATION_QUICKSTART.md" "VerifierSDK" "integration quickstart documents the verifier SDK"
  require_contains "$ROOT_DIR/docs/guides/INTEGRATION_QUICKSTART.md" "hello_world_protected_resource_python" "integration quickstart documents the hello-world example"
  require_contains "$ROOT_DIR/OPEN_SOURCE_BOUNDARY.md" "paid control plane" "open-source boundary names the paid layer"
  require_contains "$ROOT_DIR/.github/workflows/ci.yml" "\"3.11\"" "ci covers python 3.11"
  require_contains "$ROOT_DIR/.github/workflows/ci.yml" "bash scripts/demo_hero.sh" "ci runs the public demo"
  require_contains "$ROOT_DIR/.github/workflows/ci.yml" "bash scripts/verify_readme_quickstart.sh" "ci verifies the README quickstart"
  require_contains "$ROOT_DIR/.github/workflows/ci.yml" "actenon.cli conformance run" "ci runs conformance"
  require_contains "$ROOT_DIR/.github/workflows/ci.yml" "actenon.cli scan local" "ci runs the local scanner"
  require_contains "$ROOT_DIR/.github/workflows/ci.yml" "pytest tests/ -q" "ci runs full tests"
  require_contains "$ROOT_DIR/.github/actions/execution-gap-scan/emit_scan_outputs.py" "GITHUB_OUTPUT" "scan output action writes github outputs"
  require_contains "$ROOT_DIR/.gitignore" "__MACOSX/" "gitignore excludes __MACOSX"
  require_contains "$ROOT_DIR/.gitignore" ".DS_Store" "gitignore excludes .DS_Store"
  require_contains "$ROOT_DIR/.gitignore" "._*" "gitignore excludes AppleDouble files"
  require_contains "$ROOT_DIR/.gitignore" "node_modules/" "gitignore excludes node_modules"

  if [[ -z "$(find "$ROOT_DIR" \( -path '*/__MACOSX*' -o -name '.DS_Store' -o -name '._*' \) -print -quit)" ]]; then
    pass "metadata residue is absent from the working tree"
  else
    fail "metadata residue is present in the working tree"
  fi

  if python3 -m venv "$VENV_DIR" >/dev/null 2>&1; then
    pass "temporary virtual environment created"
  else
    fail "temporary virtual environment creation failed"
  fi

  if run_with_venv make install >/dev/null 2>&1; then
    pass "editable install path works"
  else
    fail "editable install path failed"
  fi

  if run_with_venv python -m pip install pytest ruff build >/dev/null 2>&1; then
    pass "public test tools install"
  else
    fail "public test tools install failed"
  fi

  if run_with_venv python -m build "$ROOT_DIR" >/dev/null 2>&1; then
    pass "build path works"
  else
    fail "build path failed"
  fi

  if run_with_venv bash "$ROOT_DIR/scripts/verify_release_gate.sh" "$TEMP_ROOT/actenon-kernel-public.tar.gz" >/dev/null 2>&1; then
    pass "public release gate passes"
  else
    fail "public release gate failed"
  fi

  if bash "$ROOT_DIR/scripts/create_release_archive.sh" "$RELEASE_ARCHIVE" >/dev/null 2>&1; then
    pass "release archive builds cleanly"
  else
    fail "release archive build failed"
  fi

  if bash "$ROOT_DIR/scripts/validate_release_archive.sh" "$RELEASE_ARCHIVE" >/dev/null 2>&1
  then
    pass "release archive excludes forbidden metadata paths"
  else
    fail "release archive contains forbidden metadata paths"
  fi

  if ((FAILURES > 0)); then
    printf '\nPublic repo verification failed with %d issue(s).\n' "$FAILURES" >&2
    exit 1
  fi

  printf '\nPASS: Public repository is installable, testable, and release-ready for the open kernel scope.\n'
  printf 'Public release gate: scripts/public_repo_verify.sh\n'
}

main "$@"
