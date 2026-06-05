#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="$(mktemp -d)"
FAILURES=0

cleanup() {
  rm -rf "$BUILD_ROOT"
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
    pass "file exists: ${path#$DIST_DIR/}"
  else
    fail "missing file: ${path#$DIST_DIR/}"
  fi
}

require_absent() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    pass "excluded file absent: ${path#$DIST_DIR/}"
  else
    fail "excluded file present: ${path#$DIST_DIR/}"
  fi
}

require_contains() {
  local path="$1"
  local needle="$2"
  local description="$3"
  if grep -Fiq "$needle" "$path"; then
    pass "$description"
  else
    fail "$description (missing '$needle' in ${path#$DIST_DIR/})"
  fi
}

ACTENON_PORTABLE_DIST_DIR="$BUILD_ROOT" "$ROOT_DIR/scripts/build_portable_distribution.sh" >/dev/null

DIST_DIR="$BUILD_ROOT/actenon-portable"
ARCHIVE_PATH="$BUILD_ROOT/actenon-portable.tar.gz"

required_files=(
  "$DIST_DIR/README.md"
  "$DIST_DIR/pyproject.toml"
  "$DIST_DIR/OPEN_SOURCE_BOUNDARY.md"
  "$DIST_DIR/docs/reference/verifier/VERIFIER_SDK_REFERENCE.md"
  "$DIST_DIR/docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md"
  "$DIST_DIR/docs/guides/CONFORMANCE_TESTS_GUIDE.md"
  "$DIST_DIR/schemas/action_intent.v1.json"
  "$DIST_DIR/schemas/pccb.v1.json"
  "$DIST_DIR/schemas/receipt.v1.json"
  "$DIST_DIR/schemas/refusal.v1.json"
  "$DIST_DIR/actenon/api/intake.py"
  "$DIST_DIR/actenon/core/errors.py"
  "$DIST_DIR/actenon/models/contracts.py"
  "$DIST_DIR/actenon/models/runtime.py"
  "$DIST_DIR/actenon/proof/service.py"
  "$DIST_DIR/actenon/verifier/sdk.py"
  "$DIST_DIR/actenon/demo/portable_local_proof.py"
  "$DIST_DIR/examples/hello_world_protected_resource_python/protected_resource.py"
  "$DIST_DIR/tests/conformance/test_verifier_sdk_conformance.py"
  "$ARCHIVE_PATH"
)

excluded_files=(
  "$DIST_DIR/actenon/core/kernel.py"
  "$DIST_DIR/actenon/policy/engine.py"
  "$DIST_DIR/actenon/policy/refund.py"
  "$DIST_DIR/actenon/policy/invoice_payment.py"
  "$DIST_DIR/actenon/escrow/base.py"
  "$DIST_DIR/actenon/replay/base.py"
  "$DIST_DIR/actenon/receipts/factory.py"
  "$DIST_DIR/examples/refund_guard_local/protected_endpoint.py"
  "$DIST_DIR/examples/invoice_payment_guard_local/protected_endpoint.py"
  "$DIST_DIR/tests/unit/test_refund_policy.py"
  "$DIST_DIR/tests/unit/test_invoice_payment_policy.py"
)

printf 'Running portable distribution verification from %s\n' "$DIST_DIR"

for path in "${required_files[@]}"; do
  require_file "$path"
done

for path in "${excluded_files[@]}"; do
  require_absent "$path"
done

require_contains "$DIST_DIR/OPEN_SOURCE_BOUNDARY.md" "paid control plane" "open-source boundary documents the paid-layer boundary"
require_contains "$DIST_DIR/docs/reference/verifier/VERIFIER_SDK_REFERENCE.md" "VerifierSDK" "verifier sdk reference documents the SDK entry point"
require_contains "$DIST_DIR/docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md" "portable_local_proof" "hello-world guide documents the portable demo"
require_contains "$DIST_DIR/docs/guides/CONFORMANCE_TESTS_GUIDE.md" "test_verifier_sdk_conformance.py" "conformance guide documents the test entry point"
require_contains "$DIST_DIR/README.md" "portable verifier-side open layer" "portable readme states the distribution boundary"

if python3 -m compileall "$DIST_DIR/actenon" "$DIST_DIR/examples" "$DIST_DIR/tests" >/dev/null 2>&1; then
  pass "portable distribution compiles"
else
  fail "portable distribution failed to compile"
fi

if PYTHONPATH="$DIST_DIR" python3 -m unittest discover -s "$DIST_DIR/tests/conformance" -p 'test_*.py' >/dev/null 2>&1; then
  pass "portable conformance tests pass"
else
  fail "portable conformance tests failed"
fi

demo_artifacts="$(mktemp -d)"
if PYTHONPATH="$DIST_DIR" python3 -m actenon.demo.portable_local_proof --artifacts-dir "$demo_artifacts" >/dev/null 2>&1; then
  pass "portable local proof demo passes"
else
  fail "portable local proof demo failed"
fi

if [[ -f "$demo_artifacts/manifest.json" && -f "$demo_artifacts/pccb.json" && -f "$demo_artifacts/protected_resource_response.json" ]]; then
  pass "portable local proof artifacts are written"
else
  fail "portable local proof artifacts are missing"
fi

rm -rf "$demo_artifacts"

if ((FAILURES > 0)); then
  printf '\nPortable distribution verification failed with %d issue(s).\n' "$FAILURES" >&2
  exit 1
fi

printf '\nPASS: Portable distribution is internally consistent.\n'
printf 'Portable acceptance gate: scripts/verify_portable_distribution.sh\n'
