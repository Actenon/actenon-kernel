#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if command -v cargo >/dev/null 2>&1; then
  CARGO_CMD=(cargo)
elif command -v rustup >/dev/null 2>&1; then
  RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-$(rustup toolchain list | awk '/active, default/{print $1; exit}')}"
  RUST_BIN_DIR="$(dirname "$(rustup which --toolchain "$RUST_TOOLCHAIN" cargo)")"
  PATH="$RUST_BIN_DIR:$PATH"
  export PATH
  CARGO_CMD=("$RUST_BIN_DIR/cargo")
else
  printf 'cargo or rustup is required for Rust SDK conformance.\n' >&2
  exit 1
fi

cd "$ROOT_DIR"

"$PYTHON_BIN" -m unittest \
  actenon.conformance.test_verifier_sdk_conformance.VerifierSdkConformanceTests.test_shared_cross_sdk_conformance_vectors

(
  cd sdk/typescript
  node --import tsx --test ./tests/verifier-conformance.test.ts
)

(
  cd sdk/go
  go test ./verifier -run '^TestSharedVerifierConformanceVectors$'
)

(
  cd sdk/rust
  "${CARGO_CMD[@]}" test --test verifier_conformance_test
)

printf 'Shared verifier SDK conformance passed: Python, TypeScript, Go, Rust.\n'
