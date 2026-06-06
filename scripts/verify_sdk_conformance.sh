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

"$PYTHON_BIN" scripts/verify_conformance_manifest.py
"$PYTHON_BIN" -m actenon.cli conformance run --require-complete

(
  cd sdk/typescript
  node --import tsx --test \
    ./tests/verifier-conformance.test.ts \
    ./tests/countersignature.test.ts \
    ./tests/transparency.test.ts \
    ./tests/trust-artifacts.test.ts
)

(
  cd sdk/go
  go test ./verifier
)

(
  cd sdk/rust
  "${CARGO_CMD[@]}" test --tests
)

CONFORMANCE_VERSION="$(tr -d '[:space:]' <"$ROOT_DIR/conformance/VERSION")"
printf 'Conformance %s passed: Python, TypeScript, Go, Rust; P10-PUB, P11-PUB, and P12-PUB vectors included.\n' \
  "$CONFORMANCE_VERSION"
