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

# The Go and Rust SDKs live in their own repositories; test them at the
# commits pinned in sdk/standalone-sdk-pins.json against this tree's vectors.
SDK_CACHE="${ACTENON_SDK_CACHE:-$ROOT_DIR/.sdk-cache}"
for sdk in sdk-go sdk-rust; do
  read -r repo sha < <("$PYTHON_BIN" -c "import json,sys; p=json.load(open('sdk/standalone-sdk-pins.json'))[sys.argv[1]]; print(p['repository'], p['sha'])" "$sdk")
  dest="$SDK_CACHE/$sdk"
  if [ "$(git -C "$dest" rev-parse HEAD 2>/dev/null || true)" != "$sha" ]; then
    rm -rf "$dest"
    git init -q "$dest"
    git -C "$dest" fetch -q --depth 1 "https://github.com/$repo" "$sha"
    git -C "$dest" checkout -q FETCH_HEAD
  fi
  test "$(git -C "$dest" rev-parse HEAD)" = "$sha"
  "$PYTHON_BIN" scripts/check_standalone_sdk_fixtures.py "$dest"
done

(
  cd "$SDK_CACHE/sdk-go"
  ACTENON_KERNEL_VECTOR_LOCK="$ROOT_DIR/conformance/vector-lock.json" go test -count=1 ./...
)

(
  cd "$SDK_CACHE/sdk-rust"
  ACTENON_KERNEL_VECTOR_LOCK="$ROOT_DIR/conformance/vector-lock.json" "${CARGO_CMD[@]}" test --all-targets --locked
)

CONFORMANCE_VERSION="$(tr -d '[:space:]' <"$ROOT_DIR/conformance/VERSION")"
printf 'Conformance %s passed: Python, TypeScript, Go (sdk-go@pinned), Rust (sdk-rust@pinned); P10-PUB, P11-PUB, and P12-PUB vectors included.\n' \
  "$CONFORMANCE_VERSION"
