#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

cd "$ROOT_DIR"

output="$("$PYTHON_BIN" examples/quickstart_min.py)"
printf '%s\n' "$output"

expected_lines=(
  "ACTENON QUICKSTART"
  "valid: EXECUTED"
  "mismatch: REFUSED (INTENT_MISMATCH)"
  "replay: REFUSED (DUPLICATE_REPLAY)"
  "side_effects: 1"
  "No valid proof, no execution."
)

for expected in "${expected_lines[@]}"; do
  if ! grep -Fqx "$expected" <<<"$output"; then
    printf 'README quickstart output missing expected line: %s\n' "$expected" >&2
    exit 1
  fi
done

printf 'PASS: README quickstart output matches the documented result.\n'
