#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${ACTENON_DEMO_ARTIFACTS_DIR:-$ROOT_DIR/artifacts/local_proof}"
LEGACY_STATE_DIR="$ROOT_DIR/.actenon"

rm -rf "$ARTIFACT_DIR"
rm -rf "$LEGACY_STATE_DIR"

printf 'Reset local proof demo state.\n'
printf 'Removed artifacts: %s\n' "$ARTIFACT_DIR"
printf 'Removed local state: %s\n' "$LEGACY_STATE_DIR"
