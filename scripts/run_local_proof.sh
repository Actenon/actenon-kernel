#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${ACTENON_DEMO_ARTIFACTS_DIR:-$ROOT_DIR/artifacts/local_proof}"

if [[ "${ACTENON_DEMO_SKIP_RESET:-0}" != "1" ]]; then
  ACTENON_DEMO_ARTIFACTS_DIR="$ARTIFACT_DIR" "$ROOT_DIR/scripts/reset_demo_state.sh" >/dev/null
fi

mkdir -p "$ARTIFACT_DIR"

PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
python3 -m actenon.demo.local_proof --artifacts-dir "$ARTIFACT_DIR"

printf '\nArtifacts written to: %s\n' "$ARTIFACT_DIR"
printf 'Manifest: %s\n' "$ARTIFACT_DIR/manifest.json"
printf 'Summary: %s\n' "$ARTIFACT_DIR/SUMMARY.txt"
