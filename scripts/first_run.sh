#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf 'Running zero-credential local proof demo...\n'
"$ROOT_DIR/scripts/run_local_proof.sh"

printf '\nNext reads:\n'
printf ' - %s\n' "$ROOT_DIR/docs/guides/FIRST_10_MINUTES.md"
printf ' - %s\n' "$ROOT_DIR/docs/guides/LOCAL_PROOF_RUNBOOK.md"
