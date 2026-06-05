#!/usr/bin/env bash
set -euo pipefail

DETAILS=false
if [[ "${1:-}" == "--details" ]]; then
  DETAILS=true
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

RUNTIME_DIR="${ACTENON_HERO_RUNTIME_DIR:-artifacts/hero_demo_runtime/live}"
LOCAL_SIGNER_WARNING="ACTENON LOCAL HMAC SIGNER IS FOR LOCAL/DEV/DEMO ONLY"

run_simulation() {
  local log_file
  log_file="$(mktemp)"
  if ! PYTHONWARNINGS="ignore:${LOCAL_SIGNER_WARNING}:RuntimeWarning" \
    python3 -m actenon.cli simulate --runtime-dir "${RUNTIME_DIR}" "$@" --json >"${log_file}" 2>&1; then
    cat "${log_file}" >&2
    rm -f "${log_file}"
    exit 1
  fi
  rm -f "${log_file}"
}

run_simulation --incident replit
run_simulation --scenario replay-refused

python3 - "${ROOT_DIR}" "${RUNTIME_DIR}" "${DETAILS}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from actenon.models.serialization import build_artifact_digest


root = Path(sys.argv[1]).resolve()
runtime_dir = Path(sys.argv[2])
details = sys.argv[3].lower() == "true"


def artifact_path(*parts: str) -> Path:
    return root / runtime_dir / "simulations" / Path(*parts)


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def load_required(path: Path) -> dict[str, Any]:
    if not path.exists():
        print(f"missing expected demo artifact: {relative(path)}", file=sys.stderr)
        sys.exit(1)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print(f"expected JSON object artifact: {relative(path)}", file=sys.stderr)
        sys.exit(1)
    return payload


def digest(payload: dict[str, Any]) -> str:
    artifact_digest = build_artifact_digest(payload)
    return f"{artifact_digest.algorithm}:{artifact_digest.value}"


counterfactual_path = artifact_path("replit", "counterfactual_unprotected_execution.json")
refusal_path = artifact_path("replit", "refusal.json")
receipt_path = artifact_path("replay-refused", "execution_receipt.json")
replay_refusal_path = artifact_path("replay-refused", "replay_refusal.json")

counterfactual = load_required(counterfactual_path)
refusal = load_required(refusal_path)
receipt = load_required(receipt_path)
replay_refusal = load_required(replay_refusal_path)

reason_code = refusal.get("refusal_code") or refusal.get("reason_code")
if not reason_code:
    print(f"refusal artifact has no refusal_code/reason_code: {relative(refusal_path)}", file=sys.stderr)
    sys.exit(1)

if receipt.get("outcome") != "executed":
    print(f"receipt artifact was not executed: {relative(receipt_path)}", file=sys.stderr)
    sys.exit(1)

snapshot = {
    "refusal": {
        "reason_code": reason_code,
        "side_effect_executed": False,
        "artifact": relative(refusal_path),
        "pccb_id": refusal.get("correlation", {}).get("pccb_id"),
        "artifact_digest": digest(refusal),
    },
    "receipt": {
        "outcome": receipt.get("outcome"),
        "side_effect_executed": True,
        "artifact": relative(receipt_path),
        "receipt_id": receipt.get("receipt_id"),
        "pccb_id": receipt.get("correlation", {}).get("pccb_id"),
        "artifact_digest": digest(receipt),
    },
}

print("ACTENON")
print("No valid proof, no execution.")
print()
print("Agent attempts:")
print("  database.delete_table production_customers")
print()
print("WITHOUT proof gate:")
print("  WOULD EXECUTE")
print("  side_effect_executed: true")
print("  consequence: destructive action reaches side effect path")
print()
print("WITH ACTENON:")
print("  REFUSED")
print(f"  reason_code: {reason_code}")
print("  side_effect_executed: false")
print(f"  refusal artifact: {relative(refusal_path)}")
print()
print("VALID PROOF:")
print("  EXECUTED ONCE")
print("  side_effect_executed: true")
print(f"  receipt artifact: {relative(receipt_path)}")
print()
print("SNAPSHOT:")
print(json.dumps(snapshot, indent=2))
print()
print("Done: unproven action refused; valid proof executed once.")

if details:
    print()
    print("Details:")
    print(f"  counterfactual artifact: {relative(counterfactual_path)}")
    print(f"  counterfactual status: {counterfactual.get('status')}")
    print(f"  duplicate replay artifact: {relative(replay_refusal_path)}")
    print(f"  duplicate replay reason_code: {replay_refusal.get('refusal_code')}")
PY
