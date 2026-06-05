#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY_SCRIPT="$ROOT_DIR/scripts/verify.sh"
CRITERIA_FILE="$ROOT_DIR/docs/ACCEPTANCE_CRITERIA.md"

if "$VERIFY_SCRIPT"; then
  printf '\nJUDGMENT: spec harness ready for kernel rebuild.\n'
  printf 'Single acceptance gate: scripts/verify.sh\n'
  printf 'Public contract set:\n'
  printf ' - schemas/action_intent.v1.json\n'
  printf ' - schemas/pccb.v1.json\n'
  printf ' - schemas/receipt.v1.json\n'
  printf ' - schemas/refusal.v1.json\n'
  printf 'Core python modules:\n'
  printf ' - actenon/api\n'
  printf ' - actenon/core\n'
  printf ' - actenon/policy\n'
  printf ' - actenon/proof\n'
  printf ' - actenon/escrow\n'
  printf ' - actenon/replay\n'
  printf ' - actenon/verifier\n'
  printf ' - actenon/receipts\n'
  printf ' - actenon/models\n'
  printf 'Local proof command: bash ./scripts/run_local_proof.sh\n'
  printf 'First wedge: refund execution\n'
  printf 'Refund specs:\n'
  printf ' - docs/reference/wedges/REFUND_WEDGE_SPEC.md\n'
  printf ' - docs/reference/wedges/REFUND_RECEIPT_REFERENCE.md\n'
  printf ' - docs/reference/wedges/REFUND_RUNBOOK.md\n'
  printf 'Invoice payment specs:\n'
  printf ' - docs/reference/wedges/INVOICE_PAYMENT_WEDGE_SPEC.md\n'
  printf ' - docs/project-history/PAYMENT_EXECUTION_CONTROL_SUMMARY.md\n'
  printf ' - docs/reference/wedges/INVOICE_PAYMENT_RECEIPT_REFERENCE.md\n'
  printf ' - docs/reference/wedges/INVOICE_PAYMENT_RUNBOOK.md\n'
  printf 'Refund local proof scenarios:\n'
  printf ' - allow -> executed\n'
  printf ' - deny -> deny\n'
  printf ' - approval_required -> approval-required\n'
  printf ' - needs_evidence -> needs-evidence\n'
  printf 'Invoice payment local proof scenarios:\n'
  printf ' - allow -> executed\n'
  printf ' - duplicate_invoice_payment -> deny\n'
  printf ' - wrong_entity -> deny\n'
  printf ' - bank_mismatch -> deny\n'
  printf ' - approval_missing -> approval-required\n'
  printf ' - evidence_missing -> needs-evidence\n'
  printf ' - batch_hash_mismatch -> deny\n'
  printf 'Completion criteria:\n'
  grep -E '^## AC-[0-9]{3}' "$CRITERIA_FILE" | sed 's/^## / - /'
else
  printf '\nJUDGMENT: spec harness not ready.\n' >&2
  exit 1
fi
