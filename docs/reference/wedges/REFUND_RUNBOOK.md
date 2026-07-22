# Refund Runbook

## Purpose

This runbook explains how to run and inspect the refund wedge locally.
It requires no external accounts and no API keys.

## Exact Local Command

```bash
bash ./scripts/run_local_proof.sh
```

## Refund Scenarios

### `allow`

- refund amount: `1500`
- currency: `USD`
- target payment: `payment_demo_001`
- result: proof minted and protected refund executed

### `deny`

- refund amount: `1500`
- currency: `USD`
- target payment: `payment_demo_001`
- result: denied by refund workflow before proof minting

### `approval_required`

- refund amount: `2200`
- currency: `USD`
- target payment: `payment_demo_001`
- result: approval-required receipt with approver guidance

### `needs_evidence`

- refund amount: `1500`
- currency: `USD`
- target payment: `payment_demo_001`
- result: needs-evidence receipt with follow-up requirements

## Artifact Paths

- manifest: `artifacts/local_proof/manifest.json`
- summary: `artifacts/local_proof/SUMMARY.txt`
- scenario inputs and outputs: `artifacts/local_proof/scenarios/`
- refund receipts: `artifacts/local_proof/outcomes/receipts/`
- refund refusals: `artifacts/local_proof/outcomes/refusals/`
- protected refund state: `artifacts/local_proof/state/protected_endpoint_state.json`
- replay state: `artifacts/local_proof/state/replay.sqlite3`

## What To Inspect

For the allow case:

- `scenarios/allow/action_intent.json`
- `scenarios/allow/pccb.json`
- `scenarios/allow/execution_receipt.json`
- `scenarios/allow/execution_payload.json`

For the non-execution decision cases:

- `scenarios/deny/decision_receipt.json`
- `scenarios/deny/refusal.json`
- `scenarios/approval_required/decision_receipt.json`
- `scenarios/needs_evidence/decision_receipt.json`

## Remaining Gap To External Provider Proof

The refund wedge is local and deterministic today.

What remains before sandbox or provider proof:

- provider-backed payment and refund adapters
- provider-authenticated receipts and reconciliation
- production signer and key-management infrastructure
- external approval and evidence workflows
