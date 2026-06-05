# Invoice Payment Runbook

## Purpose

This runbook explains how to run and inspect invoice payment execution locally.
It requires no external accounts and no API keys.

## Exact Local Command

```bash
bash ./scripts/run_local_proof.sh
```

## Invoice Payment Scenarios

The combined local proof command writes invoice payment artifacts under:

- `artifacts/local_proof/invoice_payment/`

Scenarios:

- `allow`
- `duplicate_invoice_payment`
- `wrong_entity`
- `bank_mismatch`
- `approval_missing`
- `evidence_missing`
- `batch_hash_mismatch`

## What To Inspect

Important invoice payment paths:

- `artifacts/local_proof/invoice_payment/manifest.json`
- `artifacts/local_proof/invoice_payment/SUMMARY.txt`
- `artifacts/local_proof/invoice_payment/scenarios/allow/execution_receipt.json`
- `artifacts/local_proof/invoice_payment/scenarios/allow/execution_payload.json`
- `artifacts/local_proof/invoice_payment/scenarios/duplicate_invoice_payment/refusal.json`
- `artifacts/local_proof/invoice_payment/scenarios/wrong_entity/refusal.json`
- `artifacts/local_proof/invoice_payment/scenarios/bank_mismatch/refusal.json`
- `artifacts/local_proof/invoice_payment/scenarios/approval_missing/decision_receipt.json`
- `artifacts/local_proof/invoice_payment/scenarios/evidence_missing/decision_receipt.json`
- `artifacts/local_proof/invoice_payment/scenarios/batch_hash_mismatch/refusal.json`
- `artifacts/local_proof/invoice_payment/state/protected_endpoint_state.json`
- `artifacts/local_proof/invoice_payment/state/replay.sqlite3`

## Remaining Gap To Sandbox Or Provider Proof

What still remains:

- provider-backed payment execution adapters
- provider-authenticated payment and settlement receipts
- reconciliation against external bank or provider events
- production signer and key-management infrastructure
- external approval and evidence workflow integrations
