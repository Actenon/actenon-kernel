# Invoice Payment Receipt Reference

## Purpose

This document defines the operator-readable receipt behavior for the invoice payment wedge.

## Decision Receipts

Decision receipts are emitted for:

- `allow`
- `deny`
- `approval-required`
- `needs-evidence`

Each decision receipt includes operator-readable fields for:

- payer entity
- supplier or payee
- bank account reference
- invoice-set
- amount
- currency
- payment date
- payment batch
- batch hash
- proposer identity

Approval-required receipts include approver guidance.

Needs-evidence receipts include the missing evidence types.

## Execution Receipts

Execution receipts are emitted when the protected invoice payment endpoint executes successfully.

They include:

- `payment_execution_id`
- `reconciliation_id`
- `reconciliation_status`
- `payment_batch_id`
- `invoice_ids`
- `payer_entity_id`
- `supplier_id`
- `amount_minor`
- `currency`
- local execution reference
- operator-readable summary

## Refused Receipts

If protected execution is refused after proof verification, the kernel emits:

- a structured refusal envelope
- a refused receipt referencing the refusal

The refused receipt still preserves the operator-readable payment context.
