# Invoice Payment Wedge Spec

## Purpose

This document defines invoice payment execution as the second strong finance wedge for the kernel.

Core rule:

- no proof, no payment

## Scope

The invoice payment wedge covers one consequential action:

- `invoice_payment.execute`

The wedge binds and controls:

- payer entity
- supplier or payee
- bank account reference
- invoice set
- amount
- currency
- payment date
- payment batch or run identifier
- proposer identity
- evidence references
- risk and workflow context

## Action Intent Shape

The invoice payment Action Intent remains generic and transport-agnostic.

The wedge uses Action Intent `action.parameters` to carry:

- `payer_entity_id`
- `supplier_id`
- `bank_account_reference`
- `invoice_ids`
- `amount_minor`
- `currency`
- `payment_date`
- `payment_batch_id`
- `batch_hash`
- `proposer_id`

The wedge uses Action Intent `action.constraints` for exact binding:

- exact payer entity binding
- exact supplier or payee binding
- exact bank account reference binding
- exact invoice-set binding
- exact amount binding
- exact currency binding
- exact payment date binding
- exact batch identifier binding
- exact batch hash binding

## Proof Binding

Invoice payment PCCBs bind the exact action and target through:

- full `action` object equality
- full `target` object equality
- exact audience binding
- exact scope binding
- expiry
- nonce
- canonical action hash

For this wedge, the proof therefore binds:

- payer entity
- payee
- bank account reference
- invoice-set
- amount
- currency
- payment date
- payment batch
- batch hash

## Policy Controls

The wedge enforces:

- payer entity validation
- payee validation
- bank detail validation input checks
- duplicate invoice or payment checks
- batch hash validation
- amount and currency checks
- payment date checks
- approval chain validation
- evidence requirements
- replay protection

## Required Refusal Reasons

The wedge emits machine-readable refusal reasons for:

- `DUPLICATE_INVOICE_PAYMENT`
- `WRONG_ENTITY`
- `BANK_MISMATCH`
- `APPROVAL_MISSING`
- `EVIDENCE_MISSING`
- `BATCH_HASH_MISMATCH`

Additional refusal reasons may appear for related exact-binding failures such as payee mismatch or invoice-set mismatch.

## Local Proof Coverage

The zero-credential local proof path covers:

- allow to executed
- duplicate invoice or payment deny
- wrong entity deny
- bank mismatch deny
- approval-required
- needs-evidence
- batch hash mismatch deny

No external accounts or API keys are required.
