# Refund Wedge Spec

## Purpose

Refunds are the first strong finance wedge for the Actenon kernel.

This wedge proves that the kernel can gate a consequential financial action with:

- typed Action Intent intake
- refund-specific policy evaluation
- exact proof binding
- protected endpoint execution
- replay protection
- operator-readable receipts

## Supported Refund Flow

The current wedge supports refund execution against a local payment record with:

- exact target binding to a payment resource
- exact amount binding through Action Intent fields, proof binding, and protected endpoint verification
- exact currency binding
- single-use proof and escrow
- replay protection at the execution edge

## Refund Action Intent

Refund Action Intent is still expressed through the generic public `action_intent` contract.

The refund wedge expects:

- `action.name = refund.create`
- `action.capability = refund.execute`
- `target.resource_type = payment`
- `action.parameters.amount_minor`
- `action.parameters.currency`
- `action.constraints.exact_amount_minor`
- `action.constraints.exact_currency`

This keeps the public model generic while making the refund wedge precise.

## Policy Flows

The local refund wedge now supports four strong decision flows:

- `allow`
- `deny`
- `approval-required`
- `needs-evidence`

### Allow

Normal-risk refunds with valid target, amount, currency, and refundable balance are authorized for protected execution.

### Deny

Blocked-risk refunds or structurally invalid refund requests are denied before proof minting or execution.

### Approval-Required

Elevated-value or approval-flagged refunds stop pending operator approval.

### Needs-Evidence

Review-risk refunds stop until required evidence is attached.

## Proof Binding

Refund PCCBs bind:

- the exact refund action
- the payment target
- the refund amount
- the refund currency
- audience
- scope
- expiry
- nonce
- action hash

The protected endpoint verifies those bindings before any refund side effect occurs.

## Protected Refund Endpoint

The local protected refund endpoint enforces:

- exact amount binding
- exact currency binding
- payment target requirement
- remaining refundable balance check

Execution writes local state only and returns a local execution reference.

## Receipts

Refund receipts are intended to be operator-readable.

They include readable summaries plus structured details such as:

- amount
- currency
- target payment
- local execution reference when present

## Local Proof Coverage

The zero-credential local refund proof mode covers:

- allow and execution
- deny with refusal
- approval-required with follow-up instructions
- needs-evidence with follow-up instructions

No external accounts or API keys are required.
