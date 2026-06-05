# Refund Receipt Reference

## Purpose

This document explains how refund receipts should be read by operators and by automated consumers.

Refund receipts are still emitted through the generic `receipt` contract. The wedge adds refund-specific meaning through the summary text and `details` payload.

## Refund Decision Receipts

Decision-stage refund receipts use these outcomes:

- `allow`
- `deny`
- `approval-required`
- `needs-evidence`

Operator-readable summaries now state:

- refund amount
- refund currency
- target payment
- high-level decision

Refund `details` include:

- `wedge = refund`
- `amount_minor`
- `currency`
- `target_resource_type`
- `target_resource_id`
- `rule_evaluations`

## Refund Execution Receipts

Execution-stage refund receipts use:

- `outcome = executed`
- `phase = execution`

Refund execution receipts include:

- operator-readable execution summary
- local execution reference
- updated resource version
- remaining refundable balance when returned by the protected endpoint

## Refund Refused Receipts

When a protected refund execution is refused, the refused receipt includes:

- operator-readable refund summary
- target payment
- amount
- currency
- refusal-linked correlation

## Related Artifacts

For local proof mode, refund receipt artifacts are written under:

- `artifacts/local_proof/outcomes/receipts/`

Related refusal artifacts are written under:

- `artifacts/local_proof/outcomes/refusals/`
