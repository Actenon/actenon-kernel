# Reconciliation Spec

Status: Ecosystem boundary guidance for a reserved public surface. This document does not activate Reconciliation as an active v1 compatibility target.

## Purpose

This document describes the current reconciliation boundary groundwork that lets external provider ecosystems map provider-specific state into a stable kernel-facing reconciliation vocabulary.

The open kernel intentionally does not implement provider-authenticated reconciliation end to end. It publishes the interface and state model so broader ecosystem components can do so without turning this repository into the paid control plane.

For the activation requirements that would need to be met before Reconciliation becomes an active public surface, see [`../../../RECONCILIATION_ACTIVATION_PLAN.md`](../../../RECONCILIATION_ACTIVATION_PLAN.md).

## Scope

This document describes reserved-surface groundwork for:

- a portable provider snapshot shape
- a stable kernel reconciliation status vocabulary
- state-mapping expectations from provider state into kernel state

This document does not define:

- provider-specific polling logic
- bank or processor reconciliation workflows
- settlement or ledger-of-record semantics
- operator case-management flows

## Reference Interfaces

The reference interfaces live at:

- `actenon/reconciliation/base.py`

Related reserved public spec surface:

- `spec/reconciliation/SPEC.md`

These interfaces are groundwork for a reserved surface. They are not, by themselves, an active public conformance target or a published portable reconciliation contract.

## Kernel Reconciliation Statuses

The portable kernel reconciliation vocabulary is:

- `recorded-local`
- `provider-pending`
- `provider-confirmed`
- `provider-failed`
- `reversed`
- `unknown`

These statuses are intentionally broader than any single provider's state model.
They are published here as reserved-surface ecosystem guidance, not as activation of a reconciliation v1 compatibility surface.

## Provider State Mapping

Provider-specific states SHOULD be mapped into kernel states using `ProviderStateMapping`.

The mapping guidance is:

| Provider state meaning | Kernel reconciliation status |
| --- | --- |
| locally recorded only, no provider confirmation yet | `recorded-local` |
| queued, accepted, processing, pending, submitted | `provider-pending` |
| succeeded, settled, completed, confirmed | `provider-confirmed` |
| failed, rejected, cancelled before success | `provider-failed` |
| reversed, returned, chargeback-like reversal, post-success undo | `reversed` |
| anything not confidently mapped | `unknown` |

The OSS repository does not ship provider-specific mappings. External adapters or paid-layer components are expected to supply them.

## Snapshot And Record Semantics

- `ProviderReconciliationSnapshot` captures what an adapter or external reconciler learned from a provider at a point in time.
- `KernelReconciliationRecord` captures the normalized kernel-facing result after mapping.
- `StaticReconciliationMapper` is a generic reference mapper, suitable for tests and lightweight integrations.

## Security Considerations

- A provider snapshot is not automatically trusted finality; it is trusted only to the extent the adapter and provider channel are trusted.
- Mappers SHOULD fail to `unknown` rather than overstate certainty.
- Reconciliation records produced through this interface are portable normalization artifacts, not a claim that the OSS kernel itself performed provider-authenticated settlement verification.

## Boundary

This repository publishes the reconciliation vocabulary and mapper abstraction.

That publication is intentional groundwork. It should not be read as activation of a public Reconciliation standard.

It does not publish:

- production reconciliation workers
- provider-specific reconciliation adapters
- settlement confirmation services
- dispute or exception workflows
