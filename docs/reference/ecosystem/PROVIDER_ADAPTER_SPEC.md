# Provider Adapter Spec

## Purpose

This document defines the provider-adapter boundary that lets external systems call consequential downstream providers without embedding those integrations into the open kernel.

The open kernel owns proof verification, replay protection, structured refusals, and portable contracts. Provider adapters own translation from a verified kernel request into a provider-specific side effect.

## Scope

This document defines:

- the normalized request shape sent to adapters
- the normalized result shape returned by adapters
- the relationship between adapters and reconciliation
- the trust boundary between the OSS kernel and any paid or external provider layer

This document does not define:

- any provider-specific API
- payment-processor logic
- bank-integration logic
- hosted workflow behavior

## Terminology

- Provider adapter: an integration component that executes a verified consequential action against an external provider or system of record.
- Adapter request: the normalized request produced after proof verification succeeds.
- Adapter result: the normalized side-effect result returned by the adapter.
- Reconciliation snapshot: a later observation of provider state used to reconcile what happened after execution.

## Normative Interface

The reference interface lives at:

- `actenon/adapters/base.py`

The adapter boundary consists of:

- `ProviderAdapterContext`
- `ProviderAdapterRequest`
- `ProviderAdapterResult`
- `ProviderAdapter`
- `ReconciliationCapableProviderAdapter`

## Request Semantics

A provider adapter request MUST be constructed only after the protected execution path has:

1. verified the PCCB
2. enforced audience, tenant, subject, action, target, expiry, and action-hash checks
3. enforced replay and single-use execution checks required by the path

The normalized adapter request carries:

- the exact `action`
- the exact `target`
- stable execution identifiers such as `request_id`, `intent_id`, and `pccb_id`
- execution timing and audience context
- the verified PCCB for correlation and downstream traceability

Adapters MUST NOT accept hidden side-effect parameters that bypass the verified Action Intent unless those parameters are independently constrained by the integration boundary.

## Result Semantics

An adapter result is intentionally narrow. It provides:

- `provider_reference`: the downstream provider's stable reference when available
- `provider_state`: the provider-specific execution state string
- `side_effect_reference`: an optional stable execution reference for receipts or logging
- `details`: implementation-specific supplemental metadata

An adapter result does not prove provider finality on its own.

## Reconciliation Relationship

Adapters MAY support reconciliation by implementing the optional reconciliation-capable extension.

When they do, they SHOULD return provider snapshots that can be mapped into kernel reconciliation states using:

- `actenon/reconciliation/base.py`
- [RECONCILIATION_SPEC.md](RECONCILIATION_SPEC.md)

## Security Considerations

- Adapters are part of the trusted computing base once control passes beyond proof verification.
- A malicious or buggy adapter can misreport downstream status or perform side effects outside the verified model.
- Adapter implementations SHOULD treat `ProviderAdapterRequest` as the complete authorized scope and avoid hidden side channels for execution parameters.
- The open kernel does not authenticate provider adapters on behalf of deployers; deployers must secure adapter credentials and runtime trust separately.

## Boundary

Provider adapters belong to the broader ecosystem around the kernel. They are intentionally not implemented here as concrete provider integrations.

The OSS repository publishes the interface so that:

- a paid control plane can plug into the open kernel
- external implementers can build adapters against a stable boundary
- the open kernel does not become the provider-integration product
