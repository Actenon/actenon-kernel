# Reconciliation Spec

Status: Reserved surface, no v1 contract published

This surface is important, but intentionally not active yet.

## Why This Surface Exists

Protected execution answers whether a consequential action was allowed to happen.

Reconciliation answers whether later provider-facing reality matches what the system recorded.

That is an important ecosystem boundary, especially for finance and other consequential wedges, but the repository does not yet publish a portable reconciliation contract with the precision needed for safe public compatibility claims.

## Terminology

- Reconciliation: the process of establishing whether a recorded consequential action matches authoritative external reality.
- Provider-authenticated reconciliation: reconciliation based on signals from the external provider or system of record.
- Local reconciliation record: a local example artifact used for demonstration or testing, not a public interoperability contract.

## Current Repository Position

This repository does not publish an active portable reconciliation schema or reconciliation conformance contract today.

The invoice payment local example records local reconciliation identifiers for demonstration purposes, but those artifacts are not a provider-authenticated public standard.

The current vocabulary, mapper interfaces, and ecosystem guidance are intentional groundwork for a reserved surface. They do not activate Reconciliation as an active public standard.

For the ecosystem-facing reconciliation boundary, see [../../docs/reference/ecosystem/RECONCILIATION_SPEC.md](../../docs/reference/ecosystem/RECONCILIATION_SPEC.md).

For what still needs to exist before this surface can become active, see [../../RECONCILIATION_ACTIVATION_PLAN.md](../../RECONCILIATION_ACTIVATION_PLAN.md).

## Expected Behavior

- Implementations MUST NOT claim conformance to a reconciliation v1 contract from this repository because no such contract is published.
- Implementations MAY expose local or internal reconciliation identifiers in receipts or example artifacts if they are clearly non-normative.
- Consumers SHOULD treat reconciliation claims outside the current `/spec` contracts as implementation-specific unless and until a future public contract is published.
- The presence of mapper interfaces, local receipt fields, or ecosystem guidance in this repository MUST NOT be treated as activation of a public Reconciliation compatibility target.

## Open-Kernel Boundary

Provider-authenticated reconciliation belongs outside the current open kernel boundary.

The open kernel may:

- emit receipts with correlation fields
- expose local example reconciliation identifiers
- define future extension points

The open kernel does not currently standardize:

- provider event ingestion
- settlement confirmation contracts
- reconciliation dispute workflows
- ledger-of-record semantics

## Security Considerations

- local example reconciliation identifiers must not be represented as provider-authenticated truth
- misleading reconciliation semantics can create false confidence about settlement, money movement, or operational finality
- any future public reconciliation contract would need to define trust source, finality semantics, and correlation rules explicitly

## Compatibility And Versioning

- This document reserves the surface but does not define a conformance contract.
- Publication of a future reconciliation v1 contract would require a new schema, normative semantics, and explicit migration guidance.
- Publication would also require explicit reference implementation expectations and conformance coverage, as described in [`../../RECONCILIATION_ACTIVATION_PLAN.md`](../../RECONCILIATION_ACTIVATION_PLAN.md).

## Conformance

No implementation may claim conformance to a public reconciliation v1 contract from this repository because no such contract is published yet.
