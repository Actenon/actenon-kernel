# Policy Bundle Spec

Status: Reserved surface, no v1 contract published

## Terminology

- Policy bundle: a hypothetical portable artifact that packages policy material for independent evaluation or inspection.
- Policy engine: an implementation that evaluates a request using policy logic.
- Reference policy engine: an implementation example in this repository, not a portable interchange standard.

## Current Repository Position

This repository includes reference policy engines in `actenon/policy`, but it does not publish a portable policy-bundle interchange contract today.

Those policy engines are implementation material, not yet a standardized public bundle format.

For the ecosystem-facing policy-bundle model and interface boundary, see [../../docs/reference/ecosystem/POLICY_BUNDLE_SPEC.md](../../docs/reference/ecosystem/POLICY_BUNDLE_SPEC.md).

## Expected Behavior

- Implementations MUST NOT claim conformance to a policy-bundle v1 contract from this repository because no such contract is published.
- Consumers SHOULD treat policy artifacts outside the current public contracts as implementation-specific.
- Reference policy engines in this repository MAY demonstrate behavior, but they are not normative wire formats or portable bundle definitions.

## What Is Reserved

The term "policy bundle" is reserved here for a future portable artifact that could package policy material for independent evaluation or verifier use without turning the open repository into a hosted control plane.

Any future public policy-bundle surface would need to be:

- versioned
- portable
- explicit about inputs and semantics
- safe to validate without hidden control-plane state

## Security Considerations

- a future policy-bundle format must not depend on hidden hosted state to preserve public verifiability
- policy portability must not create a backdoor for smuggling secret operational logic into the open contract surface
- bundle semantics would need to separate explainability, evaluability, and execution authority explicitly

## Compatibility And Versioning

- This document reserves the surface but does not define a conformance contract.
- Publication of a future policy-bundle v1 contract would require a new schema, normative semantics, and migration guidance.

## Conformance

No implementation may claim conformance to a public policy-bundle v1 contract from this repository because no such contract is published yet.
