# Evidence API Spec

Status: Public local kernel service surface, not a hosted API contract

## Purpose

Evidence API defines the local kernel-side query surface for asking whether a proof and outcome chain exists for a specific execution anchor.

This spec describes the current local service semantics exposed by:

- `EvidenceQuery`
- `EvidenceVerdict`
- `EvidenceResult`
- `EvidenceQueryService`

It does not define an HTTP API, hosted service, or control-plane product.

## Normative Sources

- this document
- the active artifact specs it relies on:
  - [`../action-intent/SPEC.md`](../action-intent/SPEC.md)
  - [`../pccb/SPEC.md`](../pccb/SPEC.md)
  - [`../receipt/SPEC.md`](../receipt/SPEC.md)
  - [`../refusal/SPEC.md`](../refusal/SPEC.md)
  - [`../receipt-chain/SPEC.md`](../receipt-chain/SPEC.md)

There is no standalone machine schema for this surface in the current pass. The current public semantics are defined by the local kernel types and this document.

## EvidenceQuery Shape

An `EvidenceQuery` identifies exactly one lookup anchor.

Supported fields:

- `receipt_id`
- `pccb_id`
- `intent_id`
- `action_hash`

Normative rules:

- callers MUST set exactly one of those fields
- callers MUST NOT set more than one
- each field is treated as an exact lookup value, not a fuzzy search

## EvidenceVerdict Values

The current verdict set is:

- `VERIFIED_EXECUTION`
- `VERIFIED_REFUSAL`
- `PROOF_NOT_FOUND`
- `HASH_MISMATCH`
- `CHAIN_BROKEN`

Normative meaning:

- `VERIFIED_EXECUTION`: a valid execution receipt, PCCB, and receipt-evidence chain were found for the requested anchor
- `VERIFIED_REFUSAL`: a valid refusal, refused receipt, PCCB, and receipt-evidence chain were found for the requested anchor
- `PROOF_NOT_FOUND`: no qualifying proof or terminal outcome chain could be found for the requested anchor
- `HASH_MISMATCH`: a canonical action hash or referenced receipt digest did not match the recomputed value
- `CHAIN_BROKEN`: a chain was implied by the local artifacts, but a required link was missing, inconsistent, cyclic, or otherwise not traversable

## EvidenceResult Structure

An `EvidenceResult` contains:

- `verdict`
- `summary`
- `receipt_id`
- `refusal_id`
- `pccb_id`
- `intent_id`
- `action_hash`
- `chain_depth`
- `details`

Field semantics:

- `verdict` is the machine-level outcome
- `summary` is a human-readable explanation of the outcome
- `receipt_id`, `refusal_id`, `pccb_id`, `intent_id`, and `action_hash` identify the resolved local artifacts when available
- `chain_depth` is the number of receipt-evidence hops traversed successfully before the result was reached
- `details` MAY carry implementation-specific structured context such as expected hash values or observed mismatches

## Resolution Order And Expectations

### `receipt_id`

Resolution behavior:

1. load the receipt by `receipt_id`
2. if the receipt is `executed`, verify the linked `Action Intent`, `PCCB`, action-hash integrity, and receipt chain
3. if the receipt is `refused`, locate the paired `Refusal` and verify the refusal path
4. if the receipt exists but is not a terminal execution artifact, return `PROOF_NOT_FOUND`

### `pccb_id`

Resolution behavior:

1. prefer a `Refusal` correlated to the PCCB
2. otherwise prefer a `Receipt` correlated to the PCCB
3. if the PCCB exists but no terminal outcome artifact exists, return `CHAIN_BROKEN`
4. if no related local proof or outcome artifacts exist, return `PROOF_NOT_FOUND`

### `intent_id`

Resolution behavior:

1. prefer a `Refusal` tied to the intent
2. otherwise prefer a `Receipt` tied to the intent
3. otherwise inspect local PCCBs tied to the intent
4. if proof exists but no terminal outcome artifact exists, return `CHAIN_BROKEN`
5. if nothing relevant exists, return `PROOF_NOT_FOUND`

### `action_hash`

Resolution behavior:

1. prefer a PCCB whose `action_hash.value` matches exactly
2. if one exists, resolve through the `pccb_id` path
3. otherwise inspect local receipts and refusals whose `correlation.action_hash.value` matches exactly
4. if nothing relevant exists, return `PROOF_NOT_FOUND`

## Hash Verification Semantics

The current local evidence-query path verifies:

- PCCB `action_hash` against the canonical Action Intent hash
- `Receipt.correlation.action_hash`, when present, against that same canonical Action Intent hash
- `Refusal.correlation.action_hash`, when present, against that same canonical Action Intent hash
- receipt evidence digests against the canonical full `Receipt` artifact hash defined in the receipt-chain surface

Any canonical hash mismatch yields `HASH_MISMATCH`.

## Chain Traversal Semantics

The local evidence-query surface follows receipt evidence refs through the parent `Action Intent` chain.

Traversal behavior:

1. inspect `intent.evidence_refs`
2. select refs whose `type` is `actenon.receipt`
3. load each referenced receipt
4. verify the declared digest against the canonical receipt digest
5. load the parent intent for that receipt using `receipt.intent_id`
6. continue traversal recursively

If an intent has no receipt evidence refs, the traversal depth for that step is `0`.

## Bounded Depth Behavior

Receipt-chain traversal is bounded.

The current kernel default is:

- maximum chain depth: `8`

If traversal:

- exceeds the configured maximum depth
- encounters a cycle
- encounters a missing referenced receipt
- encounters a missing parent Action Intent
- lacks the local stores needed for traversal

the result is `CHAIN_BROKEN`.

## Local-Only Boundary

This spec defines the local kernel query surface only.

It does not standardize:

- a hosted search endpoint
- remote pagination
- multi-tenant archive behavior
- evidence review workflows
- external retention or deletion policies

A future hosted wrapper MAY expose equivalent concepts, but that would be a separate API surface and would need explicit versioning rather than being inferred from this local service spec.

## Compatibility And Versioning

- this surface is additive and local; it does not change active v1 artifact semantics
- changing verdict meanings, query resolution order, or chain-traversal behavior in a breaking way requires explicit versioned change
- a future hosted API MUST NOT claim compatibility merely because it uses similar names unless it explicitly preserves these semantics

## Related Specs

- [`../receipt-chain/SPEC.md`](../receipt-chain/SPEC.md)
- [`../protected-endpoint/SPEC.md`](../protected-endpoint/SPEC.md)
- [`../replay/SPEC.md`](../replay/SPEC.md)
- [`../../CONFORMANCE.md`](../../CONFORMANCE.md)
