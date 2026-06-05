# Receipt Chain Spec

Status: Public additive kernel surface built on active v1 artifacts

## Purpose

Receipt chain standardizes how an `Action Intent` can point at a prior `Receipt` artifact as evidence, and how a kernel or policy engine can verify that reference without inventing a new parallel evidence mechanism.

This surface is additive. It reuses:

- the active v1 `Action Intent` contract
- the active v1 `Receipt` contract
- the existing `evidence_refs` field on `Action Intent`

It does not create a new top-level artifact type.

## Normative Sources

- [`../action-intent/SPEC.md`](../action-intent/SPEC.md)
- [`../receipt/SPEC.md`](../receipt/SPEC.md)
- this document

There is no standalone machine schema for receipt chain in this pass because it is defined as a constrained use of already-active fields.

## Standard Receipt Evidence Type

The standard receipt evidence type is:

- `actenon.receipt`

Implementations using receipt-based evidence references SHOULD use this type string exactly.

## Evidence Reference Shape

Receipt chain uses the existing `EvidenceRef` structure from `Action Intent.evidence_refs`.

A receipt evidence reference has this shape:

```json
{
  "type": "actenon.receipt",
  "value": "rcpt_0001",
  "digest": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  }
}
```

Normative meaning:

- `type` MUST be `actenon.receipt`
- `value` MUST identify the referenced receipt by `receipt_id`
- `digest` SHOULD be present when receipt-chain verification is expected
- `digest.algorithm`, `digest.canonicalization`, and `digest.value` together declare the expected receipt artifact hash

## Digest And Hash Expectations

Receipt evidence verification hashes the full referenced `Receipt` artifact, not an ad hoc subset of fields.

The current kernel behavior uses:

- algorithm: `sha-256`
- canonicalization: `RFC8785-JCS`

The declared digest is compared against the canonical digest recomputed from the loaded receipt artifact.

Consumers performing receipt-chain verification SHOULD treat these conditions as invalid:

- missing digest where receipt-chain integrity verification is required
- malformed digest payload
- a declared digest that does not match the recomputed canonical receipt digest

## Chain Verification Semantics

When a consumer verifies receipt evidence refs, it:

1. reads `Action Intent.evidence_refs`
2. selects entries whose `type` is `actenon.receipt`
3. loads the referenced receipt by `receipt_id`
4. recomputes the canonical receipt digest
5. compares the recomputed digest to the declared digest
6. evaluates whether the referenced receipt outcome is suitable for the local rule or query being applied

If any referenced receipt cannot be loaded, has an invalid digest, or fails the configured suitability checks, the receipt chain is not valid for that consumer.

Receipt chain verification does not itself authorize execution. It verifies that a caller-supplied receipt reference corresponds to a real, untampered prior receipt artifact.

## Outcome Suitability

Receipt outcome suitability is consumer-specific.

The current kernel policy rule defaults to allowing only:

- `executed`

That means a referenced receipt with `allow`, `deny`, `approval-required`, `needs-evidence`, or `refused` is not suitable under the default receipt-evidence rule.

Consumers MAY configure a different allowed outcome set, but that is a local policy choice rather than a change to the `EvidenceRef` structure.

## Optional Capability Matching

The current kernel policy rule also supports an optional required-capability check.

When configured, the consumer compares:

- `referenced_receipt.action.capability`

against:

- the locally configured required capability

If they do not match, the receipt evidence fails local verification.

This capability check is optional and policy-local:

- it is not encoded as a separate receipt-chain field
- it does not change the `EvidenceRef` shape
- it does not redefine the active `Receipt` contract

## Nested Chain Traversal

Receipt evidence can form a chain when the parent `Action Intent` for a referenced `Receipt` also contains `evidence_refs` of type `actenon.receipt`.

In that case, a chain-aware consumer MAY:

1. load the referenced receipt
2. load that receipt's parent `Action Intent` by `receipt.intent_id`
3. continue traversal through that parent intent's receipt evidence refs

The current kernel evidence-query path performs this traversal with a bounded maximum depth and fails closed on missing links, cycles, or depth exhaustion.

## Boundary

Receipt chain is not:

- a hosted evidence workflow
- an approval system
- an archive product
- a new proof format
- a substitute for protected-endpoint verification

It is a portable convention for linking active v1 artifacts through the existing `evidence_refs` field.

## Compatibility And Versioning

- receipt chain is additive to active v1 `Action Intent` and `Receipt`
- it does not rename or remove any active v1 fields
- it does not activate a new top-level artifact contract
- changing the meaning of `type=actenon.receipt`, the digest expectations, or the chain-verification semantics in a breaking way requires explicit versioned change

## Related Specs

- [`../action-intent/SPEC.md`](../action-intent/SPEC.md)
- [`../receipt/SPEC.md`](../receipt/SPEC.md)
- [`../evidence-api/SPEC.md`](../evidence-api/SPEC.md)
- [`../../THREAT_MODEL.md`](../../THREAT_MODEL.md)
