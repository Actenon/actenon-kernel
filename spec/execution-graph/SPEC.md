# Execution Graph Spec

Status: Public optional publication surface, not required for protected-endpoint correctness

## Purpose

Execution Graph defines the narrow first public publication surface for exposing
hash-addressed evidence that a consequential execution outcome occurred.

The first version is intentionally small. It standardizes:

- the `ExecutionAnchor` artifact
- the digests that an anchor publishes
- the canonical hash computation for those digests
- the minimal safe metadata envelope around that publication

It does not standardize:

- a hosted transparency service
- publication transport infrastructure
- public search APIs
- archive or retention workflows
- tenant administration or dashboard behavior

Protected-endpoint correctness does not depend on this surface. A deployment
can be fully conformant without publishing any execution anchors.

## Normative Sources

- this document
- [`../pccb/SPEC.md`](../pccb/SPEC.md)
- [`../receipt/SPEC.md`](../receipt/SPEC.md)
- [`../refusal/SPEC.md`](../refusal/SPEC.md)
- [`../../actenon/models/serialization.py`](../../actenon/models/serialization.py)

There is no standalone machine schema in this pass. The public shape is defined
here as a narrow JSON artifact.

## ExecutionAnchor Concept

An `ExecutionAnchor` is a public, publishable summary artifact that binds a
terminal execution outcome to canonical digests of the underlying kernel
artifacts.

Its purpose is transparency and external correlation, not authorization.

An `ExecutionAnchor` does not replace:

- protected-endpoint proof verification
- replay enforcement
- local receipt or refusal storage
- local evidence-query traversal

## What Gets Published

The first version publishes only:

- the anchor contract identity
- publication timestamp
- terminal outcome classification
- the canonical `action_hash` value for the execution
- a canonical digest of the governing PCCB
- a canonical digest of the terminal outcome artifact
- optional flat public metadata

Normative rule:

- an anchor MUST describe exactly one terminal execution outcome

Terminal outcome values in this first version are:

- `executed`
- `refused`

## What Stays Private

This surface is intentionally digest-first.

The following are not part of the first public anchor payload:

- full `Action Intent` artifacts
- full `PCCB` artifacts
- full `Receipt` artifacts
- full `Refusal` artifacts
- approval records
- evidence payload bodies
- provider-side response payloads
- tenant-private justification or context
- arbitrary side-effect details

Deployers MAY publish the underlying artifacts separately under their own
policy, but that is outside this spec.

## Canonical Digest Expectations

All digests published in an `ExecutionAnchor` MUST use the repository's shared
artifact hashing path:

- algorithm: `sha-256`
- canonicalization: `RFC8785-JCS`

Normative meaning:

- `pccb_digest` hashes the full `PCCB` artifact
- `receipt_digest` hashes the full `Receipt` artifact
- `refusal_digest` hashes the full `Refusal` artifact

These digests MUST be computed from the full artifact JSON, not from an ad hoc
subset of fields.

## Anchor Hash

The `ExecutionAnchor` itself is hash-addressable.

Its anchor hash is computed as:

1. serialize the full `ExecutionAnchor` JSON artifact with `RFC8785-JCS`
2. hash the canonical bytes with `sha-256`

This spec does not require the anchor hash to appear as an in-band field inside
the anchor object. A publisher or verifier MAY compute it externally from the
artifact bytes.

## Publication Shape

The first-version `ExecutionAnchor` JSON shape is:

```json
{
  "contract": {
    "name": "execution_anchor",
    "version": "v1"
  },
  "published_at": "2026-04-11T12:00:00Z",
  "outcome": "executed",
  "action_hash": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  },
  "pccb_digest": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  },
  "receipt_digest": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  },
  "metadata": {
    "publisher": "acme-payments-prod",
    "region": "eu-west-1"
  }
}
```

For a refused execution outcome, `refusal_digest` is used instead of
`receipt_digest`:

```json
{
  "contract": {
    "name": "execution_anchor",
    "version": "v1"
  },
  "published_at": "2026-04-11T12:00:00Z",
  "outcome": "refused",
  "action_hash": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  },
  "pccb_digest": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  },
  "refusal_digest": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  }
}
```

## Field Rules

### `contract`

- MUST be present
- `name` MUST be `execution_anchor`
- `version` MUST be `v1`

### `published_at`

- MUST be present
- MUST be an RFC3339 / ISO 8601 UTC timestamp
- identifies when the anchor was published, not when execution occurred

### `outcome`

- MUST be present
- MUST be either `executed` or `refused`

### `action_hash`

- MUST be present
- MUST match the canonical action hash from the governing PCCB
- SHOULD use the exact metadata carried by that PCCB:
  - `algorithm=sha-256`
  - `canonicalization=RFC8785-JCS`

### `pccb_digest`

- MUST be present
- MUST hash the full governing `PCCB`

### `receipt_digest`

- MUST be present when `outcome=executed`
- MUST NOT be present when `outcome=refused`

### `refusal_digest`

- MUST be present when `outcome=refused`
- MUST NOT be present when `outcome=executed`

### `metadata`

- MAY be present
- MUST be a flat JSON object whose values are scalars:
  - string
  - number
  - boolean
  - null
- MUST NOT contain nested objects or arrays
- MUST be safe for public publication

Keys beginning with `actenon.` are reserved for future standard use.

## Metadata Boundary

Allowed metadata is intentionally narrow. Suitable examples include:

- publisher label
- region
- environment
- public deployment shard identifier

Unsuitable metadata includes:

- customer names
- raw provider references
- internal operator notes
- full resource identifiers when they are not already public
- arbitrary request or response payloads

This spec does not attempt automated privacy classification. The deployer is
responsible for deciding whether a metadata field is safe to publish.

## Publication Transport Boundary

This spec defines the anchor artifact only.

A deployment MAY publish an anchor through:

- a local file
- an append-only feed
- an object store
- an HTTP endpoint
- another public transport

Transport is explicitly out of scope in this first version.

## Verification Expectations

A verifier checking an `ExecutionAnchor` should:

1. parse the anchor and validate the contract name/version
2. confirm the outcome field is valid
3. confirm the digest metadata is supported
4. recompute the anchor hash from the anchor artifact if the transport depends
   on hash addressing
5. compare `pccb_digest` against the full PCCB artifact when that artifact is
   available
6. compare `receipt_digest` or `refusal_digest` against the corresponding full
   artifact when available
7. confirm `action_hash` matches the governing PCCB

This spec does not require a verifier to be able to fetch the underlying
artifacts automatically.

## Optionality And Correctness Boundary

Execution Graph is optional.

Normative rule:

- failure to publish an `ExecutionAnchor` MUST NOT make an otherwise valid
  protected-endpoint execution incorrect

Protected-endpoint correctness still depends on:

- Action Intent validation
- PCCB verification
- audience and subject/tenant binding
- expiry enforcement
- replay enforcement where configured
- structured Receipt / Refusal emission

Anchor publication is an additive transparency surface around those behaviors,
not a substitute for them.

## Compatibility And Versioning

- this first version is intentionally minimal
- adding required fields or changing digest semantics in a breaking way
  requires explicit versioning
- future graph edge or publication-service semantics MUST be additive or
  separately versioned rather than silently redefining `execution_anchor v1`

## Related Specs

- [`../pccb/SPEC.md`](../pccb/SPEC.md)
- [`../receipt/SPEC.md`](../receipt/SPEC.md)
- [`../refusal/SPEC.md`](../refusal/SPEC.md)
- [`../evidence-api/SPEC.md`](../evidence-api/SPEC.md)
- [`../../KERNEL_GUARANTEES.md`](../../KERNEL_GUARANTEES.md)
