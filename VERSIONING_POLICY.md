# Versioning Policy

## Purpose

This repository publishes versioned public contracts before implementation details so external integrators can trust contract stability while kernel internals evolve behind the boundary.

## Active V1 Surface

Current active v1 public contracts:

- `spec/action-intent/schema.json`
- `spec/pccb/schema.json`
- `spec/receipt/schema.json`
- `spec/refusal/schema.json`

Current active v1 public behavior surfaces:

- `spec/protected-endpoint/SPEC.md`
- `spec/replay/SPEC.md`

Reserved public surfaces that are not active v1 compatibility targets:

- `spec/reconciliation/SPEC.md`
- `spec/policy-bundle/SPEC.md`

Each active surface has a matching human-readable spec under `/spec`.

## VAR Standard Versioning

VAR means Verifiable Action Receipt: the neutral standard surface for
proof-bound records of consequential agent actions.

VAR versioning covers:

- public artifact contracts
- canonicalization profiles
- action-hash and proof-binding rules
- conformance vectors
- conformance suite expectations
- well-known key-discovery contracts
- key lifecycle and revocation semantics
- receipt/refusal attestation semantics when active

VAR-compatible implementations must identify the VAR surface version and the
canonicalization profile they target.

## Version Format

- machine schemas carry the major contract version in their canonical source file under `schemas/`
- `/spec/<surface>/schema.json` exposes the current active schema for that surface
- each schema carries a fixed `contract.version` marker such as `v1`
- each schema has a stable `$id`

In this repository, a major version is the compatibility unit.

## Canonicalization Profile Versioning

The current frozen canonicalization profile for Cloud-to-Kernel interop is:

```text
actenon-jcs-sha256-v1
```

This profile covers deterministic JSON canonicalization, SHA-256 digesting,
float rejection, Unicode/string handling, duplicate-key behavior, and base64url
without padding where base64url is required by a wire contract.

Canonicalization profiles must not mutate in place. Any future change requires:

1. a new canonicalization profile version
2. conformance vectors for both the old and new profile
3. an explicit dual-support window when deployed systems need migration time
4. migration documentation for issuers, verifiers, and SDKs

## Conformance Vector Versioning

Conformance vectors are compatibility artifacts, not disposable test fixtures.

The suite itself uses semantic versioning independently of the package version.
Its current version is declared by `conformance/VERSION`,
`conformance/suite.json`, and `actenon/conformance/version.py`. Vector bytes are
locked by `conformance/vector-lock.json`.

Versioned vectors should identify:

- VAR or kernel surface version
- contract version
- canonicalization profile
- key-discovery contract version when relevant
- lifecycle/revocation semantics when relevant
- expected valid and invalid mutation cases

Changing the expected interpretation of an existing vector is a breaking change
unless the vector is clearly marked as superseded and a new versioned vector is
published.

Published conformance releases use `conformance-vMAJOR.MINOR.PATCH` signed Git
tags. The release workflow emits a deterministic archive, SHA-256 sidecar, and
GitHub/Sigstore provenance. The `Actenon Verified` mark must always state the
exact conformance version.

## Key Discovery And Lifecycle Versioning

Well-known key-discovery contracts, key `use` values, key lifecycle states, and
revocation semantics are public compatibility surfaces when they affect proof
or attestation verification.

Versioning applies to:

- key document path and shape
- `kid`, `algorithm`, `use`, and public-key encoding
- `active`, `retired`, `suspended`, `revoked`, and `hard_revoked` semantics
- issue-time-aware key selection
- soft-revoke and hard-revoke behavior
- external-anchor recovery semantics for hard-revoked keys

Lifecycle and revocation semantics must not be silently changed in place. A
breaking change requires a new versioned contract and an explicit dual-support
window.

## What Counts As Breaking

Any of the following requires a new major version:

- renaming a field
- removing a field
- making an optional field required
- changing field meaning or semantics
- changing identifier, timestamp, or hash rules
- changing canonicalization rules
- changing outcome or category enum values
- tightening validation in a way that rejects previously valid payloads
- changing how a verifier must interpret a proof or receipt
- changing a frozen wire contract without a new version
- changing key-discovery, lifecycle, or revocation semantics that affect
  verification results

## What Does Not Require A New Major Version

These changes may happen within the current major version:

- wording clarifications in documentation
- additional non-normative examples
- stricter internal implementation behavior that does not change public contract validity or meaning
- new vendor-specific data carried only inside `extensions`

## Extension Rules

- `extensions` is the portable vendor-specific escape hatch
- data inside `extensions` must not change the meaning of core authorization, proof, receipt, or refusal semantics
- consumers should ignore unknown keys inside `extensions`

## Publication Rules

When a new major version is created:

1. publish a new versioned schema under `schemas/`
2. expose the intended active surface under `/spec`
3. publish or update the matching human-readable spec
4. document the migration delta from the previous major version
5. update conformance material intentionally

Breaking changes to frozen wire contracts require dual-support guidance. The
old contract must not be mutated in place.

## Priority Rule

Public contract compatibility takes priority over internal convenience.

For active public contracts, the `/spec` surface is the canonical documentation entry point.
