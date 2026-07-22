# Outcome Attestation v2alpha1

## Status

Outcome Attestation v2alpha1 is an active opt-in kernel contract for cryptographically attesting Receipt and Refusal artifacts.

It does not replace Receipt v1 or Refusal v1. It wraps one outcome artifact in a signed envelope so a verifier can check artifact integrity and origin against a configured verification key.

## Purpose

Receipt v1 and Refusal v1 are structured outcome artifacts. They are portable, stable, and machine-readable, but a copied JSON receipt or refusal by itself does not prove who emitted it.

Outcome Attestation adds a signed envelope for deployments that need portable verification of outcome origin without changing the v1 outcome payload.

## Active Contracts

There are two active v2alpha1 attestation contracts:

- `receipt_attestation` wraps a Receipt artifact.
- `refusal_attestation` wraps a Refusal artifact.

The active schemas are:

- [`../../schemas/receipt_attestation.v2alpha1.json`](../../schemas/receipt_attestation.v2alpha1.json)
- [`../../schemas/refusal_attestation.v2alpha1.json`](../../schemas/refusal_attestation.v2alpha1.json)

## Required Fields

An attestation envelope MUST contain:

- `contract`: the attestation contract name and version.
- `unsigned_payload`: the issuer-signed payload.
- `signature`: a signature over `unsigned_payload`.
- `external_anchors`: post-signing durability anchors. This array MAY be empty.

`unsigned_payload` MUST contain:

- `attestation_id`: a unique identifier for this attestation envelope.
- `issued_at`: the timestamp when the envelope was signed.
- `issuer`: the signing authority identity.
- `artifact_type`: `receipt` or `refusal`.
- `artifact_digest`: a digest over the embedded artifact.
- `outcome_artifact`: the embedded Receipt or Refusal artifact.
- `proof_binding`: the `intent_id`, `pccb_id`, and `action_hash` values referenced by the embedded outcome artifact when available.
- `metadata`: implementation metadata.

The embedded Receipt or Refusal MUST remain semantically unchanged. Implementations MUST NOT change Receipt or Refusal field semantics in order to support attestation.

## What Is Signed

The signer signs only the canonical `unsigned_payload`.

The unsigned payload includes:

- `attestation_id`
- `issued_at`
- `issuer`
- `artifact_type`
- `artifact_digest`
- `outcome_artifact`
- `proof_binding`
- `metadata`

`external_anchors` MUST NOT be included in `unsigned_payload`. Adding
`external_anchors` after issuer signing MUST NOT invalidate the issuer
signature. Each external anchor commits to the `artifact_digest` inside the
issuer-signed payload and is verified independently against its own trust root.

The reference implementation uses the frozen cross-repo canonicalization profile:

- digest algorithm: `sha-256`
- canonicalization profile: `actenon-jcs-sha256-v1`

## Verification

A verifier MUST:

1. Parse the attestation envelope and embedded outcome artifact.
2. Ensure `external_anchors` is not inside `unsigned_payload`.
3. Recompute the digest of the embedded Receipt or Refusal.
4. Compare the recomputed digest to `artifact_digest`.
5. Check that `proof_binding` values do not contradict the embedded outcome artifact.
6. Canonicalize `unsigned_payload`.
7. Verify `signature` against canonical `unsigned_payload` using a key whose well-known `use` includes `outcome_attestation`.
8. Fail closed if any parse, digest, canonicalization, key-purpose, lifecycle, or signature check fails.

Successful attestation verification proves only that the signed envelope matches the embedded artifact and the configured signing key. It does not prove provider finality, reconciliation, business correctness, hosted approval correctness, or that the signer should have emitted the outcome.

## Signers And Keys

The OSS kernel defines the portable signer and verifier interface used by the reference implementation. Local HMAC signing is available for demos, conformance, and local verification.

Production key custody, hosted signer services, HSM policy, certificate operations, and enterprise trust administration are outside this OSS kernel surface.

Key discovery can publish verification keys for environments that use public-key verification. See [`../key-discovery/SPEC.md`](../key-discovery/SPEC.md).

Outcome attestations MUST verify only against keys whose discovery document
`use` includes `outcome_attestation`. PCCB proof-issuance keys and
outcome-attestation keys are purpose-bound and cross-use fails unless a pilot
key explicitly lists both purposes.

## Compatibility

Outcome Attestation is additive and opt-in:

- Receipt v1 remains active and unchanged.
- Refusal v1 remains active and unchanged.
- Existing v1-only consumers can ignore attestation envelopes.
- Consumers that require portable origin checks SHOULD require and verify an attestation envelope.

Changing attestation contract names, required fields, signature coverage, digest rules, or verification semantics requires a new attestation version.

## Non-Goals

Outcome Attestation does not define:

- a hosted trust registry
- approval routing
- evidence review workflows
- provider-authenticated reconciliation
- long-term archive or dashboard semantics
- billing, tenancy administration, or control-plane operations
