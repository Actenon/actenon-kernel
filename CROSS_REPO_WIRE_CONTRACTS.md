# Cross-Repo Wire Contracts

This document freezes the Cloud-to-Kernel interop contracts for the Actenon v2
keystone. It is the pre-implementation source of truth for externally
verifiable proof and outcome artifacts.

Key lifecycle and receipt-durability semantics come from
[`REVOCATION_AND_RECEIPT_DURABILITY.md`](REVOCATION_AND_RECEIPT_DURABILITY.md).
If this document and that note disagree on revocation, hard revoke, key purpose,
or external anchors, the durability note wins.

The keystone proves external verifiability of issued proof and outcome
artifacts. It does not, by itself, prove replay protection, protected-endpoint
enforcement, downstream adapter correctness, or business-policy correctness.
Those are separate Actenon runtime and deployment guarantees.

## Normative Direction

The kernel is the source of truth for public proof and outcome verification.

- Cloud may depend on the kernel.
- The kernel must not depend on Cloud.
- Cloud internal storage models are not public wire contracts.
- Cloud must export kernel-shaped artifacts for external verification.

In particular, Cloud's internal `IssuedProof` is not a PCCB. Cloud must export a
real kernel-compatible PCCB and sign the exact bytes produced from the kernel
PCCB unsigned payload.

## Canonicalization Profile

All signed and digested cross-repo artifacts use:

```yaml
canonicalization_profile: "actenon-jcs-sha256-v1"
```

This profile freezes:

- deterministic JSON canonicalization
- SHA-256 digesting
- float rejection
- Unicode and string handling
- duplicate JSON object key behavior
- base64url without padding where base64url is required
- no in-place future changes

Duplicate JSON object keys are invalid for all proof, key-discovery, receipt,
refusal, attestation, and verification-bundle documents. Runtime verification
parsers must reject duplicate keys before canonicalization rather than accepting
the last duplicate value.

Verifier implementations must also fail closed on pathological inputs before
canonicalization. The Python kernel defaults reject raw JSON inputs larger than
1,048,576 bytes, JSON-like values deeper than 128 levels, and canonicalized JSON
outputs larger than 1,048,576 bytes. Other conforming implementations may use
stricter local limits, but must document them and must reject oversize/deep
inputs safely.

Any future change requires:

- a new canonicalization profile version
- an explicit dual-support window
- conformance vectors for both versions

Cloud must not treat `json.dumps(sort_keys=True)` as the cross-repo signing
contract. Cloud must use the kernel canonicalization path and kernel artifact
structures for public proof and outcome artifacts.

Required conformance vectors must include:

- Unicode NFC vs NFD normalization behavior, with the expected behavior stated
  explicitly.
- Duplicate JSON object keys, with rejection required.
- Oversize or deeply nested input, with fail-closed behavior required.

## PCCB Wire Contract

Cloud must export a kernel-compatible PCCB for external verification.

Rules:

- The exported proof artifact contract is `pccb v1`.
- Cloud must construct a real kernel `PCCB` object or use a kernel-provided PCCB
  builder.
- Cloud must sign `canonicalize_bytes(PCCB.unsigned_payload())`.
- The signature must be placed in `PCCB.signature`.
- The verifier must recompute the unsigned payload from the PCCB and verify the
  signature over those bytes.

Cloud must not independently mirror the PCCB unsigned-payload dictionary as a
long-lived public contract. If an adapter is needed, it must be named explicitly,
for example `export_kernel_pccb(...)`, and it must build the public artifact via
kernel code.

Required future implementation tests:

- Cloud PCCB unsigned payload equals kernel `PCCB.unsigned_payload()`.
- Cloud PCCB digest equals the kernel digest over the same canonical structure.
- Mutating any signed PCCB field fails verification.

## Action Hash Contract

The action hash input structure is the kernel `build_action_hash_input(...)`
structure.

Cloud must use this structure for public proof export. Cloud must not construct
a slightly different action-hash dictionary and assume shared canonicalization
will make it compatible.

Required future implementation tests:

- Cloud action-hash input equals kernel `build_action_hash_input(...)`.
- Cloud action hash equals kernel `sha256_hex(...)` over the same canonical
  structure.
- Mutating action, target, tenant, subject, issued time, expiry, or amount-like
  fields fails verification.

## EdDSA Encoding Contract

The pilot asymmetric signing contract uses Ed25519 / EdDSA.

Public key wire encoding:

- JWK key type: `OKP`
- curve: `Ed25519`
- key id: `kid`
- algorithm: `EdDSA`
- public key: raw 32-byte Ed25519 public key encoded in JWK `x`
- JWK `x`: base64url without padding
- no PEM, DER, or SPKI in the wire artifact

Signature wire encoding:

- algorithm: `EdDSA`
- encoding: `base64url`
- value: raw 64-byte Ed25519 signature encoded as base64url without padding
- no DER-wrapped signature
- no PEM signature wrapper

Negative conformance vectors must reject:

- padded base64url where unpadded base64url is required
- wrong key type
- wrong curve
- DER-wrapped signature
- PEM, DER, or SPKI public key material in the wire artifact
- algorithm mismatch
- algorithm downgrade or confusion
- signature `key_id` that does not match the discovered key

## Key Discovery Contract

The canonical well-known path is:

```text
/.well-known/actenon/keys.json
```

Verifier-side discovery must treat the fetched URL as part of the trust
boundary:

- The configured issuer origin must be an HTTPS origin.
- The discovery URL must be exactly
  `https://<issuer-origin>/.well-known/actenon/keys.json`.
- The default kernel resolver does not follow HTTP redirects.
- Redirects must not be used to move discovery to another origin, scheme, or
  path.
- The fetched document's `origin` must match both the configured issuer origin
  and the actual fetched URL origin.
- Default network fetching rejects localhost, loopback, link-local, private,
  multicast, and obvious metadata IP destinations where they are IP literals or
  resolve through DNS.

The key discovery document must support key lookup by issuer, `kid`, `algorithm`,
`use`, `status`, and artifact issue time.

Each verification key entry must support:

- `kid` or `key_id`
- `algorithm`
- `use`: one or more of `proof_issuance`, `outcome_attestation`
- `status`: `active`, `retired`, `suspended`, `revoked`, or `hard_revoked`
- `public_key_jwk`
- `not_before`
- `expires_at`
- `revoked_at`
- `hard_revoked_at`
- `revocation_reason`

`revocation_reason` is structured:

```json
{
  "code": "rotation | compromise | suspected_exfiltration | timestamp_trust_loss | operational | superseded | other",
  "detail": "optional human-readable explanation"
}
```

Purpose binding is mandatory:

- A PCCB must verify only against a key whose `use` includes
  `proof_issuance`.
- A receipt/refusal attestation must verify only against a key whose `use`
  includes `outcome_attestation`.
- Cross-use must be rejected.
- A `proof_issuance` key must not verify an outcome attestation unless the key
  explicitly lists `outcome_attestation`.
- An `outcome_attestation` key must not verify a PCCB unless the key explicitly
  lists `proof_issuance`.

If one pilot key is temporarily reused for both purposes, the well-known
document must explicitly list both uses, and documentation must state that this
is pilot-only. Production should use purpose-separated keys.

RS256 discovery keys must publish RSA JWK material with an RSA modulus of at
least 2048 bits and public exponent `65537`. JWK `n` and `e` values must be
unpadded base64url. Weak RSA keys and nonstandard public exponents are rejected
before signature verification.

Issue-time-aware lifecycle behavior follows
[`REVOCATION_AND_RECEIPT_DURABILITY.md`](REVOCATION_AND_RECEIPT_DURABILITY.md):

- Retired keys remain published for historical verification.
- Soft-revoked keys reject artifacts issued after `revoked_at`.
- Soft-revoked keys may verify artifacts issued before `revoked_at`, subject to
  normal checks.
- Hard-revoked keys reject historical artifacts unless an independent external
  anchor proves existence before `hard_revoked_at`.

Negative conformance vectors must include wrong `kid`, wrong purpose, revoked
after issue time, hard-revoked without anchor, and hard-revoked with anchor
requiring anchor verification.

## Outcome Attestation Envelope Contract

Receipt and refusal attestations use an envelope with three top-level parts:

- `unsigned_payload`: signed by the issuer
- `signature`: issuer signature over `unsigned_payload`
- `external_anchors`: optional anchors obtained after issuer signing

`external_anchors` MUST NOT be included in `unsigned_payload`. Adding
`external_anchors` after signing MUST NOT invalidate the issuer signature.

Required receipt attestation envelope shape:

```json
{
  "contract": {
    "name": "receipt_attestation",
    "version": "v2alpha1"
  },
  "unsigned_payload": {
    "attestation_id": "att_...",
    "issued_at": "RFC3339",
    "issuer": {},
    "artifact_type": "receipt",
    "artifact_digest": {
      "algorithm": "sha-256",
      "value": "..."
    },
    "outcome_artifact": {},
    "proof_binding": {
      "intent_id": "intent_...",
      "pccb_id": "pccb_...",
      "action_hash": "..."
    },
    "metadata": {}
  },
  "signature": {
    "algorithm": "EdDSA",
    "key_id": "kid_...",
    "encoding": "base64url",
    "value": "..."
  },
  "external_anchors": []
}
```

Refusal attestation uses the same envelope shape with:

```json
{
  "contract": {
    "name": "refusal_attestation",
    "version": "v2alpha1"
  }
}
```

The issuer signature proves origin and integrity of `unsigned_payload`. The
external anchor proves that the artifact digest existed at or before the anchor
time. A verifier must verify the issuer signature and `artifact_digest` first. A
verifier may then verify external anchors.

Issuer verification and external-anchor verification are separate layers:

- `external_anchors` is outside `unsigned_payload`, so adding anchors after
  issuer signing does not change the signed bytes.
- If anchors are present but no external anchor verifier is configured, normal
  active, retired, or soft-revoked historical artifacts may still pass issuer
  signature and artifact-integrity verification.
- In that no-verifier case, anchors are advisory/unverified and provide no
  anchor time to key-lifecycle policy.
- Hard-revoked historical recovery still requires an independently verified
  pre-revocation anchor.

`artifact_digest` must commit to the embedded `outcome_artifact`. The
`proof_binding` must reference values from the embedded outcome artifact and
must not contradict it.

Do not duplicate proof/action binding inconsistently:

- If `intent_id`, `pccb_id`, or `action_hash` are already present in the
  embedded Receipt or Refusal, `proof_binding` must reference the same values.
- If a value is unavailable, it may be null or omitted according to the
  contract.
- A value must not be invented.

Required future implementation tests:

- Cloud receipt attestation `unsigned_payload` equals the kernel expected
  receipt attestation `unsigned_payload`.
- Cloud refusal attestation `unsigned_payload` equals the kernel expected
  refusal attestation `unsigned_payload`.
- The attestation `artifact_digest` matches the embedded outcome artifact.
- The `proof_binding` references values from the embedded outcome artifact and
  must not contradict it.
- Tampering with `outcome_artifact`, `artifact_digest`, `proof_binding`,
  `issuer`, `issued_at`, or `signature` fails.

## External Anchor Contract

`external_anchors` is reserved now, even when empty.

Per-anchor shape:

```json
{
  "type": "transparency_log | rfc3161_timestamp | hosted_trust_network | countersignature",
  "anchor_id": "anchor_...",
  "anchored_at": "RFC3339",
  "artifact_digest": {
    "algorithm": "sha-256",
    "value": "..."
  },
  "trust_root": {
    "type": "log_id | tsa_certificate | issuer_key | network_id",
    "id": "..."
  },
  "proof": {
    "format": "inclusion_proof | timestamp_token | signature | opaque",
    "value": null
  },
  "metadata": {}
}
```

Rules:

- Each external anchor must commit to the `artifact_digest` inside the
  issuer-signed `unsigned_payload`.
- Each external anchor is verified independently against its own trust root.
- `external_anchors` may be empty for the keystone.
- Cryptographic verification of anchor proof is out of scope for the keystone.
- `hard_revoked` plus no external anchor must fail historical verification.
- `hard_revoked` plus only advisory/unverified anchors must fail historical
  verification.
- `hard_revoked` plus a verified pre-revocation local anchor may pass
  historical verification or return the documented recoverable historical state.

## Shared Conformance Vectors

Cross-repo fixtures should become public interop vectors rather than throwaway
CI artifacts.

Create a versioned vector set, for example:

```text
conformance/vectors/cloud_invoice_payment_v1/
  action_intent.json
  pccb.json
  issuer_keys.json
  receipt.json
  refusal.json
  receipt_attestation.json
  refusal_attestation.json
  mutations/
    amount_changed.json
    audience_changed.json
    expired.json
    wrong_kid.json
    wrong_purpose.json
    algorithm_mismatch.json
    algorithm_downgrade.json
    padded_base64.json
    der_wrapped_signature.json
    unicode_nfc_nfd.json
    duplicate_json_keys.json
    hard_revoked_without_anchor.json
    hard_revoked_with_anchor.json
```

Required assertions:

- PCCB unsigned payload equality between Cloud and kernel.
- Action hash input equality between Cloud and kernel.
- Digest equality between Cloud and kernel.
- Receipt/refusal attestation unsigned payload equality between Cloud and
  kernel.
- Signed-field mutation fails.
- Outcome-artifact tampering fails.
- `artifact_digest` tampering fails.
- `proof_binding` tampering fails.
- Wrong key purpose fails.
- Hard-revoked without anchor fails.
- Hard-revoked with anchor enters `anchor_verification_required` unless full
  anchor verification is implemented.

Fixture validity must not be time-flaky. Tests must either pin verifier
`context.now` inside the PCCB validity window or generate fresh fixtures at test
time.

## Implementation Gate

Implementation may begin only after these contracts are reviewed and accepted.
The first implementation pass must update code, schemas, and tests to match
these frozen documents rather than redefining the wire contracts during signing
backend work.
