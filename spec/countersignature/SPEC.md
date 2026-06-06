# Receipt Counter-Signature Format

Status: Active opt-in v1 public verification surface

## Purpose

A Receipt v1 artifact may be self-issued by the protected endpoint. A receipt
counter-signature lets an independent witness sign the canonical digest of that
Receipt so a relying party can verify the witness statement offline using only
pinned public keys.

This surface is deliberately verifier-side and open. It defines the artifact,
signature input, public-key selection, and failure behavior. It does not define
counter-signing services, private-key custody, approval workflows, or signing
APIs.

Machine schema:

- [`../../schemas/receipt_countersignature.v1.json`](../../schemas/receipt_countersignature.v1.json)

## Artifact

```json
{
  "contract": {
    "name": "receipt_countersignature",
    "version": "v1"
  },
  "receipt_digest": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "<64 lowercase hex characters>"
  },
  "witness": {
    "type": "service",
    "id": "witness-identity"
  },
  "signed_at": "2026-04-10T09:02:00Z",
  "anchor_reference": {
    "type": "transparency_log",
    "id": "optional-anchor-id"
  },
  "signature": {
    "algorithm": "EdDSA",
    "key_id": "witness-key-2026-04",
    "encoding": "base64url",
    "value": "<unpadded base64url Ed25519 signature>"
  }
}
```

Required fields:

- `contract`
- `receipt_digest`
- `witness`
- `signed_at`
- `signature`

`anchor_reference` is optional. When present, it is covered by the signature.
Verification of the referenced external system is a separate operation.

## Receipt Digest

For a Receipt artifact, the digest is:

```text
SHA-256(RFC8785-JCS(receipt))
```

The digest object MUST declare:

- `algorithm: sha-256`
- `canonicalization: RFC8785-JCS`
- `value`: lowercase hexadecimal SHA-256 output

Relying parties MAY supply either the complete Receipt or a previously pinned
digest to `verify_countersignature`.

## Signature Input

The Ed25519 signature covers the RFC 8785 canonical bytes of:

```json
{
  "context": "actenon.receipt-countersignature.v1",
  "receipt_digest": "<the complete digest object>",
  "witness": "<the complete witness object>",
  "signed_at": "<the exact signed_at string>",
  "anchor_reference": "<included only when present in the artifact>"
}
```

The domain-separation `context` is mandatory. The signature therefore binds the
receipt digest, witness identity, signing time, and optional anchor reference.
It does not sign or re-authorize the underlying action.

## Public Keys And Historical `kid` Values

Counter-signing public keys use the existing
[`key_discovery v1`](../key-discovery/SPEC.md) document. A conforming key
descriptor uses:

```json
{
  "key_id": "witness-key-2026-04",
  "algorithm": "EdDSA",
  "use": "receipt_countersignature",
  "status": "active",
  "public_key_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "witness-key-2026-04",
    "alg": "EdDSA",
    "use": "sig",
    "x": "<unpadded base64url public key>"
  }
}
```

Publishers SHOULD retain retired public keys in the versioned key set. A
counter-signature created under an older `key_id` remains verifiable when:

- the exact historical `key_id` remains present
- its status is `retired`
- its validity bounds include `signed_at`
- it has not been revoked at or before `signed_at`

The key-set `issuer` MUST match `witness.type` and `witness.id`.

## Offline Pinning

A relying party can:

1. obtain `https://<witness-origin>/.well-known/actenon/keys.json` over an
   authenticated channel
2. review the issuer, origin, key purposes, and lifecycle metadata
3. pin the complete document or its digest in local configuration
4. pass that pinned JSON document to `verify_countersignature`
5. verify future artifacts without contacting the witness service

Fetching is not required during artifact verification. The verifier API accepts
an already trusted key-set document and performs no network calls.

The conformance key set under
[`../../conformance/vectors/receipt_countersignature_v1/`](../../conformance/vectors/receipt_countersignature_v1/)
contains throwaway public fixture keys only. It is not an Actenon production
trust anchor.

## Verification

A verifier MUST:

1. validate `receipt_countersignature v1`
2. recompute or parse the supplied Receipt digest
3. require exact equality with `receipt_digest`
4. require the key-set issuer to match `witness`
5. select exactly one public key by `signature.key_id`
6. require `algorithm: EdDSA` and key use `receipt_countersignature`
7. accept only an `active` or time-valid `retired` key
8. apply `not_before`, `expires_at`, and `revoked_at` to `signed_at`
9. verify the Ed25519 signature over the canonical signature input
10. fail closed on every mismatch

Unknown or duplicate key IDs, wrong-purpose keys, altered digests, wrong public
keys, malformed JWKs, and invalid signatures MUST be rejected.

## Security And Claim Boundary

A valid counter-signature proves that the holder of the selected witness key
signed the specified receipt-digest statement. It does not prove:

- that the Receipt is truthful
- provider finality
- correct policy or approval decisions
- production exposure or exploitability
- that every execution route was protected
- that the witness should have counter-signed the Receipt

Trust in the witness identity and its pinned public keys remains a relying-party
decision.

## Compatibility

Changing the contract name, version, signature input, digest algorithm,
canonicalization, required fields, or key-selection behavior requires a new
counter-signature version.

This format is additive. It does not change Receipt v1 or Outcome Attestation
v2alpha1.
