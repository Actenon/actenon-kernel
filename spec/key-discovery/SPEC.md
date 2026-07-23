# Key Discovery Spec

Status: Public cross-boundary trust surface

## Purpose

This spec defines a well-known HTTPS document for publishing issuer verification keys used to verify Actenon-signed artifacts.

It is designed for:

- PCCB verification when the issuer uses asymmetric signing
- signed outcome-attestation verification
- receipt counter-signature verification
- transparency checkpoint verification
- independent verifier implementations that need a stable key-discovery format

It is not tied to hosted Actenon infrastructure. Any issuer can publish this document from its own HTTPS origin.

## Scope

This spec defines:

- the well-known URL shape
- the JSON response structure
- key matching by `key_id`
- revocation and expiry handling
- caching expectations
- failure behavior

This spec does not define:

- private-key custody
- KMS or HSM operational workflows
- transparency logs
- hosted registries
- control-plane trust distribution

## Well-Known URL Shape

An issuer that publishes verification keys MUST expose a JSON document at:

- `https://<issuer-origin>/.well-known/actenon/keys.json`

Normative rules:

- the scheme MUST be `https`
- the path MUST be `/.well-known/actenon/keys.json`
- verifiers SHOULD NOT follow redirects by default
- redirects MUST NOT be used to change discovery to another origin, scheme, or path
- verifiers SHOULD fetch this document with an HTTPS `GET`
- verifiers SHOULD reject localhost, loopback, link-local, private, multicast,
  and metadata IP destinations when they are visible before fetching

This spec defines the document location and format once an issuer origin is known. It does not require the origin to be embedded in every Actenon artifact.

## Response Structure

The discovery document is a JSON object with these top-level fields:

- `contract`
- `issuer`
- `origin`
- `published_at`
- `keys`

Optional top-level fields:

- `cache`

### `contract`

The document contract is:

```json
{
  "name": "key_discovery",
  "version": "v1"
}
```

Consumers MUST reject documents whose `contract.name` or `contract.version` do not identify `key_discovery` `v1`.

### `issuer`

`issuer` identifies the signer authority that owns the published verification keys.

Expected fields:

- `type`
- `id`

Optional fields:

- `display_name`

### `origin`

`origin` is the canonical HTTPS origin serving the discovery document.

It MUST match the configured issuer origin and the actual origin from which the
document was fetched.

### `published_at`

`published_at` is an RFC3339 timestamp identifying when the key set was last published.

### `cache`

`cache`, when present, is an object with:

- `max_age_seconds`

This is advisory cache metadata for verifiers. It does not replace normal HTTP caching headers.

### `keys`

`keys` is an array of key descriptors.

The document MUST contain at least one key descriptor.

Within a single document, `key_id` values MUST be unique.

## Key Descriptor Fields

Each key descriptor MUST include:

- `key_id`
- `algorithm`
- `use`
- `status`
- `public_key_jwk`

Optional fields:

- `not_before`
- `expires_at`
- `revoked_at`
- `replaced_by`
- `revocation_reason`

### `key_id`

`key_id` is the exact key identifier used for signature routing and trust matching.

It MUST match the signed artifact's `signature.key_id` exactly.

### `algorithm`

`algorithm` is the expected signature algorithm for this key and MUST match the signed artifact's `signature.algorithm`.

### `use`

`use` identifies the intended use of the discovered key.

Current values include:

- `verify` for legacy generic verification
- `proof_issuance`
- `outcome_attestation`
- `receipt_countersignature`
- `transparency_checkpoint`
- `issuer_status`
- `approval_artifact`

### `status`

Allowed values:

- `active`
- `retired`
- `revoked`

Meaning:

- `active`: usable for verification and expected to be current for new signatures
- `retired`: no longer preferred for new signatures, but still usable for verification if time-valid and not revoked
- `revoked`: not usable according to the revocation rules below

### `public_key_jwk`

`public_key_jwk` contains the verification key material in JWK form.

The JWK MUST be sufficient for an independent verifier to reconstruct the public verification key.

This spec uses JWK because it is language-neutral and copyable across environments.

Symmetric local demo secrets such as the OSS local proof HMAC secret are not publishable through this discovery format and are outside the intended scope of this document.

### Time Fields

`not_before`, `expires_at`, and `revoked_at`, when present, MUST be RFC3339 timestamps.

## Matching By Key ID

Verification uses exact `key_id` matching:

1. fetch or load the discovery document for the issuer origin
2. locate the single key descriptor whose `key_id` exactly equals the artifact's `signature.key_id`
3. confirm that the key descriptor's `algorithm` exactly equals the artifact's `signature.algorithm`
4. verify that the key is currently usable under the time and revocation rules below
5. verify the signature using the discovered public key

Failure rules:

- if no key matches `key_id`, verification MUST fail closed
- if multiple keys share the same `key_id`, the document is invalid and verification MUST fail closed
- if `algorithm` does not match, verification MUST fail closed

## Revocation And Expiry Handling

Verifiers SHOULD evaluate key usability against the signed artifact's issuance timestamp.

Examples:

- for a PCCB, use `issued_at`
- for a signed outcome attestation, use the attestation envelope's `issued_at`
- for a receipt counter-signature, use `signed_at`
- for a transparency checkpoint, use `issued_at`
- for an issuer-status artifact, use `issued_at`
- for an approval artifact, use `issued_at`

A key is usable only if all of the following hold:

- `status` is `active` or `retired`
- if `not_before` is present, artifact issuance time is greater than or equal to it
- if `expires_at` is present, artifact issuance time is strictly earlier than it
- if `revoked_at` is present, artifact issuance time is strictly earlier than it

Additional rules:

- if `status` is `revoked`, verifiers MUST reject the key unless local trust policy explicitly defines a narrower historical-verification exception
- if an artifact does not expose a trustworthy issuance time and key time bounds matter, verification SHOULD fail closed
- `replaced_by`, when present, is advisory for operators and caching clients; it does not change signature verification semantics by itself

## Caching Expectations

Issuers SHOULD serve the discovery document with HTTP caching headers, especially:

- `Cache-Control`
- `ETag`

Issuers MAY also include:

- `cache.max_age_seconds`

Verifier expectations:

- verifiers SHOULD honor the smaller of HTTP `max-age` and `cache.max_age_seconds` when both are present
- if neither is present, verifiers SHOULD default to a short cache lifetime such as 300 seconds
- verifiers MAY use conditional requests such as `If-None-Match` when `ETag` is available
- verifiers SHOULD refresh the document after cache expiry before concluding that a newly seen `key_id` is missing

## Failure Behavior

Verification MUST fail closed when:

- the discovery URL cannot be fetched and there is no still-valid cached document
- the response is not valid JSON
- the document does not declare `key_discovery` `v1`
- `origin` does not match the fetched origin
- a required top-level field is missing
- `keys` is empty
- a key descriptor is malformed
- `key_id` cannot be matched exactly
- algorithm, status, time bounds, or revocation rules make the matched key unusable
- the discovered key material cannot verify the signature

A verifier MAY use a previously cached document while it is still inside the cache lifetime. Once that cache lifetime has expired, continued use of stale key material is a local trust-policy decision, not a default behavior required by this spec.

## Boundary

This well-known format is a public discovery surface, not a hosted trust service.

It does not require:

- Actenon-operated infrastructure
- a central registry
- a vendor-specific KMS
- a control-plane account

Any issuer with an HTTPS origin can publish a conforming discovery document.

## Compatibility And Versioning

- changing the URL shape, required top-level fields, required key fields, or exact `key_id` matching behavior requires a new version
- additive optional fields do not require a new version if they do not change existing verification meaning
- this spec does not by itself create a hosted verification API or trust registry

## Example

- [`examples/acme-keys.json`](examples/acme-keys.json)

## Related Documents

- [`../../docs/reference/ecosystem/SIGNER_KMS_SPEC.md`](../../docs/reference/ecosystem/SIGNER_KMS_SPEC.md)
- [`../../RECEIPT_V2_DESIGN.md`](../../RECEIPT_V2_DESIGN.md)
- [`../protected-endpoint/SPEC.md`](../protected-endpoint/SPEC.md)
