# Production Signing Custody

Status: architecture and interface plan. The open kernel defines production signing custody requirements and provides an external-managed signing seam. This document does not claim that any hosted Actenon Cloud deployment is already operating production KMS/HSM custody.

## Core Rule

Production proof issuance must use non-exportable asymmetric private keys.

- `external_managed` is the production custody backend shape.
- `pilot_local_eddsa` is for tests, pilots, and interop only.
- `development_local_hmac` is never production.

Safe public claim:

> Actenon defines the production signing custody requirements and provides an external-managed signing seam.

Unsafe public claim unless separately implemented and operated:

> Actenon Cloud uses production KMS/HSM custody.

## Production Requirements

Production signing custody requires:

- non-exportable private keys
- KMS/HSM-backed asymmetric signing
- explicit key purpose: `proof_issuance` or `outcome_attestation`
- separation between proof issuance keys and outcome-attestation keys
- tenant-aware key references
- public verification material published through well-known JWK discovery
- rotation, suspend, revoke, and hard-revoke lifecycle handling
- audit logging for every signing operation
- provider operation references where available
- no private key export, no private JWK fields, and no raw secret material in application state
- emergency key compromise playbook

The issuer/control plane is the proof root. Production signing custody is therefore high-value infrastructure, not an implementation detail.

## Backend Contract

The provider-neutral backend contract lives in:

- `actenon/proof/signers/external_managed.py`

The contract is intentionally narrow:

- sign canonical bytes
- return algorithm, key id, signature bytes, public key reference, and optional provider operation id
- never expose private key material
- report key status before signing
- accept non-secret audit metadata
- fail closed for unknown, suspended, revoked, hard-revoked, disabled, deleted, wrong-purpose, or mismatched keys

The `ExternalManagedSigner` adapts the managed result back into the existing `SignatureSpec` envelope, so the PCCB wire contract does not change.

## Key Reference Shape

`ManagedKeyReference` includes:

- provider
- provider key reference
- public key id (`kid`)
- algorithm
- purpose
- tenant id, where applicable
- public key reference
- key version
- lifecycle status

The provider key reference is a pointer to the managed key, not private key material.

## Audit Metadata

Every production signing operation should record at least:

- operation id
- purpose
- tenant id
- request id
- correlation id
- actor or service identity where available
- payload digest
- key id
- provider operation id
- outcome: completed or refused/failed

Audit records must not contain private keys, raw credentials, provider secrets, full action parameters unless explicitly approved by policy, or raw signature material unless the deployment intentionally stores public proof artifacts.

## Production Guard

Production mode must reject unsafe signing backends:

- `development_local_hmac`: fail closed in production
- `pilot_local_eddsa`: fail closed in production unless an explicit unsafe override is set for a narrowly documented emergency/demo path
- unknown backend: fail closed in production
- `external_managed`: allowed production backend shape

The kernel exposes:

- `validate_signing_backend_for_environment(...)`
- `ProductionSigningGuardError`
- `ExternalManagedSigner`
- `ExternalManagedSigningBackend`

The local HMAC signer refuses production-like environments and has no
production override. That guard is separate from, and complementary to,
backend selection validation.

## Provider Notes

The recommended first provider shape is AWS KMS asymmetric signing or an enterprise HSM/PKCS#11-backed signing service.

Algorithm compatibility must be checked against the kernel verifier contract:

- Ed25519/EdDSA is preferred where the provider supports non-exportable Ed25519 signing and public JWK publication.
- RS256 is acceptable where RSA keys meet kernel strength requirements.
- ECDSA/ES256 must not be claimed as kernel-verifiable until the verifier contract supports it.

Provider-specific adapters should live behind the `ExternalManagedSigningBackend` protocol. Do not bake AWS, GCP, Azure, Vault, or PKCS#11 details into the PCCB wire contract.

## Key Lifecycle

Lifecycle states must be reflected in signing and verification:

- `active`: may sign for its configured purpose
- `suspended`: cannot sign; historical interpretation depends on verifier policy
- `revoked`: cannot sign; publish revocation boundary
- `hard_revoked`: cannot sign; historical recovery requires valid independent anchoring where supported
- `retired`: cannot sign new artifacts; historical verification may remain valid according to lifecycle policy

Signing must fail closed for any non-active provider or local lifecycle status.

## Emergency Key Compromise

When compromise is suspected:

1. Suspend the key immediately.
2. Stop issuing proof with that key.
3. Rotate to a new managed key only after custody and policy checks pass.
4. Publish updated well-known JWK lifecycle metadata.
5. Preserve signing audit records and provider operation logs.
6. Identify affected artifacts by key id, tenant, issuer, time range, and payload digest.
7. Decide whether revocation or hard-revocation is required.
8. If hard-revoked, require independent external anchors for historical recovery where that recovery is supported.
9. Notify affected operators according to the deployment incident plan.
10. Document root cause and update IAM, custody, approval, and monitoring controls.

Do not export the private key to investigate. Provider-side attestations, logs, and public verification material are the inspection surface.

## Non-Claims

This document does not claim:

- a hosted signing service exists in the OSS kernel
- AWS KMS is configured in every deployment
- production key ceremonies are automated
- production custody is complete for Actenon Cloud unless the Cloud deployment separately proves it
- local HMAC or pilot-local EdDSA are production-safe
- a valid signature proves the business decision was correct
