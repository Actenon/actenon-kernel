# Signer And KMS Spec

## Purpose

This document defines the portable signer boundary for proof minting and verification.

The open kernel needs a stable way to sign PCCBs in local, KMS-backed, or HSM-backed environments without hard-coding a specific key-management product into the repository.

## Scope

This document defines:

- the portable `Signer` contract
- the local reference signer
- abstract KMS-backed and HSM-backed signer adapters
- the Python well-known key resolver for verifier-side trust distribution
- stable expectations for `algorithm`, `key_id`, and signature encoding

This document does not define:

- cloud-vendor KMS APIs
- production key-rotation workflows
- HSM operational procedures
- hosted key-custody services

## Normative Interface

The reference interfaces live at:

- `actenon/proof/signers/base.py`
- `actenon/proof/signers/local.py`
- `actenon/proof/signers/external_managed.py`
- `actenon/proof/signers/kms.py`
- `actenon/proof/signers/hsm.py`

Compatibility shims are preserved at:

- `actenon/proof/signing.py`
- `actenon/proof/local.py`

## Signer Contract

A conforming signer exposes:

- `algorithm`
- `key_id`
- `sign(payload: bytes) -> SignatureSpec`
- `verify(payload: bytes, signature: SignatureSpec) -> bool`

`SignatureSpec` remains the portable proof signature envelope used by PCCBs.

## Local Signer

The open kernel preserves the current deterministic local signer behavior through:

- `HmacSha256Signer`
- `build_local_proof_signer()`

This signer exists for:

- local proof mode
- tests
- reference demos

It is not positioned as production key custody.

## KMS And HSM Boundaries

The KMS and HSM modules define adapter shapes, not product integrations.

They exist so external systems can:

- delegate proof signing to a remote key-management system
- delegate proof signing to an HSM-backed service
- preserve the kernel's portable `Signer` contract

These modules do not imply that the OSS kernel now ships a production signer service.

## External-Managed Production Seam

The production custody seam is:

- `ExternalManagedSigningBackend`
- `ExternalManagedSigner`
- `ManagedKeyReference`
- `ManagedSigningAuditMetadata`
- `ManagedSigningResult`
- `validate_signing_backend_for_environment(...)`

This seam is provider-neutral. It signs canonical bytes with a non-exportable
managed key and adapts the result back to the existing `SignatureSpec` envelope,
so the PCCB wire contract does not change.

The backend contract must:

- return algorithm, key id, signature bytes, public key reference, and optional provider operation id
- never expose private key material
- check key status before signing
- accept non-secret audit metadata
- refuse unknown, suspended, revoked, hard-revoked, disabled, deleted, or wrong-purpose keys

Production backend selection must fail closed for `development_local_hmac` and
for `pilot_local_eddsa` unless a deployment uses an explicit unsafe override for
a documented emergency/demo path. The intended production backend shape is
`external_managed`.

## Verification-Side Deployment Model

Protected endpoints do not need proof minting capability in order to verify PCCBs.

Verifier-side deployments need:

- a trust root or verification adapter that can validate PCCB signatures
- stable `algorithm` and `key_id` routing information
- a protected endpoint that supplies the correct local audience, capability, and replay context

The Python reference path exposes:

- `actenon.proof.SignatureVerifier`
- `actenon.verifier.VerifierSDK`
- `actenon.proof.WellKnownKeyResolver`
- `actenon.proof.WellKnownKeySignatureVerifier`

Local demos use `build_local_proof_signer()` as a deterministic trust root. That local `HS256` HMAC material is public repository test material, not production custody; anyone can forge local-mode proofs from the default secret. Production deployments can supply a verifier-compatible asymmetric implementation without turning the protected endpoint into a proof-minting service.

The zero-dependency well-known resolver path handles:

- HTTPS fetch
- no-redirect default discovery
- canonical issuer-origin and well-known path enforcement
- localhost/private/link-local/metadata IP rejection where visible to the fetcher
- JSON parsing
- `key_id` selection
- revocation and expiry checks
- cache-backed resolution

Actual asymmetric signature verification from discovered JWKs currently requires the optional `cryptography` package in the Python environment. The repository does not add that as a hard dependency.

For issuer-side publication, the CLI also exposes:

- `actenon-kernel keys publish`

That command generates a conformant `key_discovery` `v1` JSON document for a single verification key from supplied public JWK material. It is intentionally small: it helps an issuer publish the well-known document shape, but it does not provide rotation orchestration or hosted lifecycle management.

## Optional Proof Seal Client Hook

The kernel also exposes an optional proof-seal client hook for deployments that
want to replace the locally minted PCCB with a sealed PCCB before execution.

The reference interfaces live at:

- `actenon/proof/signers/proof_seal.py`

The public boundary is intentionally small:

- `ProofSealClient`
- `NoOpProofSealClient`
- `HttpProofSealClient`
- `ProofSealError`

This hook is not a hosted Actenon service. It is a client-side integration
point only.

Important execution invariant:

- proof sealing is optional
- if sealing is enabled synchronously, it is part of the critical admit path
- graph-style fire-and-forget publication rules do not apply to seal
  substitution because the sealed PCCB may be the proof used for subsequent
  escrow issuance and protected-endpoint execution

The kernel therefore only accepts seal substitutions that preserve the active
v1 binding surface of the locally minted PCCB, including:

- `intent_id`
- `issued_at`
- `not_before`
- `expires_at`
- `subject`
- `tenant`
- `audience`
- `action`
- `target`
- `scope`
- `escrow_id`
- `action_hash`

The substitution path may change identity and attestation-oriented fields such
as:

- `pccb_id`
- `issuer`
- `nonce`
- `signature`
- additive `extensions`

If `require_proof_seal=True`, proof-seal failures are refusal-producing and do
not fall through silently to local execution proof minting. If sealing is
disabled, kernel behavior remains unchanged. If sealing is configured but not
required, the local PCCB remains the fallback.

## Security Considerations

- A signer is only as trustworthy as the underlying key-management system and configured trust roots.
- `key_id` is a routing and trust-decision aid, not proof of custody by itself.
- Compromise of the signing authority or verification trust roots is outside what the open kernel can remediate automatically.
- Deployers SHOULD ensure that algorithm choice, verification behavior, and key identity remain stable across independent verifier implementations.

## Boundary

The OSS kernel publishes the signer contract and minimal adapter shims.

It does not publish:

- a required production KMS provider integration
- a hosted signing service
- key-rotation orchestration
- operator key-management workflows
- a hosted key-discovery registry
