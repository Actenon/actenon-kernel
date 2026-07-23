# Key Lifecycle Runbook

Status: operational runbook template for managed signing custody. Adapt this to the deployment's KMS/HSM provider, IAM model, incident process, and retention requirements before production use.

## Scope

This runbook covers keys used for:

- `proof_issuance`
- `outcome_attestation`

It assumes production keys are non-exportable asymmetric keys managed by KMS, HSM, or equivalent custody. It does not apply to `development_local_hmac` or `pilot_local_eddsa` except to state that they are not production keys.

## Lifecycle States

| State | Signing behavior | Verification posture |
| --- | --- | --- |
| `active` | May sign for its configured purpose. | Verifiers may accept according to proof binding and time policy. |
| `retired` | Must not sign new artifacts. | Historical verification may pass according to lifecycle policy. |
| `suspended` | Must not sign. | Treat as blocked for new issuance; investigate before reactivation. |
| `revoked` | Must not sign. | Publish revocation boundary and reject affected artifacts according to policy. |
| `hard_revoked` | Must not sign. | Historical recovery requires valid independent anchoring where supported. |

Any unknown provider state must fail closed.

## Create Key

1. Create a non-exportable asymmetric key in the provider.
2. Set key usage to signing/verification only.
3. Assign purpose: `proof_issuance` or `outcome_attestation`.
4. Bind tenant or issuer ownership where applicable.
5. Record provider key reference and public key reference.
6. Publish public verification material through well-known JWK discovery.
7. Verify the key can sign canonical bytes through `external_managed`.
8. Verify public verification succeeds from the published JWK.
9. Record the creation ceremony and operator approvals.

Do not export private key material.

## Activate Key

1. Confirm key purpose, algorithm, tenant, and issuer.
2. Confirm public JWK publication.
3. Confirm provider key status is active/enabled.
4. Confirm audit logging is enabled.
5. Mark the key active/default for its purpose.
6. Perform a test signing operation over non-production canonical bytes.
7. Verify the signature using the public verifier path.

## Rotate Key

1. Create and validate the replacement key.
2. Publish the replacement public JWK.
3. Mark the replacement active/default.
4. Stop new signing with the old key.
5. Mark the old key retired.
6. Preserve the old public key for historical verification until retention policy permits removal.
7. Review signing audit records for unexpected use of the old key after rotation.

Rotation must not rewrite existing proof payloads.

## Suspend Key

Use suspension when compromise is suspected but not confirmed, or when provider/IAM behavior is uncertain.

1. Disable signing in Actenon configuration.
2. Disable or suspend the provider key where supported.
3. Publish suspended lifecycle status.
4. Alert operators.
5. Preserve audit and provider logs.
6. Investigate before reactivation or revocation.

Suspended keys must not sign.

## Revoke Key

Use revocation when the key must no longer be trusted for new signing and a revocation boundary is needed.

1. Stop all signing with the key.
2. Publish revoked lifecycle status and timestamp.
3. Rotate to a replacement key if issuance must continue.
4. Identify affected artifacts by key id, tenant, issuer, and time range.
5. Preserve audit evidence.
6. Communicate verifier policy for historical artifacts.

Revoked keys must not sign.

## Hard-Revoke Key

Use hard revocation when compromise means historical artifacts require independent durability evidence for recovery.

1. Stop all signing with the key.
2. Publish hard-revoked lifecycle status and timestamp.
3. Rotate to a replacement key.
4. Identify affected artifacts and external anchors.
5. Require valid external anchors for historical recovery where supported.
6. Treat unanchored historical artifacts as failed or a documented non-success verification state.
7. Preserve all provider, issuer, audit, and incident records.

Hard-revoked keys must not sign.

## Emergency Key Compromise Playbook

1. Declare an incident and assign an incident owner.
2. Suspend the suspected key immediately.
3. Block new signing operations for the key id and provider key reference.
4. Preserve application audit logs and provider signing logs.
5. Rotate to a known-good managed key if issuance must continue.
6. Publish updated well-known JWK lifecycle metadata.
7. Compare audit records against expected issuance requests.
8. Determine whether revoke or hard-revoke is required.
9. Notify affected operators, tenants, or relying parties according to policy.
10. Update IAM, custody, approval, monitoring, and deployment controls before closing.

Do not export private keys for investigation. Use provider attestations, public keys, logs, and signed artifact digests.

## Production Guard Checklist

- `development_local_hmac` is rejected in production.
- `pilot_local_eddsa` is rejected in production unless an explicit unsafe override is documented and time-bounded.
- `external_managed` is selected for production signing.
- Key purpose matches requested operation.
- Provider and local key status are active before signing.
- Audit metadata is recorded for every signing attempt.
- Public verification succeeds from well-known key discovery.

