# KMS Key Rotation Runbook

## Purpose

This runbook describes how to rotate an Actenon proof-issuance signing
key backed by AWS KMS. It is the operator-facing companion to the
key-lifecycle state machine in
[`actenon/proof/signers/key_lifecycle.py`](../../../actenon/proof/signers/key_lifecycle.py)
and the AWS KMS backend in
[`actenon/proof/signers/aws_kms.py`](../../../actenon/proof/signers/aws_kms.py).

Fable 5's review Part 3C identified key custody as the universal gate
across every persona: the CISO, the auditor, the underwriter, and the
engineer all independently arrive at "no real KMS wired." This runbook
exists so that rotation is an executed procedure, not a described one.

## When to rotate

Rotate on any of:

- **Scheduled rotation** — every 90 days for production issuers. Set a
  calendar reminder; do not wait for an incident.
- **Personnel change** — any operator with KMS `kms:Sign` permission on
  the production key leaves the team or loses access. Rotate
  immediately, even if you trust the departing operator.
- **Suspected compromise** — indicators of compromise on the issuer
  host, the KMS client config, or the AWS account. Rotate first,
  investigate second.
- **Confirmed compromise** — the key material is known or believed to
  be in someone else's hands. Rotate and escalate to `revoked` (or
  `hard_revoked` if an external anchor exists — see below).
- **Algorithm deprecation** — AWS deprecates an algorithm or key spec
  (e.g., RSA-2048 below the security threshold). Rotate to a stronger
  key.

## Preconditions

Before starting rotation, verify:

1. **You have KMS permissions.** You need `kms:CreateKey`,
   `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:TagResource`, and
   `kms:Sign` on the old and new keys.
2. **You have Actenon issuer permissions.** You need to update the
   issuer's key reference (typically a config file or database row).
3. **The new key is created but not yet active.** Create the new key
   with `KeySpec=ASYMMETRIC_SIGNATURE_ED25519` (or another supported
   algorithm) and `KeyUsage=SIGN_VERIFY`. Tag it with
   `actenon-lifecycle=active` and `actenon-key-id=issuer:prod:YYYY-MM`.
4. **The new key's public key is published.** Run
   `actenon-kernel keys publish` with the new key's public JWK to
   produce the well-known key discovery document. Verifier-side
   deployments fetch this document to know which keys to trust.
5. **You have a maintenance window.** Rotation is fast (seconds), but
   in-flight proofs may be issued by the old key for a brief period.
   The window ensures clean cutover.

## Rotation procedure

### Step 1: Create the new key in AWS KMS

```bash
# Create the new asymmetric signing key.
NEW_KEY_ID=$(aws kms create-key \
  --key-spec SYMMETRIC_DEFAULT \
  --key-usage SIGN_VERIFY \
  --tags TagKey=actenon-issuer,TagValue=prod \
  --tags TagKey=actenon-lifecycle,TagValue=active \
  --tags TagKey=actenon-key-id,TagValue="issuer:prod:2026-07" \
  --query KeyMetadata.KeyId \
  --output text)

# For asymmetric keys (recommended):
NEW_KEY_ID=$(aws kms create-key \
  --key-spec ECC_ED25519 \
  --key-usage SIGN_VERIFY \
  --description "Actenon proof issuance key for 2026-07" \
  --tags TagKey=actenon-issuer,TagValue=prod \
  --tags TagKey=actenon-lifecycle,TagValue=active \
  --tags TagKey=actenon-key-id,TagValue="issuer:prod:2026-07" \
  --query KeyMetadata.KeyId \
  --output text)

echo "New key ARN: $NEW_KEY_ID"
```

### Step 2: Publish the new key's public key

Fetch the public key from KMS and publish it as a well-known key
discovery document:

```bash
# Get the public key JWK.
aws kms get-public-key --key-id "$NEW_KEY_ID" --output json > /tmp/new-key-pub.json

# Publish the well-known discovery document.
actenon-kernel keys publish \
  --issuer https://authority.example.com \
  --key-id "issuer:prod:2026-07" \
  --public-key-jwk /tmp/new-key-pub.json \
  --output /var/www/.well-known/actenon/keys.json
```

Verifier-side deployments fetch this document on their next cache
refresh (default 5 minutes). The new key will be trusted as soon as
the cache refreshes.

### Step 3: Switch the issuer to use the new key

Update the issuer's config to point at the new key ARN:

```bash
# Update the issuer's key reference (adjust for your config system).
sed -i "s|arn:aws:kms:eu-west-2:123456789012:key/old-5678|$NEW_KEY_ID|g" \
  /etc/actenon/issuer.yaml

# Restart the issuer so it picks up the new config.
systemctl restart actenon-issuer
```

### Step 4: Verify the new key is minting proofs

Issue a test proof and verify it:

```bash
# Issue a test intent + proof against the new key.
actenon intent create --action test.ping --target test:rotation --output /tmp/intent.json
actenon-kernel verify-proof \
  --intent /tmp/intent.json \
  --pccb /tmp/pccb.json \
  --audience service:rotation-test
```

The verify should succeed. If it fails, the well-known discovery
document may not have propagated yet — wait 5 minutes and retry.

### Step 5: Mark the old key as `retired`

Once the new key is minting proofs and the old key has stopped being
used, mark the old key as `retired`:

```bash
# Update the old key's lifecycle tag.
OLD_KEY_ID="arn:aws:kms:eu-west-2:123456789012:key/old-5678"

aws kms tag-resource \
  --key-id "$OLD_KEY_ID" \
  --tags TagKey=actenon-lifecycle,TagValue=retired
```

Update the issuer's local key registry so the old key's status
reflects `retired`:

```python
from actenon.proof.signers.key_lifecycle import KeyLifecycleState, DEFAULT_MACHINE

# Verify the transition is allowed.
DEFAULT_MACHINE.assert_can_transition(
    from_state="active",
    to_state=KeyLifecycleState.RETIRED.value,
)

# Update your key registry (database, config, etc.) to reflect retired.
key_registry.update_status(old_key_id, KeyLifecycleState.RETIRED.value)
```

### Step 6: Verify historical proofs still verify with the old key

The old key should still verify proofs it minted before retirement.
This is the rotation invariant — historical receipts remain auditable.

```bash
# Take a proof minted by the old key before rotation.
actenon-kernel verify-proof \
  --intent /tmp/old-intent.json \
  --pccb /tmp/old-pccb.json \
  --audience service:audit-test
```

This should still succeed. If it fails, the old key was hard-revoked
by mistake — see [Troubleshooting](#troubleshooting) below.

### Step 7: Schedule the old key for deletion (after retention period)

Keep the old key in `retired` state for at least 90 days (or your
regulator's retention requirement, whichever is longer). After the
retention period, schedule the key for deletion in AWS KMS:

```bash
# Schedule deletion 7 days out (minimum allowed by AWS KMS).
aws kms schedule-key-deletion \
  --key-id "$OLD_KEY_ID" \
  --pending-window-in-days 7
```

This moves the AWS KMS key state to `PendingDeletion`, which the
Actenon backend maps to `revoked`. The key can no longer sign (already
true — it was retired) and can still verify (until AWS actually
deletes it).

**Important:** once AWS actually deletes the key, neither signing nor
verification will work. Make sure all historical receipts that need to
remain auditable have been re-anchored to an external anchor
(transparency log, third-party countersignature) BEFORE the key is
deleted.

## Escalation: hard-revocation

If the old key is confirmed compromised AND you have an external anchor
(transparency log inclusion proof) that proves historical proofs
predated the compromise, you may hard-revoke the key:

```bash
aws kms tag-resource \
  --key-id "$OLD_KEY_ID" \
  --tags TagKey=actenon-lifecycle,TagValue=hard_revoked
```

Hard-revocation:

- **Blocks signing** (already blocked by `retired`)
- **Blocks verification** — historical receipts signed by this key
  become unverifiable
- **Breaks historical verifiability** — only safe if an external anchor
  exists

**Do not hard-revoke without an external anchor.** If you do, you lose
the ability to audit historical receipts, which defeats the entire
purpose of the Actenon evidence chain.

## Troubleshooting

### "Key in state 'retired' cannot sign"

This is correct behaviour. Retired keys do not sign — they only
verify. If you need to mint with the old key, you have a bug in your
cutover. Investigate why the issuer is still trying to use the old
key; do NOT re-activate it (see `retired -> active` is forbidden in
the state machine).

### "Key in state 'hard_revoked' cannot verify"

This is correct behaviour after hard-revocation. Historical proofs
signed by this key are no longer verifiable. If you did not intend
this, you must have an external anchor (transparency log) to fall back
on. If you do not have one, do not hard-revoke.

### Rotation verification fails (new key not trusted)

The verifier's well-known key cache has not refreshed yet. Wait 5
minutes (or whatever `DEFAULT_WELL_KNOWN_CACHE_MAX_AGE_SECONDS` is set
to in your deployment). If it still fails, check that the well-known
discovery document is reachable from the verifier's network.

### AWS KMS Sign API call fails with `KMSInvalidStateException`

The key is in a non-signable AWS state (Disabled, PendingDeletion,
PendingImport, Unavailable, Updating). Check the key's state in the
AWS console. The Actenon backend maps these to `suspended` or
`revoked` and refuses to sign — this is correct fail-closed behaviour.

## See also

- [Signer And KMS Spec](SIGNER_KMS_SPEC.md) — the portable signer boundary
- [`actenon/proof/signers/key_lifecycle.py`](../../../actenon/proof/signers/key_lifecycle.py) — state machine source
- [`actenon/proof/signers/aws_kms.py`](../../../actenon/proof/signers/aws_kms.py) — AWS KMS backend source
- [`tests/unit/test_aws_kms_signer.py`](../../../tests/unit/test_aws_kms_signer.py) — backend tests
- [Insurer Clarity](../../../../actenon-cloud/docs/INSURER_CLARITY.md) — what cryptography does and does not prove
