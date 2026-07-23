# External Anchors

External anchors are optional durability evidence for copied Receipt and Refusal
attestation envelopes. They are deliberately outside `unsigned_payload`, so an
anchor can be appended after issuer signing without changing the signature
input.

This pass implements only a local primitive:

```text
Receipt or Refusal
  -> outcome attestation unsigned_payload.artifact_digest
  -> LocalAppendOnlyAnchorLog JSONL entry
  -> external_anchors[] sibling entry
  -> verifier checks local log entry and hash chain
```

There is no hosted trust network in this feature.

## Wire Boundary

An outcome attestation keeps this shape:

```json
{
  "contract": {"name": "receipt_attestation", "version": "v2alpha1"},
  "unsigned_payload": {
    "artifact_digest": {"algorithm": "sha-256", "value": "..."}
  },
  "signature": {"algorithm": "EdDSA", "key_id": "...", "encoding": "base64url", "value": "..."},
  "external_anchors": []
}
```

`external_anchors` must remain a sibling of `unsigned_payload`. If it appears
inside `unsigned_payload`, parsing fails. Because the signature covers only
`unsigned_payload`, adding a valid anchor after signing does not invalidate the
issuer signature.

## Local Append-Only Log

`LocalAppendOnlyAnchorLog` writes JSON lines. Each entry stores:

- local anchor contract and sequence number
- anchor id
- artifact type and artifact id when available
- the attestation `artifact_digest`
- anchor time
- previous entry hash
- current entry hash

The entry hash is a SHA-256 digest of the canonical entry without `entry_hash`.
Verification replays the local log, checks contiguous sequence numbers, checks
the hash chain, finds the referenced entry, and confirms the anchor commits to
the signed `artifact_digest`.

Example:

```python
from actenon.anchors import LocalAppendOnlyAnchorLog
from dataclasses import replace

log = LocalAppendOnlyAnchorLog("var/anchors/outcomes.jsonl")
attestation = outcome_service.attest_receipt(receipt)

anchor = log.anchor_attestation(attestation)
anchored_attestation = replace(
    attestation,
    external_anchors=[*attestation.external_anchors, anchor.to_dict()],
)
```

Or use the convenience helper:

```python
anchored_attestation = log.append_anchor_to_attestation(attestation)
```

## Verification

Configure the outcome attestation verifier with the local log:

```python
service = OutcomeAttestationService(
    signer=verifier_or_signer,
    issuer=issuer,
    external_anchor_verifier=log,
)

service.verify_receipt_attestation(anchored_attestation, verifier=signature_verifier)
```

If `external_anchors` is non-empty and no anchor verifier is configured,
issuer signature verification may still pass for normal active, retired, or
soft-revoked historical artifacts. In that case the anchors are advisory and
unverified: they do not provide durability evidence and no anchor time is passed
to key-lifecycle policy.

Unsupported or opaque anchors are also advisory unless a configured verifier can
verify them. A configured verifier failure for a supported anchor, such as a
wrong artifact digest, fails verification.

## Hard Revocation

Well-known key discovery treats `hard_revoked` as stricter than normal
revocation. A hard-revoked key fails historical verification unless the
attestation has an independently verified external anchor with an anchor time
before `hard_revoked_at`.

For the local MVP:

- hard-revoked key with no anchor fails
- hard-revoked key with only advisory or unverified anchors fails
- hard-revoked key with a wrong-digest anchor fails
- hard-revoked key with a valid pre-revocation local anchor passes

This does not prove a hosted timestamping service, global publication, provider
finality, business correctness, or operator honesty. It proves the copied
artifact was committed into the configured local append-only log before the
hard-revocation boundary used by the verifier.
