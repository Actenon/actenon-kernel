# Revocation And Receipt Durability

This note settles the key lifecycle and receipt-durability doctrine for the
Actenon v2 keystone. It now reflects the implemented outcome-attestation
verification path and the local external-anchor MVP.

The goal is narrow: define how proof and outcome-attestation keys are evaluated,
how historical receipts remain verifiable, and how local external anchors fit
without changing the issuer-signed bytes later.

## Lifecycle Fields

Issuer key records and well-known key-discovery entries must support these
fields for cross-repo verification:

- `status`: one of `active`, `retired`, `suspended`, `revoked`, `hard_revoked`.
- `use`: one or more of `proof_issuance`, `outcome_attestation`.
- `not_before`: earliest artifact issuance time for which the key is valid.
- `expires_at`: latest artifact issuance time for which the key is valid.
- `revoked_at`: soft-revocation timestamp.
- `hard_revoked_at`: hard-revocation timestamp.
- `revocation_reason`: structured reason object.

`revocation_reason` is structured, not free text alone:

```json
{
  "code": "rotation | compromise | suspected_exfiltration | timestamp_trust_loss | operational | superseded | other",
  "detail": "optional human-readable explanation"
}
```

## Lifecycle States

| State | Can sign new artifacts? | Artifacts issued before state-change verify? | Artifacts issued after state-change verify? | Notes |
|---|---:|---:|---:|---|
| active | Yes | Yes | Yes | Normal key state, subject to purpose, time, issuer, signature, and artifact checks. |
| retired | No | Yes | No | Planned rotation/end-of-use. Retired keys remain published for historical verification. |
| suspended | No | Yes, unless policy says suspension is retroactive | No during suspension | Temporary hold. Reversible. Historical artifacts normally remain verifiable because compromise is not assumed. |
| revoked | No | Yes, if issued before revoked_at | No | Soft revoke. Relies on issuer issued_at because soft revoke assumes the key was not compromised before revoked_at. |
| hard_revoked | No | No, unless independently externally anchored before hard_revoked_at | No | Severe compromise/loss of timestamp trust. Historical issuer timestamps are no longer trusted without external anchoring. |

Soft revoke depends on the issuer timestamp being trustworthy. If that
assumption fails, the event must be escalated to `hard_revoked`.

## Soft Revoke

Soft revoke covers normal rotation, operational revocation, superseded keys, and
revocation events where the issuer still trusts timestamps emitted before
`revoked_at`.

Verification behavior:

- Artifacts issued after `revoked_at` must be rejected.
- Artifacts issued before `revoked_at` may verify, subject to normal checks.
- Normal checks include issuer, signature, purpose, `not_before`, `expires_at`,
  artifact shape, digest, and proof/action binding.

Soft revoke is appropriate when the key should stop authorizing new artifacts
but the issuer does not believe the key was compromised before `revoked_at`.

## Hard Revoke

Hard revoke is used only when key compromise means issuer timestamps cannot be
trusted. Examples include confirmed private-key compromise, suspected key
exfiltration, or loss of timestamp trust.

Verification behavior:

- Default behavior is to distrust all artifacts signed by the hard-revoked key.
- Historical artifacts signed before `hard_revoked_at` do not remain valid only
  because they carry an issuer `issued_at` timestamp.
- Exception: an artifact with an independently verified external anchor proving
  the artifact digest existed before `hard_revoked_at` may remain historically
  verifiable.
- Artifacts issued after `hard_revoked_at` must be rejected.

Hard revoke is intentionally severe. It protects verifiers when the issuer's
own timestamps can no longer be used to separate legitimate historical
artifacts from backdated artifacts produced after compromise.

## Trigger Authority

Issuer operators may retire, suspend, and soft revoke keys through normal key
lifecycle operations.

Hard revoke requires documented evidence or a documented operational judgement
that timestamp trust is lost. Valid triggers include:

- confirmed private-key compromise
- suspected private-key exfiltration
- signing-provider compromise affecting timestamp trust
- audit finding that the issuer can no longer distinguish pre-compromise and
  post-compromise artifacts
- emergency operator action later documented with `revocation_reason`

Hard revoke is not a routine rotation mechanism.

## Purpose Binding

Key purpose is security-critical and must be enforced during verification.

- A PCCB must verify only against a key whose `use` includes `proof_issuance`.
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

## External Receipt Durability

The issuer signature proves origin and integrity of the issuer-signed
attestation payload. It does not prove that the artifact existed before a later
hard-revoke event if timestamp trust is lost.

An external anchor proves that the anchored artifact digest existed at or before
a specific time according to an independent trust root. Examples include:

- transparency-log inclusion proof
- RFC-3161-style timestamp
- hosted trust-network inclusion proof
- countersignature by an independent key

Historical verification may depend on both:

- issuer signature, to prove origin and integrity of the signed payload
- external anchor, to prove existence at or before the anchor time

In hard-revoke recovery, an independently verified external anchor may preserve
historical verifiability for an artifact signed before `hard_revoked_at`.

## External Anchors Field

Receipt and refusal attestation envelopes carry `external_anchors`, even when
empty.

Placement is mandatory:

- `unsigned_payload` is signed by the issuer.
- `signature` sits beside `unsigned_payload`.
- `external_anchors` sits beside `signature`.
- `external_anchors` MUST NOT be included in `unsigned_payload`.
- Adding `external_anchors` after signing MUST NOT invalidate the issuer
  signature.

Each external anchor commits to the `artifact_digest` inside the issuer-signed
`unsigned_payload`. Each external anchor is verified independently against its
own trust root when a verifier for that anchor is configured.

Issuer signature verification and external anchor verification are separate
layers:

- The issuer signature proves origin and integrity of `unsigned_payload`.
- The external anchor proves the `artifact_digest` existed at or before the
  verified anchor time.
- Anchors are outside `unsigned_payload`, so adding an anchor after signing does
  not invalidate the issuer signature.
- If anchors are present but no anchor verifier is configured, normal active,
  retired, or soft-revoked historical artifacts may still pass issuer
  verification; the anchors are advisory/unverified and provide no durability
  evidence.
- Hard-revoked historical recovery still requires an independently verified
  pre-revocation external anchor.

Implemented local per-anchor shape:

```json
{
  "contract": {"name": "external_anchor", "version": "v1"},
  "anchor_id": "anc_local_...",
  "anchor_type": "local_append_only_log",
  "artifact_digest": {
    "algorithm": "sha-256",
    "value": "..."
  },
  "anchored_at": "RFC3339",
  "log_uri": "file:///...",
  "sequence": 1,
  "entry_hash": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "..."
  },
  "metadata": {}
}
```

For the current local MVP:

- `external_anchors` may be empty.
- `LocalAppendOnlyAnchorLog` verifies the local JSONL hash chain and the
  referenced entry.
- Hosted transparency, RFC-3161 timestamping, and hosted trust-network
  verification are out of scope.
- `hard_revoked` plus no external anchor must fail historical verification.
- `hard_revoked` plus only advisory/unverified anchors must fail historical
  verification.
- `hard_revoked` plus a verified pre-revocation local anchor may pass
  historical verification.

## Verification Semantics

Verification should proceed in this order:

1. Parse the artifact and verify the issuer-signed payload shape.
2. Verify the embedded artifact digest.
3. Resolve the issuer key by issuer, `key_id`, purpose, status, and artifact
   issue time.
4. Verify the issuer signature over `unsigned_payload`.
5. Apply key lifecycle rules.
6. If lifecycle rules require an external anchor, verify or require verification
   of an anchor whose digest matches the issuer-signed `artifact_digest`.

Issuer signature verification and external-anchor verification are different
operations:

- The issuer signature proves artifact origin and integrity of
  `unsigned_payload`.
- The external anchor proves the artifact digest existed at or before a
  specific time.
- Historical verification may depend on both when a key is hard-revoked.

## Non-Goals

This note does not build or activate:

- a transparency log
- an RFC-3161 timestamp authority
- hosted trust-network anchoring
- a claim that hard-revoked receipts remain valid unless externally anchored
- replay protection, protected-endpoint enforcement, downstream adapter
  correctness, or business-policy correctness
