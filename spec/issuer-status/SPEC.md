# Issuer Status Format

Status: Active opt-in v1 public verification surface

## Purpose

`issuer_status v1` is a short-lived, signed assertion about whether a proof
issuer is in good standing. It lets a relying party make a freshness-bounded
revocation decision offline using pinned public keys.

This specification defines the artifact and verification behavior only. It
does not define or operate an issuer registry, status API, key custodian, or
availability service.

Machine schema:

- [`../../schemas/issuer_status.v1.json`](../../schemas/issuer_status.v1.json)

## Artifact

```json
{
  "contract": {"name": "issuer_status", "version": "v1"},
  "issuer": {"type": "service", "id": "proof-issuer.example"},
  "authority": {"type": "service", "id": "issuer-status-authority.example"},
  "status": "good_standing",
  "issued_at": "2026-06-06T12:00:00Z",
  "expires_at": "2026-06-06T12:15:00Z",
  "status_reference": "status-entry-0042",
  "signature": {
    "algorithm": "EdDSA",
    "key_id": "status-2026-06",
    "encoding": "base64url",
    "value": "<unpadded base64url Ed25519 signature>"
  }
}
```

`status` is one of `good_standing`, `suspended`, or `revoked`.

The signature covers the RFC 8785 canonical bytes of:

```json
{
  "context": "actenon.issuer-status.v1",
  "issuer": "<complete issuer identity>",
  "authority": "<complete authority identity>",
  "status": "<status>",
  "issued_at": "<exact issued_at>",
  "expires_at": "<exact expires_at>",
  "status_reference": "<included only when present>"
}
```

The key is selected by `kid` from `key_discovery v1`, whose `issuer` must match
`authority`. The key descriptor must include `use: "issuer_status"`.

## Verification

`verify_issuer_status` checks:

1. exact issuer identity
2. status authority against the pinned key-set issuer
3. key purpose, validity interval, and `kid`
4. Ed25519 signature
5. assertion issue time and expiry
6. caller-configured maximum freshness
7. `good_standing` status

The default policy is `required` and fails closed for missing, expired, stale,
unverifiable, suspended, or revoked status.

`status_policy="disabled"` is an explicit fail-open opt-out. The verifier logs
a warning and performs no status check. It is not suitable for high-assurance
verification.

## Claim Boundary

A valid assertion proves only that the pinned status authority signed the
stated status for the stated interval. It does not prove the issuer's business,
regulatory, or operational trustworthiness beyond that authority's assertion.
