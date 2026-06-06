# Approval Artifact Format

Status: Active opt-in v1 public verification surface

## Purpose

`approval_artifact v1` is a signed approval bound to the exact canonical
Actenon action. It lets a verifier establish who approved, in which role, when,
and for precisely which action without trusting a caller-provided boolean.

This specification contains no approval service, workflow backend, signer, or
private-key custody implementation.

Machine schema:

- [`../../schemas/approval_artifact.v1.json`](../../schemas/approval_artifact.v1.json)

## Artifact

```json
{
  "contract": {"name": "approval_artifact", "version": "v1"},
  "approval_id": "approval-0042",
  "approver": {"type": "user", "id": "security-admin@example"},
  "approval_type": "security_admin",
  "decision": "approved",
  "action_hash": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "<exact Action Intent hash>"
  },
  "issued_at": "2026-06-06T12:00:00Z",
  "signature": {
    "algorithm": "EdDSA",
    "key_id": "approver-2026-06",
    "encoding": "base64url",
    "value": "<unpadded base64url Ed25519 signature>"
  }
}
```

`action_hash` uses the same exact-action hash input as PCCB minting:
`intent_id`, tenant, requester, action, target, `issued_at`, and `expires_at`.

The signature covers the RFC 8785 canonical bytes of:

```json
{
  "context": "actenon.approval-artifact.v1",
  "approval_id": "<approval id>",
  "approver": "<complete approver identity>",
  "approval_type": "<approval role or type>",
  "decision": "approved",
  "action_hash": "<complete action hash>",
  "issued_at": "<exact issued_at>"
}
```

The key is selected by `kid` from `key_discovery v1`, whose `issuer` must match
the approver. The key descriptor must include `use: "approval_artifact"`.

## Preflight Evidence

Preflight accepts signed artifacts through `approval_artifacts` together with
their public `approval_trusted_keys`. Each artifact is verified and bound to
the exact Action Intent before its `approval_type` can satisfy a policy rule.

Legacy `approval_present` and `approver_types` inputs remain supported for
backward compatibility. They are caller assertions, not cryptographic
evidence. Deployments choose whether that trust assumption is acceptable.

## Claim Boundary

Verification proves the pinned approver key signed the approval fields and
exact action hash. It does not prove the human understood the action, that the
identity system was uncompromised, or that local separation-of-duty policy was
correctly designed.
