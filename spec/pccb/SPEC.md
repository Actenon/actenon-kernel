# PCCB Spec

Status: Active v1

## Purpose

PCCB is the portable proof artifact issued after a positive authorization decision. A protected endpoint verifies this artifact before any consequential action may execute.

PCCB is proof, not a hint.

## Normative Sources

- [`schema.json`](schema.json)
- [`../../schemas/pccb.v1.json`](../../schemas/pccb.v1.json)
- this document

The `/spec` layer is the normative entrypoint for human readers. The underlying machine-readable schema remains versioned under `/schemas`.

## Terminology

- Issuer: the authority that signs or otherwise issues the PCCB.
- Subject: the principal on whose behalf the action was authorized.
- Verifier: the protected endpoint or verifier-side component that validates the PCCB.
- Audience: the intended verifier identity the PCCB is bound to.
- Scope: the capability and execution limits the PCCB authorizes.

## Required Bindings

A valid PCCB must bind all of the following:

- exact action
- exact target
- exact audience
- exact scope
- tenant
- subject
- issue time
- not-before time
- expiry
- nonce
- action hash

If any of those bindings do not match the execution attempt, the verifier must refuse execution.

## Normative Semantics

- Consumers MUST reject payloads whose `contract.name` or `contract.version` do not identify `pccb` `v1`.
- `audience` identifies the intended verifier or protected endpoint.
- A PCCB issued for one audience MUST NOT be accepted by another.
- `scope` defines what the proof authorizes and whether it is single-use.
- `nonce` carries replay-relevant proof material.
- `action_hash` is the canonical digest of the authorized action material.
- `signature` carries the proof material verifiers use to make an explicit trust decision.

In v1, `action_hash` uses:

- algorithm: `sha-256`
- canonicalization: `RFC8785-JCS`

For v1, the action hash is computed over the canonical JSON representation of the normalized action material defined by the corresponding implementation and verifier rules for Action Intent, tenant, requester or subject binding, action, target, and validity window. Independent implementations MUST agree on the same v1 action-hash meaning to claim interoperability.

## Relationship To Escrow

PCCB and escrow are distinct:

- PCCB proves authorization and binding
- escrow governs capability issuance and single-use consumption

A valid PCCB without valid execution-side state may still be refused at execution time.

## Boundary

PCCB must not expose internal policy traces, storage keys, or execution stack details unless those fields are intentionally published as portable public fields.

## Security Considerations

- Verifiers MUST make an explicit trust decision about issuer material rather than treating any syntactically valid signature as sufficient.
- `not_before` and `expires_at` are security controls. Implementations SHOULD maintain clock correctness appropriate to the risk of the protected action. A verifier MAY apply an explicitly configured, bounded clock skew tolerance; the default tolerance SHOULD be zero, and any configured tolerance expands the effective acceptance window.
- Reuse of a PCCB across audiences, tenants, or subjects must be treated as invalid even if the signature verifies.
- `nonce` and replay-related fields SHOULD be treated as single-use execution material, not merely logging metadata.
- `extensions` MUST NOT weaken or override the public binding rules.

## Compatibility And Versioning

- v1 interoperability depends on stable interpretation of `audience`, `scope`, `nonce`, `action_hash`, and `signature`.
- Changes to hash semantics, canonicalization, required bindings, or signature interpretation require a new major version.
- Explanatory notes and additional examples do not create a new version.
- Versioning policy for this repository is defined in [`../../VERSIONING_POLICY.md`](../../VERSIONING_POLICY.md).

## Examples

These examples are informative only. They illustrate active v1 PCCB shape and binding semantics; they do not expand the normative surface.

- [`examples/hello-world.json`](examples/hello-world.json): a baseline PCCB for the hello-world protected endpoint flow.
- [`examples/wrong-audience.json`](examples/wrong-audience.json): a PCCB bound to a different verifier audience. This pairs with [`../refusal/examples/audience-mismatch.json`](../refusal/examples/audience-mismatch.json).
- [`examples/expired.json`](examples/expired.json): a PCCB whose binding window has already ended. This pairs with [`../refusal/examples/expired-proof.json`](../refusal/examples/expired-proof.json) and the stale-proof-reuse entry in [`../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits`](../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits).
- [`examples/wrong-tenant.json`](examples/wrong-tenant.json): a PCCB whose tenant binding no longer matches the supplied Action Intent. This pairs with [`../refusal/examples/wrong-tenant.json`](../refusal/examples/wrong-tenant.json).
- [`examples/wrong-subject.json`](examples/wrong-subject.json): a PCCB whose subject binding no longer matches the supplied Action Intent requester. This pairs with [`../refusal/examples/wrong-subject.json`](../refusal/examples/wrong-subject.json).
- [`examples/mutated-action.json`](examples/mutated-action.json): a forged or mutated PCCB action binding that changes the exact side-effect parameters. This pairs with [`../refusal/examples/action-mismatch.json`](../refusal/examples/action-mismatch.json) and makes the parameter-substitution threat concrete in [`../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits`](../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits).
