# Refusal Spec

Status: Active v1

## Purpose

Refusal is the structured, machine-readable envelope for a denied or invalid consequential-action request.

It is the public contract callers and protected endpoints can rely on when the system will not proceed.

## Normative Sources

- [`schema.json`](schema.json)
- [`../../schemas/refusal.v1.json`](../../schemas/refusal.v1.json)
- this document

The `/spec` layer is the normative entrypoint for human readers. The underlying machine-readable schema remains versioned under `/schemas`.

## Terminology

- Category: the high-level class of failure such as schema, policy, proof, or replay.
- Reason code: the stable programmatic failure identifier.
- Violation: a field-level or rule-level detail attached to a refusal.

## Required Fields

- `contract`
- `refusal_id`
- `category`
- `reason_code`
- `message`
- `retryable`
- `refused_at`

## Normative Semantics

- Consumers MUST reject payloads whose `contract.name` or `contract.version` do not identify `refusal` `v1`.
- `category` identifies the refusal family such as `schema`, `policy`, `proof`, `escrow`, `replay`, or `execution`.
- `reason_code` is the stable programmatic failure code.
- `message` is human-readable and safe to expose externally.
- `retryable` tells the caller whether retry can succeed after correction or time passage.
- `violations` provides field-level or rule-level details without forcing clients to parse free-form text.
- `rule_refs` MAY expose published rule identifiers when those identifiers are safe and intentionally public.
- `details` and `extensions` MAY add explanatory information, but core refusal meaning is determined by the required top-level fields.

## Boundary

Refusal must not leak:

- secret material
- raw signatures
- private keys
- internal stack traces

Published rule identifiers are allowed only when they are intentionally safe to expose.

## Security Considerations

- Refusal payloads SHOULD fail closed: they should explain enough to support remediation without exposing secrets or private operational state.
- Implementations MUST avoid leaking raw cryptographic material, stack traces, provider credentials, or hidden workflow internals.
- `retryable` should reflect whether a corrected or delayed retry can plausibly succeed, not whether the transport can be retried mechanically.
- Consumers SHOULD rely on `category`, `reason_code`, and `violations` for machine handling rather than parsing `message`.

## Compatibility And Versioning

- v1 compatibility is defined by the refusal schema and refusal semantics in this document. Readers accept the legacy `refusal_code` spelling during the documented migration window; newly emitted artifacts use `reason_code`.
- Changes to refusal categories, code interpretation, required fields, or violation semantics require a new major version.
- Additional examples and explanatory text do not create a new version.
- Outcome Attestation v2alpha1 may wrap a v1 Refusal in a signed envelope, but it does not change the v1 refusal payload or semantics. See [`../outcome-attestation/SPEC.md`](../outcome-attestation/SPEC.md).
- Versioning policy for this repository is defined in [`../../VERSIONING_POLICY.md`](../../VERSIONING_POLICY.md).

## Examples

These examples are informative only. They illustrate active v1 refusal shapes and attack classes; they do not add new refusal categories, refusal codes, or fields.

- [`examples/policy-deny.json`](examples/policy-deny.json): policy denial for the refund wedge.
- [`examples/audience-mismatch.json`](examples/audience-mismatch.json): proof refusal for a PCCB presented to the wrong protected endpoint. This pairs with [`../pccb/examples/wrong-audience.json`](../pccb/examples/wrong-audience.json).
- [`examples/expired-proof.json`](examples/expired-proof.json): proof refusal for a PCCB presented after its validity window. This maps to the stale-proof-reuse entry in [`../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits`](../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits).
- [`examples/action-hash-mismatch.json`](examples/action-hash-mismatch.json): proof refusal for an Action Intent whose validity window no longer matches the proof-bound action hash.
- [`examples/action-mismatch.json`](examples/action-mismatch.json): proof refusal for a mutated proof action whose exact parameters no longer match the Action Intent. This maps to the parameter-substitution threat class in [`../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits`](../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits).
- [`examples/wrong-tenant.json`](examples/wrong-tenant.json): proof refusal for a PCCB whose tenant binding does not match the Action Intent.
- [`examples/wrong-subject.json`](examples/wrong-subject.json): proof refusal for a PCCB whose subject binding does not match the Action Intent requester.
- [`examples/replay-refused.json`](examples/replay-refused.json): replay refusal for a duplicate execution attempt after the proof-bound action was already claimed.
