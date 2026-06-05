# Action Intent Spec

Status: Active v1

## Purpose

Action Intent is the public, versioned contract external callers use to request a consequential action.

It is transport-agnostic and implementation-agnostic. It is not an internal API body, queue envelope, database row, or policy snapshot.

## Normative Sources

- [`schema.json`](schema.json)
- [`../../schemas/action_intent.v1.json`](../../schemas/action_intent.v1.json)
- this document

The `/spec` layer is the normative entrypoint for human readers. The underlying machine-readable schema remains versioned under `/schemas`.

## Terminology

- Caller: the external system or principal that creates and submits an Action Intent.
- Intent: a single consequential-action request expressed using this contract.
- Authorizer: a system that evaluates an intent and decides whether proof may be minted.
- Protected endpoint: the execution edge that ultimately verifies proof before side effects.

## Required Top-Level Fields

- `contract`
- `intent_id`
- `issued_at`
- `expires_at`
- `tenant`
- `requester`
- `action`
- `target`

## Normative Semantics

- Consumers MUST reject payloads whose `contract.name` or `contract.version` do not identify `action_intent` `v1`.
- `intent_id` is the caller-stable correlation identifier, not an internal storage key.
- `idempotency_key`, when present, is a transmission and retry aid. It is not authorization material.
- `issued_at` and `expires_at` define the caller's stated validity window.
- Implementations SHOULD enforce that `expires_at` is later than `issued_at`.
- `tenant` defines the policy and execution isolation boundary.
- `requester` identifies the principal asking for the action.
- `action` names the requested operation, capability, and parameters in portable public vocabulary.
- `action.parameters` carries the exact portable parameters the caller is asking to execute.
- `target` identifies the resource under action in a way that later proof and receipt material can bind to exactly.
- `context` may carry caller-supplied facts, but it is not a substitute for runtime context gathered later by an implementation.
- `evidence_refs` may point at supporting material, but this contract does not standardize evidence storage, retrieval, or approval workflows.
- `evidence_refs.type=actenon.receipt`, when used, is an additive standard evidence-reference convention for pointing at a prior Receipt artifact by `receipt_id` plus digest. Consumers MAY independently verify that reference through local policy or evidence-chain rules.
- `metadata` may carry annotations that do not change core meaning.
- `extensions` is the only vendor-specific escape hatch. Consumers MUST NOT derive core authorization semantics from `extensions`.

## Boundary

Action Intent must not be coupled to:

- HTTP route names
- internal service names
- storage schema
- policy engine internals
- proof or escrow internals

## Security Considerations

- Implementations MUST treat the Action Intent as untrusted input until validated.
- `requester`, `tenant`, `action`, and `target` are security-relevant fields and SHOULD be preserved exactly once accepted.
- `evidence_refs` are references, not proof of possession or proof of integrity unless the referenced object is independently verified.
- receipt evidence refs, when present, SHOULD carry a digest over the referenced Receipt artifact so local policy can verify evidence-chain integrity without redefining the Action Intent contract.
- `extensions` MUST NOT be used to smuggle hidden authorization semantics around the public contract.
- Long validity windows increase exposure to replay, stale context, and delayed execution risk. Implementations SHOULD use bounded time windows appropriate to the action class.

## Compatibility And Versioning

- v1 compatibility is defined by the published schema and normative semantics in this document.
- Additive explanatory documentation changes do not create a new version.
- Changes that alter field meaning, required fields, identifier rules, or timestamp interpretation require a new major version.
- Versioning policy for this repository is defined in [`../../VERSIONING_POLICY.md`](../../VERSIONING_POLICY.md).

## Examples

These examples are informative only. They show how active v1 fields can be used without adding new semantics beyond the published contract.

- [`examples/hello-world.json`](examples/hello-world.json): the minimal protected-resource path used by the portable local proof flow.
- [`examples/invoice-payment.json`](examples/invoice-payment.json): a realistic finance-wedge Action Intent showing exact payment binding, batch binding, evidence references, and idempotency fields within the active v1 contract.

The hello-world Action Intent is also the caller-side baseline paired with the proof and refusal examples for:

- audience mismatch
- expired proof
- wrong tenant
- wrong subject
- action mutation or parameter substitution
- replay refusal after a prior successful claim

Those pairings make the protected-endpoint attack classes concrete without adding any new Action Intent semantics beyond v1.

For the corresponding threat descriptions and residual limits, see [`../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits`](../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits).
