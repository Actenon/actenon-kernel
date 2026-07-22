# Receipt Spec

Status: Active v1

## Purpose

Receipt is the portable outcome record for consequential-action handling.

It is not limited to successful execution. In v1 it supports:

- `allow`
- `deny`
- `approval-required`
- `needs-evidence`
- `executed`
- `refused`

## Normative Sources

- [`schema.json`](schema.json)
- [`../../schemas/receipt.v1.json`](../../schemas/receipt.v1.json)
- this document

The `/spec` layer is the normative entrypoint for human readers. The underlying machine-readable schema remains versioned under `/schemas`.

## Terminology

- Outcome: the high-level result recorded by the receipt.
- Phase: the stage of the protected execution lifecycle where the outcome was recorded.
- Correlation: portable references to adjacent artifacts such as PCCBs, refusals, or request identifiers.

## Required Fields

- `contract`
- `receipt_id`
- `intent_id`
- `occurred_at`
- `outcome`
- `tenant`
- `subject`
- `action`
- `target`
- `summary`

## Normative Semantics

- Consumers MUST reject payloads whose `contract.name` or `contract.version` do not identify `receipt` `v1`.
- `allow` means the action was authorized at the decision stage, not necessarily executed.
- `deny` means the action was rejected at the decision stage.
- `approval-required` means the action is pending an approval workflow outside the current path.
- `needs-evidence` means additional evidence is required before proceeding.
- `executed` means the protected action executed and side effects may have completed.
- `refused` means the action was refused at validation, proof, replay, escrow, or execution-guard time.
- A receipt records an outcome. It does not itself authorize a later execution attempt.
- `summary` MUST remain interpretable without access to internal database rows or internal workflow state.
- `side_effects.external_reference` MAY carry a generic execution reference.
- `side_effects.provider_reference`, when present, identifies the downstream provider or external-system reference for the side effect.
- `side_effects.reconciliation_status`, when present, carries the kernel-facing reconciliation status known at receipt creation time.
- `details`, `metadata`, and `extensions` MAY add information, but core outcome meaning is determined by the top-level receipt fields.

## Correlation

`correlation` is the portable place to link a receipt to adjacent artifacts such as:

- `pccb_id`
- `escrow_id`
- `refusal_id`
- `request_id`
- `action_hash`

## Boundary

Receipt must remain portable. It must not require access to internal database rows, event payloads, or policy-engine-specific objects to interpret the outcome.

## Security Considerations

- Receipt payloads SHOULD be safe to expose to callers and auditors within the intended trust boundary.
- Implementations MUST avoid placing secrets, credentials, raw signatures, or private operational state into `summary`, `details`, or `extensions`.
- Consumers SHOULD NOT infer provider-authenticated finality from a receipt unless a separate reconciliation standard explicitly says so.
- Correlation fields help auditability, but they do not replace proof verification or replay protection.

## Compatibility And Versioning

- v1 compatibility is defined by the receipt schema and the outcome semantics in this document.
- Changing outcome meaning, required fields, phase interpretation, or correlation semantics requires a new major version.
- Additional examples and explanatory text do not create a new version.
- Outcome Attestation v2alpha1 may wrap a v1 Receipt in a signed envelope, but it does not change the v1 receipt payload or semantics. See [`../outcome-attestation/SPEC.md`](../outcome-attestation/SPEC.md).
- Versioning policy for this repository is defined in [`../../VERSIONING_POLICY.md`](../../VERSIONING_POLICY.md).

## Examples

These examples are informative only. They illustrate active v1 receipt outcomes without changing the public contract.

- [`examples/executed.json`](examples/executed.json): successful local execution.
- [`examples/provider-executed.json`](examples/provider-executed.json): execution with a local reconciliation-facing record. This does not activate provider-authenticated reconciliation or finality as an active v1 standard.
- [`examples/approval-required.json`](examples/approval-required.json): decision-stage receipt for a path that requires external approval before proof can be minted.
- [`examples/refused-proof-expired.json`](examples/refused-proof-expired.json): execution-stage refused receipt correlated to an expired-proof refusal. This keeps the failure path tangible through the canonical Receipt surface as well as the Refusal surface.
