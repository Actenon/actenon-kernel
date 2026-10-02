# Conformance Changelog

The conformance suite follows semantic versioning independently from package
releases. Existing vector meaning never changes silently.

## Unreleased

Additive vectors only; no existing vector changed meaning or bytes.

- `verifier_sdk_v1/timestamp_cases.json` with two newly minted proofs
  (`fractional_500000_*`, `fractional_123456_*`): the `ACTENON-JCS-STRICT-1`
  action-hash label and fractional-second timestamps, including non-canonical
  raw forms (`.500`, `+00:00`) and one-microsecond window boundaries. The
  previous vectors only used whole seconds and the legacy `RFC8785-JCS` label,
  so SDKs that truncated or dropped fractions, or rejected the current label,
  passed the suite while refusing real proofs.

## 1.0.0 - 2026-06-06

Initial versioned release of the active public conformance surface.

Included vector families:

- exact-action PCCB binding and verifier behavior
- Cloud-to-Kernel Receipt, Refusal, and outcome-attestation fixtures
- Receipt Counter-Signature v1, including historical `kid` verification
- Transparency Log v1 inclusion, consistency, checkpoint, monitor, and orphan checks
- Issuer Status v1 fail-closed verification
- Approval Artifact v1 exact-action verification

The mandatory cross-SDK target is Python, TypeScript, Go, and Rust for the
shared verifier, counter-signature, transparency-log, issuer-status, and
approval-artifact vector families.
