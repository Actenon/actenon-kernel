# Conformance Changelog

The conformance suite follows semantic versioning independently from package
releases. Existing vector meaning never changes silently.

## 1.1.0

Released with actenon-kernel 1.3.0. Additive vectors only: no vector file of
1.0.0 changed bytes (`git diff v1.2.1 -- actenon/conformance/vectors
conformance/vectors` adds 12 files and modifies none). MINOR, as
actenon-protocol 1.4.0 is for the same contract: an implementation that
passed 1.0.0 but ignores the protected edge's declarations does NOT pass
1.1.0. Claim the mark with its version.

- `verifier_sdk_v1/edge_binding_cases.json` (21 cases) and
  `verifier_sdk_v1/edge_revocation_cases.json` (8 cases), with the PCCB
  fixtures `edge_non_revocable_pccb.json`, `edge_revocable_pccb.json`,
  `edge_revocable_malformed_pccb.json` and `edge_single_use_false_pccb.json`:
  actenon-protocol `protocol/13-edge-binding.md` rules E1-E5 (declared
  capability, parameter constraints, resource selectors, single use, and
  revocation of revocable authority, failing closed when the revocation
  source is unknown or unreachable).
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
