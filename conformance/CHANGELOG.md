# Conformance Changelog

The conformance suite follows semantic versioning independently from package
releases. Existing vector meaning never changes silently.

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
