# Security Policy

## Scope

This repository contains an open execution kernel, not a hosted production service.

Security review is still important because the code covers:

- Action Intent and PCCB handling
- proof verification
- well-known key discovery fetch behavior
- escrow validation
- replay protection
- protected-endpoint behavior
- receipt and refusal generation
- local proof examples

Related documents:

- [THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [KERNEL_GUARANTEES.md](docs/KERNEL_GUARANTEES.md)
- [docs/SECURITY_ASSURANCE.md](docs/SECURITY_ASSURANCE.md)
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [spec/replay/SPEC.md](spec/replay/SPEC.md)

## What Usually Counts As A Kernel Security Issue

- execution without required proof verification
- incorrect proof binding checks such as audience, tenant, subject, action, target, or expiry mismatch acceptance
- replay or duplicate execution acceptance when the documented replay path is in use
- escrow failures such as accepting revoked, expired, or already-consumed execution state when the documented escrow path is in use
- well-known discovery fetch behavior that permits redirects or private/internal metadata destinations through the default resolver
- secret leakage or unsafe disclosure in public refusal or receipt artifacts
- public documentation or defaults that overstate guarantees the OSS kernel does not actually provide

## What Usually Does Not Count As A Kernel Security Issue

- missing hosted control-plane functionality
- provider-authenticated reconciliation features not published in the open specs
- policy disagreements that do not create a verification bypass
- security properties that depend on infrastructure the adopter did not deploy, such as durable replay storage, correct trust roots, or correct clock handling

When reporting an issue, distinguish clearly between:

- a flaw in the OSS kernel or published spec surface
- a deployment or integration mistake
- a future paid-layer or hosted-service concern

## Reporting A Security Concern

Do not open a public issue for a sensitive vulnerability.

Email `ross.buckley1990@gmail.com` with the subject prefix
`[ACTENON SECURITY]`. Repository security advisories may also be used when the
hosting platform presents the private reporting form.

The acknowledgement, triage, coordinated-disclosure targets, reassessment
cadence, and conformance-release assurance policy are defined in
[docs/SECURITY_ASSURANCE.md](docs/SECURITY_ASSURANCE.md).

## What To Include

- affected file or subsystem
- impact
- reproduction steps
- whether the issue affects local proof only or the kernel design more broadly
- whether the issue requires a compromised signer, adapter, or external control plane to be exploitable
- whether the issue depends on bypassing replay, escrow, or protected-endpoint checks that the spec requires

## Current Limits

This repository does not claim provider-backed production execution.

Receipts and refusals are structured public artifacts, but they are not cryptographically authenticated public attestations in the active v1 contract set.

Draft attestation groundwork for a future Receipt/Refusal v2 path is described in [RECEIPT_V2_DESIGN.md](RECEIPT_V2_DESIGN.md), but it is not an active default or a substitute for the current v1 security statement.

Findings related to hypothetical hosted control-plane features should be clearly marked as future-layer concerns, not current implemented behavior.
