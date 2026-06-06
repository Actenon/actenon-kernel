# Changelog

## Unreleased

### Changed

- The Rust verifier SDK now pins `time` 0.3.47, resolving
  CVE-2026-25727 / GHSA-r6v5-fh4h-64xc, and declares Rust 1.88 as its minimum
  supported toolchain to match the patched dependency.
- Replay-store claim and consume failures now refuse before side effects by
  default. Durable relational stores use an atomic conditional claim, record
  consumption before handler execution, and track a monotonic mutation
  watermark for rollback detection. Unsafe fail-open behavior requires the
  explicit `replay_store_failure="fail_open"` warning path.
- `Refusal.reason_code` is now the canonical Python field and emitted JSON key,
  matching `GateOutcome.reason_code`. `Refusal.refusal_code`, the
  `refusal_code=` constructor keyword, and legacy refusal JSON remain accepted
  as deprecated compatibility aliases for one release.
- The README quickstart now runs the packaged `ActenonGate` API and is verified
  in CI.

### Added

- Versioned Conformance 1.0.0 metadata, hash-locked machine-readable vectors,
  deterministic release bundles, signed-tag/Sigstore release provenance, and
  an exact-version `Actenon Verified` self-certification policy.
- Security assurance policy covering annual and trigger-based reassessment,
  public security contact, and coordinated vulnerability disclosure.
- Open Receipt Counter-Signature v1 format plus offline, `kid`-aware
  verification in the Python, TypeScript, Go, and Rust verifier SDKs.
- Shared counter-signature conformance vectors covering historical keys,
  unknown keys, wrong keys, and altered Receipt digests.
- Production issuance and approval guidance, including per-action and
  risk-tiered autonomous-agent patterns.
- Domain-tuned Preflight packs for data privacy, access governance, and
  payments, plus a clearly marked clinical workflow template.
