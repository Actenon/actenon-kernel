# Changelog

## Unreleased

### Changed

- `Refusal.reason_code` is now the canonical Python field and emitted JSON key,
  matching `GateOutcome.reason_code`. `Refusal.refusal_code`, the
  `refusal_code=` constructor keyword, and legacy refusal JSON remain accepted
  as deprecated compatibility aliases for one release.
- The README quickstart now runs the packaged `ActenonGate` API and is verified
  in CI.

### Added

- Production issuance and approval guidance, including per-action and
  risk-tiered autonomous-agent patterns.
- Domain-tuned Preflight packs for data privacy, access governance, and
  payments, plus a clearly marked clinical workflow template.
