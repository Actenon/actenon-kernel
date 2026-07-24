# Changelog

See [VERSIONING.md](VERSIONING.md) for the compatibility promise that governs
this changelog. Within 1.x, a proof that verifies under one version verifies
under any later version.

## [1.0.0] — 2026-07-24

### The promotion

The kernel is the enforcement layer of the Actenon ecosystem. Its version
number is the first thing a platform team reads when deciding whether it can
sit on a payment path. 0.1.0 said "pre-alpha, do not deploy" while the broker
that depends on it shipped at 1.4.0. This release closes that gap.

### What 1.0.0 means

See [VERSIONING.md](VERSIONING.md) for the full compatibility promise. The
core guarantee: within 1.x, no release will cause an artefact that previously
verified to stop verifying, except where doing so fixes a security defect.

### Added

- **[VERSIONING.md](VERSIONING.md)** — the compatibility promise. Defines what
  1.0 covers (public API, decision semantics, refusal taxonomy, conformance
  vectors, CLI), what it does not cover (private modules, alpha surfaces,
  wire formats, adapter internals), and the decision-semantics rule.
- **Executable invariants** (WO-9):
  - `tests/test_neutrality.py` — verification makes no network calls (both
    symmetric and asymmetric-with-inline-key paths tested)
  - `tests/test_independence.py` — AST-based check that the kernel imports no
    actenon-* package outside {actenon, actenon_protocol}
  - `tests/test_cloud_optional.py` — no cloud imports, no cloud URLs, no
    hosted-endpoint defaults
  - `scripts/assert_dep_direction.py` — verifies pyproject.toml runtime deps
  - `.github/workflows/invariants.yml` — CI gate with clean-install matrix
- **[docs/PRODUCTION_INTEGRATION.md](docs/PRODUCTION_INTEGRATION.md)** —
  self-contained, Apache-2.0 production guidance. Three key-custody tiers,
  rotation runbook, replay store operations (with tested fail-closed
  behavior), clock skew, observability, capacity benchmarks, upgrade/migration.
- **[docs/FAILURE_MODES.md](docs/FAILURE_MODES.md)** — every failure mode
  with detection, blast radius, and operator action.
- **`benchmarks/verify_benchmark.py`** — measured verification latency: p50
  0.25ms (HMAC), 0.35ms (Ed25519); throughput ~3,900/s and ~2,800/s per core.
- **`examples/production-reference/`** — docker-compose reference deployment
  with Postgres replay store, no actenon-cloud required.
- **`scripts/test_replay_store_unreachable.py`** — proves the gate fails
  closed when the replay store is unreachable.
- Badges for invariants, offline verification, and kernel independence in
  the README.

### Changed

- The quickstart no longer presents the pilot signer as the default path.
  The local HMAC signer is clearly labelled "development only" with a link
  to PRODUCTION_INTEGRATION.md for production custody tiers.
- Outcome Attestation is explicitly marked as v2alpha1 and excluded from
  the 1.0 compatibility promise (in README and VERSIONING.md).
- Production guidance that previously lived in actenon-cloud (source-available)
  is now in this repo under Apache-2.0.
- Development Status classifier: `3 - Alpha` → `5 - Production/Stable`.

### Findings (no blockers)

See [FINDINGS.md](FINDINGS.md) for the full findings log. Summary:
- Base install (no `cryptography`) runs 18/33 conformance tests; the 15
  skipped tests are asymmetric (Ed25519) and correctly gated behind the
  `[asymmetric]` extra. The README claim is true as written.
- Replay store unreachable → gate fails CLOSED (safe). No blocker.

## [0.1.0] — 2026-07-22

Initial public release.

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
