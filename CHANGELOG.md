# Changelog

See [VERSIONING.md](VERSIONING.md) for the compatibility promise that governs
this changelog. Within 1.x, a proof that verifies under one version verifies
under any later version.

## [Unreleased]

### Security

- **`BoundaryVerifier` no longer accepts an unverified token.** A string of 16 or more characters used to be reported valid. Verification now requires a configured `PCCBVerifier` and a signed PCCB for the exact Action Intent. Forged tokens are refused (`PROOF_INVALID`, or `ISSUER_UNTRUSTED` when no trust root is configured). This is a security-defect exception under [VERSIONING.md](VERSIONING.md) §1.4: inputs that previously produced a successful boundary result now refuse.
- **Edge allow-list.** `PCCBVerifier` refuses when the intent's capability is not in `context.scope_capabilities` (`SCOPE_CAPABILITY_MISMATCH`). Callers that already pass the intent's own capability are unchanged. `ActenonGate(..., capabilities=...)` sets that allow-list to the capabilities the edge declares, which is how Airlock passes the signed grant.

### Added

- **`ActenonGate` `capabilities` and `revocation_checker`.** These are the arguments Airlock passes in `src/actenon_airlock/broker.py` (`ActenonGate` then `protect(intent, proof, side_effect)`). A revocation checker that returns false or raises is `AUTHORITY_REVOKED`, and the side effect does not run.

## [1.2.1] — 2026-07-25

### Fixed

- **MCP Registry namespace case.** The registry grants `io.github.<Owner>/*`
  matching the GitHub owner verbatim, so `io.github.actenon/kernel` was
  rejected with a 403 in favour of `io.github.Actenon/kernel`. Because the
  ownership marker lives in the README that PyPI freezes into the package
  description, correcting it needs a new release. `verify-claims.yml` now
  derives the expected namespace from `GITHUB_REPOSITORY` and fails before
  a release rather than after one.
- **Sigstore release signing.** `sigstore sign --output-certificate` requires
  `--output-signature` alongside it; the job now emits only the bundle, which
  already contains both. This job runs solely on release tags, so it had been
  reported as "skipping" on every PR and had never actually executed.

## [1.2.0] — 2026-07-25

### A connectable MCP server

The MCP adapter has worked for a while, but there was no way to *use* it in
sixty seconds: no runnable binary, no registry listing, no config block to
paste. This release packages what already existed.

### Added

- **`actenon-mcp` console script** (`actenon.mcp_server`) — a stdio MCP
  server exposing three tools: `actenon_verify` (pure verification, no side
  effects, no replay state consumed), `actenon_gate` (ALLOW or a typed
  refusal, emits a hash-chained Receipt or Refusal), and `actenon_receipt`
  (fetch a prior decision with its position and hashes in the chain). Every
  response carries the machine `reason_code` *and* the human-readable
  reason, so a model can see why it was refused.
- **`--demo` mode** — offline with an ephemeral per-process key and
  in-memory state: no configuration read, no network call, no key on disk.
  Every tool description is prefixed `DEMO MODE — ephemeral key, not for
  production.`, and demo mode is itself refused in a production-like
  environment. It additionally exposes `actenon_demo_grant`, which stands in
  for the human approval step a real deployment performs in
  `actenon-permit`; that tool is **absent** from a non-demo server, because
  a verifier that issues its own authority is not a verifier.
- **`server.json`** and `.github/workflows/publish-mcp-registry.yml` — the
  listing in the official MCP Registry, published from CI via GitHub OIDC.
  The registry's PyPI ownership marker (`mcp-name:` in this README) and the
  version agreement between `server.json`, `pyproject.toml`, and the git tag
  are machine-checked by `verify-claims.yml`.

### Fail-closed behaviour

Without `--demo`, the server requires signing material and refuses to start
without it (WO-8): missing `--key-file`, a nonexistent path, and an empty
key file each exit non-zero with a message naming the demo alternative. Key
material is read from a path and never logged.

## [1.1.0] — 2026-07-24

### The base install now verifies Ed25519

`cryptography` moved from the `[asymmetric]` extra into the base runtime
dependencies. The reference broker (`actenon-permit`) mints Ed25519 proofs in
production, so `pip install actenon-kernel` previously produced a verifier
that could not verify the artifacts this ecosystem actually produces — 15 of
33 conformance tests skipped on a base install. All 33 now execute and pass
with no extras. See FINDINGS.md ("RESOLVED: base-install conformance") for
why the original "no action" conclusion was reversed.

Under the compatibility promise this is additive: no API change, and nothing
that previously verified stops verifying.

### Changed

- `cryptography>=42` is a base runtime dependency.
- The `[asymmetric]` extra is **retained** for backward compatibility —
  consumers declare `actenon-kernel[asymmetric]` (the reference broker does)
  and removing the extra would break those specs. It now restates the base
  dependency and installs nothing additional.
- CI: the base-install conformance job now asserts `cryptography` is present
  and hard-fails on any skipped conformance test (previously it asserted the
  opposite and merely reported the skip count).

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
