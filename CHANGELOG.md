# Changelog

See [VERSIONING.md](VERSIONING.md) for the compatibility promise that governs
this changelog. Within 1.x, a proof that verifies under one version verifies
under any later version.

## [1.3.0]

### Security — insecure development behaviour requires explicit development intent

Two defects, reproduced against the released 1.2.1 wheel
(`evidence/release/h1h2/`):

- **H1 — single-use proofs replayed across workers and restarts.** With no
  replay configuration, `ActenonGate`, `ProtectedExecutor`,
  `ProtectedEndpointMiddleware` and `BoundaryVerifier` kept replay state in a
  per-process temp directory (or an in-memory set). One single-use proof
  executed once per worker process and again after every restart.
- **H2 — unset or unconventional `ACTENON_ENV` silently enabled development
  signing.** The public development HMAC secret was refused only for a
  denylist of production names (`prod`, `production`, `staging`, ...). With
  `ACTENON_ENV` unset, empty, `prd`, `live`, `prod-eu`, `uat`, ... a verifier
  rooted in `build_local_proof_signer()` accepted proofs anyone can forge,
  and `actenon-permit`'s signer resolution fell back to that secret.

The boundary is now an allowlist (`actenon.security_posture`). Explicit
development intent is `ACTENON_ENV` in {`development`, `dev`, `local`,
`test`} or a development entry point (`ActenonGate.local_dev(...)`,
`actenon-mcp --demo`, `actenon-kernel up|doctor|simulate|conformance run|coverage run`).
A code-level entry point is refused when `ACTENON_ENV` declares any other
value. Without development intent the kernel refuses, at construction:

- the public development HMAC secret (`LOCAL_PROOF_SECRET`), with no override;
- per-process replay state: set `ACTENON_REPLAY_DB` to a durable path shared
  by every worker, or pass a `ReplayProtector`/`replay_store`; unsafe
  override `ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY=1`;
- `replay_protection="disabled"`; unsafe override
  `ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED=1`;
- `replay_store_failure="fail_open"`; unsafe override
  `ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN=1`.

An override is loud (`RuntimeWarning` plus a log record) and recorded in
`ActenonGate.security_downgrades` / `ProtectedExecutor.security_downgrades` /
`BoundaryVerifier.health()["security_downgrades"]`, which are empty in a
correctly configured deployment. `BoundaryVerifier` now honours
`ACTENON_REPLAY_DB`. `actenon-kernel verify-proof|attest-*` with the local
signer refuse without development intent.

**Migration (deployment-breaking for unconfigured deployments).** A service
that relied on the defaults now fails to start with a message naming the fix.
Production: configure asymmetric signing and `ACTENON_REPLAY_DB` (or an
explicit store). Local development: set `ACTENON_ENV=development` or use
`ActenonGate.local_dev(...)`. Under VERSIONING.md §1.4 this is a security
fix that changes behaviour within 1.x and requires a published security
advisory naming the affected versions (<= 1.2.1).

### Security — TypeScript verifier SDK (`@actenon/verifier-sdk`)

- `VerifierSDK.verifyJSON` verifies proof material exactly as received and
  parses it strictly. The object API cannot see what `JSON.parse` discarded:
  on the `kernel_diff_v1` corpus the TS verifier fed `JSON.parse` output
  accepted 8 proofs (plus 3 in the precision addendum) that the Python
  reference refuses (duplicate members, `2500.0` / `2.5e3` / `1e0` number
  forms, whitespace inside a signature). Through `verifyJSON`: 0.
- HMAC signature values must be canonical unpadded base64url.

### Security — the protected edge enforces its own declarations (protocol 13)

actenon-protocol `protocol/13-edge-binding.md` (normative from protocol
1.4.0) defines the rules. 1.2.1 accepted `scope_capabilities`,
`parameter_constraints` and `resource_selectors` as verifier context and then
ignored them. On the differential corpus, an edge declaring
`["payments.read"]` executed a valid `payments.refund` proof.
`PCCBVerifier` (and every SDK) now refuses with the following codes. The
shared vectors are `edge_binding_cases.json` and `edge_revocation_cases.json`.

- **E1** — the intent's capability is not in the edge's declared
  `scope_capabilities`, compared exactly with no pattern expansion; an empty
  declaration also refuses. Code `SCOPE_CAPABILITY_MISMATCH`.
- **E2** — an edge `parameter_constraints` member is missing from the signed
  `scope.parameter_constraints`, or differs canonically. Code
  `PARAMETER_MISMATCH`.
- **E3** — the signed target satisfies none of the edge's
  `resource_selectors`. Code `TARGET_MISMATCH`.
- **E4** — `scope.single_use` is not `true`. Code `SCOPE_MODE_INVALID`.
- **E5** — the proof carries a signed `extensions.authority` with
  `revocable: true` and the edge's `revocation_checker` says the authority is
  revoked, cannot be consulted, or is not configured. Code
  `AUTHORITY_REVOKED`. Every check passes before this one, and no replay
  claim or side effect happens until it does. `ActenonGate(...,
  revocation_checker=...)` and `mint_proof(..., authority=...)` support it.
- `ActenonGate` verifies against its own `capabilities`,
  `parameter_constraints` and `resource_selectors`, never against values
  derived from the request. **A gate without `capabilities` is refused at
  construction outside explicit development intent.** It would otherwise take
  the capability from the presented intent, so E1 would compare the request
  with itself. The unsafe override is
  `ACTENON_UNSAFE_ALLOW_UNDECLARED_CAPABILITIES=1`, recorded as
  `undeclared_capabilities` in `security_downgrades`. `actenon-mcp` gains
  `--capability NAME` (repeatable), which non-demo mode requires.
- Fixed: `PCCB.to_dict()` / `unsigned_payload()` aliased the minted proof's
  `extensions`, so mutating a serialised copy changed the proof.

Migration: an edge whose declarations already agree with the proofs it
receives sees no change. An edge whose declarations contradicted its proofs
was executing actions it said it does not perform; it now refuses them.
Issuers of revocable authority (actenon-permit >= 2.0.0) require edges to
configure a revocation source.

### Security — outbound HTTP clients accept only http(s) URLs

`HttpProofSealClient`, `HttpExecutionGraphClient` and the local runtime's
status probe passed configured URLs straight to `urlopen`, which also opens
`file://` and custom schemes (bandit B310). They now refuse every scheme
except http and https at construction. `docs/CRYPTO_REVIEW.md` had assessed
this as validated; the addendum there corrects it.

### TypeScript verifier SDK 0.2.0 (`@actenon/verifier-sdk`, first npm release)

- Breaking: `verify` and `verifyPayloads` (parsed objects) are no longer
  public. `verifyJSON` (raw bytes, strict parse) is the only entry point.
- `Ed25519Verifier(jwks)` verifies EdDSA proofs, the algorithm
  actenon-permit mints in production. It refuses private JWKs, duplicate or
  missing `kid`s, non-canonical `S`, and signatures that are not 64 bytes.
- Edge binding E1–E5, with `revocationChecker` in `VerifierSDKOptions`.

### Fixed — `actenon-kernel scan` from an installed wheel

The scanner's capability registry (`actenon/scanner_capability_registry.v1.json`)
was never declared as package data. `actenon-kernel scan` and
`actenon-kernel doctor --deep` failed with `FileNotFoundError` from every
installed wheel, released 1.2.1 included, while passing from a checkout. It is
now shipped. `tests/unit/test_package_data_declared.py` fails for any
undeclared data file under `actenon/`, and the clean-install job runs `scan`
from the wheel.

### Conformance suite 1.1.0

The kernel conformance suite is versioned on its own (`conformance/CHANGELOG.md`).
1.3.0 ships Conformance **1.1.0**: the edge-binding and revocation vectors
(protocol 13) and the fractional-timestamp vectors, all additive. They had been
added under the 1.0.0 label, so the same "Actenon Verified (Conformance 1.0.0)"
claim would have meant different suites. `actenon-kernel conformance run` now
reports 1.1.0, and the signed tag `conformance-v1.1.0` publishes it.

### Fixed — timestamps parse identically on every supported Python

`parse_timestamp` delegated to `datetime.fromisoformat`, whose grammar changed
in Python 3.11. The same signed proof could verify on one interpreter and be
refused on another: on 3.10 a fraction other than 3 or 6 digits was refused
(`SCHEMA_INVALID`), and on 3.11+ week dates, basic format, `+0000`, `+00` and
`,` fractions were accepted. On every interpreter the separator could be any
character, and missing seconds, empty fractions and out-of-range offset
minutes were accepted. Timestamps are now RFC 3339 section 5.6 `date-time`
(the schemas' `"date-time"` format), with the separator `T`, `t` or a space,
upper-case `Z`, and fractions of any length truncated to microseconds.
`invoice_payment` dates are RFC 3339 `full-date`. Found by the north-star
fresh-consumer rehearsal (kernel 1.3.0 on Python 3.10); measured against every
SDK with the frozen `corpus-addendum-timestamp-grammar`. Every
`kernel_diff_v1` reference outcome is unchanged on 3.10 and 3.11+.

### CI

- The suite runs the configured testpaths (`actenon/` and `tests/`, which
  includes the shared verifier-vector runner) and `examples/`, with the
  LangChain and FastAPI extras installed. Any skip not on the allowlist
  (`scripts/assert_no_unexpected_skips.py`) fails the run.
- Workflows run bash with `pipefail`. `pytest ... | tee` and
  `pytest ... | tail` previously passed when pytest failed, as did the base
  and clean-install conformance jobs.
- Clean-install conformance runs against the installed wheel, from outside
  the checkout. It previously imported `./actenon`.
- bandit scans all of `actenon/` and gates on medium severity and above.
  It previously ran `|| true`. The pip-audit SARIF step no longer swallows
  failures.
- The packed TypeScript tarball is installed into an empty project and
  imported in plain Node.

### Fixed (from the programme branch, PR #37)

- `BoundaryVerifier` verified nothing: 1.2.1 returns `valid=True` for any
  16+ character token (reproduced: `"AAAAAAAAAAAAAAAA"` -> VALID). It now
  requires a trust root and verifies the proof.
- `ActenonGate` could not be constructed with `ACTENON_ENV=production`
  (it hard-coded `LOCAL_DEBUG` disclosure). Further fixes: idempotent retries
  verify the proof first; artifact store paths are confined; the MCP server
  checks a supplied intent against the tool arguments; CLI verify commands
  stop reporting unchecked artifacts as verified. See PR #37.

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
