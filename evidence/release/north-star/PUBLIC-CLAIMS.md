# Public claims and incompleteness audit (north-star)

Scope: actenon-protocol, actenon-kernel, actenon-permit, sdk-go, sdk-rust (candidate heads), blastradius
(BLASTRADIUS.md), and the organisation profile Actenon/.github.

Searched for TODO, FIXME, XXX, HACK, placeholder, stub, `NotImplementedError`, `unimplemented!`/`todo!`,
stale or rc version strings, cross-repository claims, skips, CI jobs that never run, publish workflows and
package data.

Classes: **FIXED** (a commit on the candidate branch), **JUSTIFIED** (true as written, or intentionally
incomplete and documented), **KNOWN-LIMITATION** (true and recorded in KNOWN-LIMITATIONS.md),
**OWNER_ACTION** (OWNER-ACTIONS.md), **POST-RELEASE** (true only once the release exists; prepared, not applied).

## Claims that were false and are fixed
| Repo | Claim / defect | Fix |
|---|---|---|
| protocol | README version badge and "Python reference: Stable v1.3.0 on PyPI" after the 1.4.0 bump (PR CI `Verify README claims` red) | 626afa2 |
| protocol | "v1.3.0 is purely additive": 1.4.0 adds verifier obligations (edge binding) | 626afa2: "wire format backward-compatible; adds normative verifier obligations" |
| protocol | README asserted other repos' availability (sdk-go v1.0.0; Rust "crates.io pending"), frozen into the PyPI description | 626afa2: states minimum SDK versions as requirements and points to each SDK's README |
| protocol | INTEGRATION_GUIDE.md presented as "the full adoption path": a stale v1.0.0 maintainer plan naming a private repo | 1d855c5 (labelled historical) |
| protocol | CONFORMANCE.md / README: kernel suite "51 vectors", "Conformance 1.0.0" | e988c4d (Conformance 1.1.0, 53 tests; README names the suite without a count) |
| kernel | The conformance suite grew 33 → 51 → 53 tests under the same "Conformance 1.0.0" label | b1b175d (Conformance 1.1.0; CHANGELOG lists exactly what 1.1.0 adds; lock bytes otherwise identical) |
| kernel | `parse_timestamp`: "RFC3339" in name and message, but the grammar was `datetime.fromisoformat`'s and differed between Python 3.10 and 3.11+ | 8c5c25e (RFC 3339 §5.6, identical on every interpreter) |
| kernel | invoice-payment policy refused with "requires a YYYY-MM-DD payment_date" but accepted `20260101` and week dates on 3.11+ | 8c5c25e (`parse_calendar_date`) |
| kernel | `PostgresReplayStore` "for multi-instance protected endpoints": workers starting together failed (139/160 constructors) | 38dd580 + 185e0fd |
| kernel | aws_kms.py comment: operation ID is "the AWS-generated request ID" (code read SigningAlgorithm) | b1b175d |
| kernel | `scripts/check_published_ts_verifier.mjs` header said it runs cases.json; it ran only the 29 edge vectors | 3be5d68 (runs all four manifests, 51 vectors; fails on an unexecuted manifest) |
| kernel | `conformance-release.yml` published for any signed tag, on any commit | 4a7c71a (release gate) |
| sdk-go | Accepted `,` fractional seconds (not RFC 3339; the reference refuses) | 8a87d6f |
| sdk-go / sdk-rust | CHANGELOG: vectors pinned to kernel fce8a5b (Conformance 1.0.0 lock) | 0198ef5 / c149ab6 (pin b1b175d, Conformance 1.1.0) |
| permit | `# TODO: remove these aliases in v2.0` in 2.0.0 (aliases kept, tested) | f8ebc70 |
| permit | docs/README.md compatibility table stopped at Permit 1.4.0 | 8e36c25 |
| permit | README "TypeScript SDK v1.4.0" ×2, TS example `v1.` token; CHANGELOG floor `>=1.3.0rc1` | release-prep patch v4 (applied in RELEASE-GRAPH step 5) |

## Claims checked and true (JUSTIFIED)
- Protocol: 20 pytest skips are 15 invalid canonicalisation vectors × 2 parametrisations. The 5 vectors
  skipped by both are executed in PR CI by `test_reference_passes_every_vector_exactly_once` (runner.py over
  all 129 vectors, 0 skipped), with a negative control (`AcceptsEverything` must fail them). "129 vectors": the
  runner reports Total 129.
- Kernel: 5 skips. Three are PostgreSQL tests, executed with no skips allowed by the `postgres-replay` job.
  Two are reconciliation "Phase 4B" tests: the README declares Reconciliation a reserved, inactive surface.
  "53 conformance vectors" is checked by `Verify README claims` against `conformance run`.
- Kernel `local_runtime` simulation PCCB: its signature can never verify (demo-only, fails closed).
- Permit `NotImplementedError` in `sdk/client.py` and `adapters/payments.py`: abstract base methods.
- Permit skip `tests/test_real_agent.py` ("z-ai CLI not on PATH"): optional external CLI.
- Kernel `suite.json` `canonicalization_profile: actenon-jcs-sha256-v1`: the protocol's deliberately rejected,
  documentation-only label (`tests/test_protocol_drift.py` asserts it is never accepted on the wire). Confusing,
  but documented.
- Fixture READMEs in sdk-go/sdk-rust (`actenon-kernel==1.2.1`): accurate provenance of how those fixtures were generated.

## Known limitations (true, recorded in KNOWN-LIMITATIONS.md)
Kernel wheel's top-level `conformance`/`examples`/`schemas` packages; protocol vectors distributed only through
the git tag; no ruff gate over the kernel's `actenon/` (19 pre-existing findings); protocol lint scope excludes
`conformance/runner.py` and `scripts/`; Permit ships `_iam_stub.py`; sdists not bit-reproducible.

## Owner action / post-release
- Organisation profile: stale versions, a broken `go get github.com/actenon/...` (lower-case owner), and a link
  plus product claims for the private actenon-cloud. POST-RELEASE (`POST-RELEASE-org-profile.patch`; OWNER-ACTIONS B1).
- Kernel repository description "51 conformance vectors": OWNER-ACTIONS B2.
- Permit's disabled workflows (CI jobs that never run): OWNER-ACTIONS A1. sdk-go's disabled scan: A2.
- Publish workflow not in the release graph: protocol `publish-ts-runtime.yml` (`@actenon/protocol`) has never
  run. The README now says that package is not on npm.

## Machine checks that keep these claims true
`Verify README claims` in protocol, kernel and Permit (versions, counts, badges, registry installs, ecosystem
table); `release_gate.py validate` (every required check name is produced by a job); `verify-published.yml`
(published artefacts against the current vectors); the skip gates; `tests/unit/test_versioning_doc_claims.py`;
`tests/unit/test_package_data_declared.py`; `ARTEFACT-METADATA-CHECK v2.1` for release artefacts.
