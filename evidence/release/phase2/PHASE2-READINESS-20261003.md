# Actenon production readiness — phase 2 (2026-10-02/03)

Continues `../ECOSYSTEM-BASELINE-20261002.md` (phase 1, kernel `472f390`). Nothing there is rewritten. No
release, merge, tag or publish was performed. AIRLOCK-001 was not started. All raw results are in this directory.
Superseded runs are kept, under names that say why.

## 0. Exact candidate commits (all pushed to `ross/keen-fermi-e2y72j`)

| Repo | Commit | Version on branch | Notes |
|---|---|---|---|
| actenon-protocol | `45b7753` | 1.3.0 (release as **1.4.0**) | `protocol/13-edge-binding.md` (normative E1–E5); wire `PROTOCOL_VERSION` unchanged (1.1.0) |
| actenon-kernel | `6d6c630` (code); artefacts built from `e775389` | 1.3.0rc1 | the `6d6c630` wheel is content-identical to the tested `e775389` wheel (`unzip` + `diff -r`: no difference); the commits in between change only tests, scripts, docs, workflows and evidence |
| @actenon/verifier-sdk (kernel `sdk/typescript`) | same | 0.2.0 | never published |
| actenon-permit | `a5467ab` | 2.0.0rc1 / `@actenon/sdk` 2.0.0-rc.1 | `[tool.uv.sources]` pins kernel `e775389` (pre-release only) |
| sdk-go | `e3649cd` | module pseudo-version `v1.0.1-0.20261003002543-e3649cdd0bc1` (tag as **v1.1.0**) | |
| sdk-rust | `0a16a84` | 0.2.0 | never published on crates.io |

## 1. What phase 2 changed (by programme step)

1. **Edge contract (S1).** Decision record `actenon-protocol/protocol/13-edge-binding.md`. The vectors
   (`edge_binding_cases.json`, 21 cases; `edge_revocation_cases.json`, 8 cases) were written and seen failing in
   every SDK first (`tests/*-BEFORE-impl.txt`), then implemented in Python, TS, Go and Rust. The vectors are
   hash-locked, and sdk-go and sdk-rust vendor them.
2. **Permit 2.0.0 candidate (S2).**
   - Current main plus PR #11 (ACTENON-JCS-STRICT-1, v2 grant tokens, ledger `chain_version`).
   - No unconfigured or public-secret signing outside development intent.
   - Kernel floor `>=1.3.0rc1`.
   - Exact-capability proofs (fixes E0).
   - TS SDK: v2 tokens, v1 verification, a strict canonicaliser, and fatal UTF-8 decoding.
   - Cross-language token vectors: Python, Bun and plain Node.
   - Two CHANGELOG claims were false and are corrected, with counterexamples in `permit/`. The documented v1→v2
     re-mint path produced tokens that were refused for non-ASCII grants. Decimal normalisation did not apply to
     grant signatures.
3. **Revocation at the edge (S3).**
   - Proofs carry a signed `extensions.authority`.
   - The kernel `revocation_checker` (`ActenonGate`/`PCCBVerifier`), Go `WithRevocationChecker`, Rust
     `with_revocation_checker` and TS `revocationChecker` all fail closed: revoked, unknown, unreachable, or no
     source.
   - Permit `StoreRevocationChecker` walks the parent chain.
4. **TS parity (S4).** `verifyJSON` (raw bytes, strict parse) is the only entry point. `Ed25519Verifier` verifies
   Permit-minted EdDSA proofs, shown in E2E E1 and E8 and in the corpus (U = 0).
5. **CI (S5).** Every repo's workflows are actionlint-clean.
   - kernel:
     - all testpaths plus `examples/` run, with a skip gate;
     - pipefail everywhere; this fixed two conformance jobs that passed with failing tests;
     - clean-install conformance now really runs against the wheel;
     - bandit gates all of `actenon/` (with one real fix, see §3);
     - pip-audit SARIF no longer swallows failures;
     - the packed TS tarball is imported in Node;
     - new jobs: `postgres-replay` and `verify-published`.
   - permit: `uv sync --locked`; a skip gate; a real nightly kernel-main job; Node smoke before npm publish.
   - protocol: version and pass-mark discipline is documented.
6. **Artefacts (S6).** `build_artefacts.sh` exports exact commits (`git archive`) and builds them in fresh
   environments. Final set: `artefacts-final/` (`SHA256SUMS`, `SOURCE_COMMITS`, `REPRODUCIBILITY.md`).
7. **Corpus (S7).** §4.
8. **H1/H2/E2E (S8).** §5.

## 2. G1–G6

| Gate | Status | Evidence | What remains (exact) |
|---|---|---|---|
| **G1 Released fixes/advisories** | **BLOCKED** | Every fix is in a candidate built from an exact commit (`artefacts-final/`). `verify-published/*-PUBLISHED-registry.txt`: every published artefact fails this checkout's vectors today (kernel 1.2.1: 14 vector-test failures and a broken `scan`; `@actenon/verifier-sdk` unpublished; sdk-go `@latest` = v1.0.0; Rust not on crates.io). | Owner: execute §6 and publish the kernel and Permit GHSAs. Drafts were handed over privately and not committed (they describe unreleased vulnerabilities). Not done here by instruction |
| **G2 Required CI** | **BLOCKED** | Workflows are fixed and actionlint-clean. Every job's commands were reproduced locally (`../tests/`, `clean-install-final/`, `postgres/`). **No workflow has run on GitHub for these branches:** CI triggers on `main` and PRs to `main`, and no PR was opened (0 runs, checked via API). Permit: `ci.yml`, `protocol-drift`, `version-coherence`, `link-check` and `actenon-scan` are `disabled_inactivity` (live API), while the PyPI/npm publish workflows are **active**. Branch protection could not be read (403 in phase 1) and is not enforced | Owner/admin: (a) re-enable the Permit workflows; (b) open PRs from `ross/keen-fermi-e2y72j` in all five repos and get them green on GitHub; (c) require the CI jobs on `main` in each repo (job ids — kernel: `test` ×3 Python versions, `postgres-replay`, `typescript-verifier`, `go-verifier`, `rust-verifier`, `invariant-tests`, `clean-install`, `base-install-conformance`, `bandit`, `pip-audit`, `verify-claims`, `version-coherence`; Permit: `test-python`, `kernel-conformance`, `test-ts`, `verify-claims`, `version-coherence`; sdk-go: `test`, `kernel-vectors`; sdk-rust: `lint`, `test`, `kernel-vectors`; protocol: `conformance`, `lint`, `typescript`, `typescript-runtime`, `verify-claims`, `version-coherence`); (d) merge with merge commits, not squash (see §7.3) |
| **G3 Secure defaults** | **PASS** (candidates) | H1 FINAL (`h1h2/h1-FINAL-*`): unconfigured workers refuse to start for unset, `prd` and `production`, with 0 executions; a shared store gives 1. H2 FINAL: no non-development `ACTENON_ENV` can use the public secret (kernel and Permit). E2E FINAL E9/E9b/E9c/E10a–e: no replay store, no declared capabilities, no or invalid signing key — each refused, nothing minted. PostgreSQL 16: fail closed at start and mid-operation | Applies to candidates only; released 1.2.1 and 1.4.0 remain insecure until G1 |
| **G4 Machine-checked public claims** | **BLOCKED** | Now machine-checked: published artefacts against the current vectors (`verify-published.yml`; positive control passes on all four candidates, `verify-published/*-CANDIDATE-*`); VERSIONING version (it said 1.0.0 for four releases, now tested); PostgreSQL production claim (real-server CI job, no skip allowed); npm imports (packed-tarball Node jobs); `scan` from the wheel; skip gates. The checks fail on today's registries, so the public claims (e.g. README "SDKs: Py · TS · Go · Rust") are **false until G1** | Execute §6; `verify-published` must then pass for all four. The README badge and SDK guide need no wording change once that holds |
| **G5 Cross-language parity** | **PASS** (candidates) | §4: A = 0 and U = 0 for TS 0.2.0, Go `e3649cd` and the Rust 0.2.0 crate on both frozen corpora; stricter refusals (B) listed per case. E2E: the Python and TS edges agree on every case (E0–E8e) | Published SDKs are not at parity (old ones accept 4–5 proofs the reference refuses: `differential/COMPARE-phase1-and-released-results-vs-78efcf1-reference.txt`) until G1 |
| **G6 AIRLOCK eligibility** | **BLOCKED** | Its own defects from phase 1 are fixed and verified on built artefacts (E0 glob scope PASS; E8b revoked after minting → `AUTHORITY_REVOKED` at both edges; also E8c ancestor, E8d no source, E8e unknown store). AIRLOCK-001 not started (instruction) | G1, G2 and G4 (owner actions), then AIRLOCK-001 |

## 3. Defects found and fixed in phase 2 (beyond the brief)

| Defect | Where found | Fix |
|---|---|---|
| `actenon-kernel scan` / `doctor --deep` fail from **every installed wheel**, released 1.2.1 included (`FileNotFoundError`: registry not packaged) | running the kernel suite against its own wheel (`clean-install-78efcf1/`) | `6c5bf02`: package data, a test (failing first) for any undeclared data file, and a CI smoke test from the wheel |
| `HttpProofSealClient` / `HttpExecutionGraphClient` / status probe accept `file://` and custom schemes; `CRYPTO_REVIEW.md` had called this "validated" | making bandit gate | `ff29b71`: http(s) only (test first); a dated addendum, with the original text kept |
| `ActenonGate` without `capabilities` made E1 compare the request with itself | reviewing my own changelog text | `bfc059c`: refused outside development intent; named override; recorded downgrade; `actenon-mcp --capability` |
| CI conformance jobs passed with failing tests (`pytest \| tee`, `\| tail` without pipefail); clean-install "conformance" imported `./actenon`, not the wheel; `pytest tests/` skipped `actenon/conformance` | CI audit | `78efcf1` |
| Permit `uv.lock` stale (kernel 1.2.1 against a `>=1.3.0rc1` requirement), and CI did not use `--locked` | TS e2e failure | `e73a2eb`, `30c1d4f` |
| Permit skip gate (mine) would have failed on GitHub: two tests need the private actenon-cloud checkout | running the Permit suite against wheels in a clean tree | `a5467ab` |
| Two langchain tests expected `INTENT_MISMATCH` where the verifier reports `TARGET_MISMATCH` (both refusals), red on main | full testpaths run | `78efcf1`, with the exact code asserted (one check narrowed) |
| MCP quickstart said `ACTENON_ENV=demo` allows `--demo` (it is refused; `development` is allowed) | reproduction | `bfc059c` |
| Go: numeric edge constraints decoded as `float64` refuse valid proofs (fail closed) | corpus, B = 46 | kept strict and documented and tested (`e3649cd`); with `UseNumber`, B = 5 |
| READMEs did not say that Permit 2.0 proofs need a revocation source, or that the TS SDK does not enforce single use | review | sdk-go `e3649cd`, sdk-rust `0a16a84`, kernel `e775389` |

## 4. Differential corpus (frozen; hashes re-verified before every run)

- `kernel_diff_v1`: 179 cases, `1c2bc970…31264d`.
- Precision addendum: 14 cases, `3954555d…a3e`.
- Reference: the kernel `e775389` wheel; byte-identical results to the `78efcf1` wheel.
- Runners: phase-1 runners unchanged, plus two new runners:
  - `runner_ts_strict_eddsa.mjs` — identical except that EdDSA uses `Ed25519Verifier`;
  - `runner_go_usenumber/` — identical except that context is decoded with `UseNumber`.
- SDK sources:
  - TS: the packed tarball;
  - Go: the module zip, byte-identical to the artefact;
  - Rust: the unpacked `.crate` artefact.

| Implementation (raw entry point) | kernel_diff_v1 A / B / U | addendum A / B / U |
|---|---|---|
| TS `@actenon/verifier-sdk` 0.2.0 `verifyJSON` | **0** / 9 / 0 | **0** / 0 / 0 |
| Go `e3649cd` (phase-1 runner: context decoded to `float64`) | **0** / 46 / 0 | **0** / 0 / 0 |
| Go `e3649cd` (`UseNumber` context) | **0** / 5 / 0 | **0** / 0 / 0 |
| Rust 0.2.0 crate `0a16a84` | **0** / 6 / 0 | **0** / 0 / 0 |

**Stricter SDK refusals (B), not hidden:**
- All three SDKs refuse non-canonical base64url signatures (padded, standard alphabet, non-zero trailing bits),
  where the Python reference accepts them.
- TS and Go refuse a UTF-8 BOM prefix and a space-separated timestamp.
- TS refuses the 2^53 boundary integers (JS numbers).
- Rust refuses `num_2p64_plus1` and `canon_neg_zero_literal_text`.
- Go with the `float64` runner adds 41 `PARAMETER_MISMATCH` refusals (§3).
- Per-case lists: `differential/COMPARE-FINAL-*.txt`.

**Intended reference changes against phase 1:** exactly 5 cases, all ACCEPT → REFUSE (E1–E4):
`empty_scope_capabilities_ctx`, `action_ctx_scope_capability_missing`, `action_ctx_constraint_mismatch`,
`target_ctx_selector_mismatch`, `single_use_false_resigned` (`differential/REFERENCE-CHANGES-vs-phase1.txt`).

**Negative control:** released kernel 1.2.1, and the phase-1 Go, Rust and TS candidates, each accept 4–5 of these
against the new reference.

## 5. H1, H2 and E2E on the final built artefacts

- **E2E** (`e2e/e2e-FINAL-artefacts-final.txt`): **25/25 PASS**.
  - Setup: the Permit 2.0.0rc1 wheel issues Ed25519 proofs. Edges: the kernel 1.3.0rc1 wheel (`ActenonGate`, in
    separate processes sharing one durable replay DB) and the TS 0.2.0 tarball (`verifyJSON` + `Ed25519Verifier`).
    Revocation is read from Permit's SQLite store (Python: `StoreRevocationChecker`; TS: `node:sqlite`).
  - Single use:
    - E2: a second worker and a restarted worker are both refused `DUPLICATE_REPLAY`; 1 side effect.
    - E3: 16 + 4 concurrent presentations give 1 side effect.
  - Proof binding:
    - E0: a glob-scoped grant works at both edges.
    - E1: happy path with a Receipt; the TS edge verifies the Permit EdDSA proof.
    - E4: wrong audience.
    - E5: parameter mutation gives `ACTION_MISMATCH` at both edges.
  - Edge declarations:
    - E5b: another declared capability gives `SCOPE_CAPABILITY_MISMATCH`.
    - E5c: an unsigned edge constraint gives `PARAMETER_MISMATCH`.
    - E5d: a non-matching selector gives `TARGET_MISMATCH`; a matching one executes.
  - Forgery and expiry:
    - E6: a forged key.
    - E6b: the public HMAC secret.
    - E7: expiry gives `PROOF_EXPIRED` at both edges.
  - Revocation:
    - E8a: Permit refuses to mint after revocation.
    - E8b: a proof minted, then its grant revoked, gives `AUTHORITY_REVOKED` at both edges.
    - E8c: the same when the parent grant is revoked.
    - E8d: no revocation source refuses.
    - E8e: an unknown store refuses.
  - Missing configuration:
    - E9 and E9b: no replay DB (also with `ACTENON_ENV` empty); the edge does not start.
    - E9c: no declared capabilities; the edge does not start.
    - E10a–e: missing, invalid or partial signing configuration; no proof is minted.
  - RUN1 and RUN2 (harness defects) and RUN3 (`78efcf1`) are kept.
- **H1** (`h1h2/h1-FINAL-*`):
  - Scenario A: the issuer is configured, so a valid proof exists, and every unconfigured worker refuses to start.
    0 executions for `<unset>`, `prd` and `production`.
  - Scenario B: a shared DB gives exactly 1 execution across two workers and a restart.
  - The phase-1 harness is kept unmodified (its undeclared-capability gates are now refused).
- **H2** (`h1h2/h2-FINAL-*`): unchanged from phase 1 for the kernel; Permit `resolve_signer` now raises
  `Ed25519KeyError`. Development values (`dev`, `development`, `local`, `test`) and code-level development entry
  points (`ActenonGate.local_dev`, `actenon-mcp --demo`, with `ACTENON_ENV` unset) still allow the public secret, by
  design.
- **PostgreSQL 16** (`postgres/pg-FINAL-*`):
  - 4 processes × 8 threads give 1 execution;
  - a restart is refused `DUPLICATE_REPLAY`;
  - unreachable at start: refuses to start;
  - stopped after start: `REPLAY_STORE_UNAVAILABLE`.
- **Clean install** (`clean-install-final/`):
  - The kernel suite on its wheel passes, except 8 test cases that read the deleted source tree (classified).
    Conformance 53/53, examples 27/27.
  - The Permit suite on its wheels: 556 passed.
  - npm tarballs in plain Node: 7/7 tokens verified, 6/6 tampered refused, 4/4 v2 re-encoded byte-identically.
- **Source suites at the final commits:**
  - kernel: 907 passed; 4 allowed skips (2 Phase-4B, 2 PostgreSQL without a DSN).
  - kernel TS: 82/82, typecheck clean.
  - Permit: 558 passed; TS 56/56.
  - Go: 605 passed (race).
  - Rust: all targets pass; clippy and fmt clean.
  - protocol: 278 passed.

## 6. Exact release graph (for the owner; nothing here was executed)

1. **actenon-protocol 1.4.0** from `45b7753` after merge.
   - In one commit, set `pyproject.toml` to `1.4.0` and update the pass mark (README, CONFORMANCE.md, RUNNER_SPEC.md,
     generate_vectors.py); `test_compatibility_mark_is_consistent_everywhere` enforces this.
   - Republish `@actenon/protocol-types`: the published 1.3.0 does not import in Node; main's npm-pack smoke covers it.
   - May run in parallel with step 2; nothing depends on its code.
2. **actenon-kernel 1.3.0 + GHSA (kernel draft)** from `6d6c630` after merge.
   - Set the version to `1.3.0`; `test_versioning_doc_claims.py` forces VERSIONING.md to follow.
   - Set `SOURCE_DATE_EPOCH` in `publish.yml` (see `artefacts-final/REPRODUCIBILITY.md`).
   - Update `server.json` and the MCP registry.
   - Publish **`@actenon/verifier-sdk` 0.2.0** to npm (first release).
3. **sdk-go v1.1.0** (tag at `e3649cd`, or its merge) and **sdk-rust 0.2.0** to crates.io (first release).
   - Move each `fixtures/KERNEL_PIN` from `fce8a5b` to the kernel 1.3.0 tag commit first; the vendored vectors are
     unchanged since `fce8a5b`. Then re-pin `sdk/standalone-sdk-pins.json` in the kernel.
4. **actenon-permit 2.0.0 + `@actenon/sdk` 2.0.0 + GHSA (Permit draft)** from `a5467ab` after merge.
   - Remove `[tool.uv.sources]` and relock against PyPI kernel 1.3.0 (`uv lock`, then CI `--locked`).
   - Set versions `2.0.0` / `2.0.0`.
   - Re-enable the Permit workflows first (G2).
5. **blastradius 0.5.0**: independent (phase 1 §3); not touched in phase 2.
6. **Confirm:** dispatch `verify-published.yml` in the kernel; all four jobs must pass (G4). Then AIRLOCK-001.

## 7. Remaining blockers and residual risks (exact)

### 7.1 Owner/admin actions (blocking)

1. Open PRs and get CI green **on GitHub**. Nothing in this phase has run there.
2. Re-enable Permit's disabled workflows. Note that its publish workflows are active while its CI is disabled.
3. Branch protection with the required checks in §2 G2.
4. Execute §6, including both GHSAs.
5. Start AIRLOCK-001.

### 7.2 Technical, known and documented (not blocking G1–G5)

- The TS, Go and Rust SDKs verify but do not enforce single use. The integrator must claim the nonce in a shared
  store; READMEs say so. Only the Python kernel executor enforces it.
- `ActenonGate.local_dev(...)` and `actenon-mcp --demo` with `ACTENON_ENV` unset are development entry points and
  accept public-secret proofs (H2 V3/V5). They are refused under any non-development `ACTENON_ENV`.
- Edge declarations are only as exact as the language's numbers:
  - Go refuses `float64` declarations;
  - TS cannot tell `2500` from `2500.0` in an edge's own config;
  - the shared vectors cover only string constraints; numeric constraints are covered by the corpus.
- Grant tokens in `v1.` format remain accepted until Permit 3.0.0.
- Two Phase-4B reconciliation tests are skipped: the feature is not implemented.
- shellcheck was not available, so workflow shell bodies were not linted beyond actionlint.
- The kernel sdist is not bit-reproducible, and the wheel only is with `SOURCE_DATE_EPOCH`.
- 8 kernel tests read source paths, so they cannot run against an installed wheel.

### 7.3 Merge note

sdk-go and sdk-rust CI fetch the kernel vector lock at `KERNEL_PIN=fce8a5b`. Squash-merging the kernel PR would leave
that commit reachable only through the PR ref. Merge with a merge commit, or move the pins (step 3) before relying
on them.
