# Actenon ecosystem baseline and release-readiness evidence — 2026-10-02

Session `session_01J4ve8AjfVRSir8igyHDnMm`. Live state captured 2026-10-02T18:06Z (`raw-20261002T1806Z/`). Work ended 2026-10-02T19:0xZ.
Scope: actenon-protocol, actenon-kernel, actenon-permit, sdk-go, sdk-rust, blastradius, `.github`. actenon-scan was excluded and not touched.
The organisation's private repository (actenon-cloud) was inspected, but because this evidence lives in a public repository its details are withheld here; relevant facts were reported to the owner directly. Nothing was released, tagged, merged or published. AIRLOCK-001 was not started.

Evidence layout (everything under `evidence/release/`):

| path | content |
|---|---|
| `raw-20261002T1806Z/github/*.json` | raw GitHub API: repo, `branches/main`, protection (403 for this token), rules, rulesets, workflows, last 100 runs, open/closed PRs, tags, releases, branches, security advisories |
| `raw-20261002T1806Z/registry/` | PyPI / npm / crates.io / Go proxy / MCP Registry responses |
| `raw-20261002T1806Z/git/*.ls-remote.txt` | every ref of every repo at capture time |
| `h1h2/` | H1 and H2 reproduction harnesses and raw output (released 1.2.1, candidate) |
| `tests/` | regression tests before/after the implementation; suite baselines |
| `differential/` | the frozen corpus, generator, runners (Python/TS/Go/Rust), raw per-implementation results, comparisons |
| `e2e/` | Permit → Kernel → edge → Receipt harness and raw output (candidate, released) |
| `quickstart/` | documented commands run from the installed wheel (candidate, released) |
| `ci-local/` | kernel CI jobs reproduced locally on the candidate |
| `minversions/` | candidate kernel vs protocol 1.1.0 / 1.2.0 / 1.3.0; protocol TS package Node import |
| `permit-pr11/` | Permit 2.0.0-vs-1.5.0 determination with raw probe output |
| `artefacts/` | the candidate artefacts that were built and tested, with `SHA256SUMS` |

Rule used throughout: a failed result is never rewritten. Where a harness was corrected after a run, the superseded output is kept
under a `*-SUPERSEDED*` or `*-BEFORE*` name and the reason is stated.

---

## 1. Per-repository state (live, 18:06Z)

| | actenon-protocol | actenon-kernel | actenon-permit | sdk-go | sdk-rust | blastradius | .github |
|---|---|---|---|---|---|---|---|
| main HEAD | `b45ef37` | `43e17ad` | `c1eea9c` | `bbd1c0d` | `261ffbf` | `df10b55` | `f8317f6` |
| version on main | py 1.3.0; `@actenon/protocol-types` 1.3.0; `@actenon/protocol` 1.0.0 | py 1.2.1; `@actenon/verifier-sdk` 0.1.0; `server.json` 1.2.1 | pyproject 1.4.0; `actenon_permit.__version__` **"1.1.0"** (mismatch); `@actenon/sdk` 1.4.0 | none declared (module) | Cargo 0.1.0 | 0.4.0 | n/a (profile docs) |
| latest public tag | v1.3.0 (`e4f42f6`), ts-types-v1.3.0 | v1.2.1 (`238b3ab`) | v1.4.0 (`6e10af5`), ts-sdk-v1.4.0 | v1.0.0 (`89a23b4`) | v0.1.0 (`8b3d024`) | v0.4.0 (`08396af`) | none |
| GitHub Releases | none | v1.0.0-integration (pre), v0.1.0-public-kernel | v1.0.0-integration (pre) | none | none | none | — |
| open PRs | #18 programme branch `c30ac00` (22 commits) | #40 `43fc7cc` (vendored SDK removal, contains #37); #39 `4fc292e` (G3 failing tests, contains #37); #38 dependabot cryptography 50; #37 programme `3c6ca76`; #36 external fork | #11 `ef20ad7` (JCS-STRICT-1 / v2 tokens / 2.0.0, 11 behind main); #7 `97b675a` (stale) | none | none | #1 `f7161d8` (codex/auditable-milestone) | (not visible to API: repo cannot be attached; read via git) |
| unmerged branches relevant here | `claude/actenon-kernel-mcp-setup-qolk0h` = PR #18 | `wip/north-star-20261002/secure-defaults` (=#39), `ross/great-ptolemy-we9wbx` (=#40), `evidence/north-star-20261002` (orphan, 09:39Z evidence), `ross/keen-fermi-e2y72j` (this programme's candidate, §4) | `claude/actenon-kernel-mcp-setup-qolk0h` `08d60fe` (28 files unmerged after #21 squash), `fix/canonicalisation-unification` (=#11) | `claude/actenon-kernel-mcp-setup-qolk0h` `37700d0` (20 ahead, **no PR**; pinned by kernel #40) | `claude/…` `7fda4b4` tree == main | `claude/…` `d7f60a6` (9 bypass fixes, **no PR**, no CI run) | `fix/metadata-truth` (PR #1 ref) |
| unpushed/local work in this workspace | none | none at end (candidate commits pushed, §4) | none | none | none | none | none |
| workflows (state) | 8 active | 12 + 2 dynamic, all active | **CI, Link check, Protocol drift, Version coherence, actenon-scan: `disabled_inactivity`**; Publish ×2, Verify claims active | CI active; actenon-scan `disabled_inactivity` | CI, Publish active | CI, Publish active | none |
| latest relevant CI | main: Verify claims ✔, Version coherence ✔, actenon-scan ✔, **Link check ✘** (README links private actenon-cloud → 404); CI on `b45ef37` ✔ (07-26); PR #18 all ✔ | main: Verify claims ✔, Version coherence ✔, Bandit ✔ (cannot fail, §6), Protocol drift ✔, **Link check ✘** (same 404); CI on `43e17ad` ✔ (07-26); #40 CI ✔, Link ✘; #39 CI ✘ (intended failing tests) | last CI run 09-25 on `7c9c9cd` (**not** main HEAD); none on `c1eea9c` | **CI ✘ on every commit incl. tag v1.0.0** (`89a23b4`, `0402df3`, `bbd1c0d`): tests read kernel vectors from outside the repo | CI ✔ `261ffbf`; **Publish to crates.io ✘** (07-25, both runs) | CI ✔ `df10b55`; Publish ✔ v0.2.0–v0.4.0 | — |
| branch protection / required checks | `protected: true`, **required_status_checks enforcement_level `off`, contexts []** | not protected | not protected | not protected | not protected | not protected | not visible |
| rulesets | none | none | none | none | none | none | — |
| CI actually enforcing merges? | **no** | **no** | **no** | **no** | **no** | **no** | — |
| package destination | PyPI `actenon-protocol`; npm `@actenon/protocol-types`, `@actenon/protocol` | PyPI `actenon-kernel`; MCP Registry `io.github.Actenon/kernel`; npm `@actenon/verifier-sdk` (intended) | PyPI `actenon-permit`; npm `@actenon/sdk` | Go module proxy | crates.io `actenon-verifier-sdk` (intended) | PyPI `actenon-blastradius` | — |
| currently published | PyPI 1.3.0; npm protocol-types 1.3.0 (**fails to import in Node**, `minversions/`); `@actenon/protocol` **not published** | PyPI 1.2.1; MCP Registry 1.2.1 and 1.2.2 (`isLatest`, metadata-only, installs 1.2.1); `@actenon/verifier-sdk` **not published** | PyPI 1.4.0; npm `@actenon/sdk` 1.4.0 (**fails to import in Node ESM**) | v1.0.0 = `89a23b4` (main `bbd1c0d` is 2 commits later, untagged) | **nothing on crates.io** | 0.4.0 (note: unrelated `blastradius` 0.1.23 exists on PyPI) | — |
| relation to protocol / kernel | wire contract source; no Actenon deps | `actenon-protocol>=1.1.0,<2` | `actenon-kernel[asymmetric]>=1.0.0` (no ceiling), `actenon-protocol>=1.1.0,<2` | no runtime dep; vendored kernel vectors pinned to kernel `3c6ca76` (`fixtures/KERNEL_PIN`) on `37700d0` | same; `KERNEL_PIN` `3c6ca76` | none (`dependencies = []`) | — |

GitHub security advisories: the advisories API returns an **empty list for every in-scope repo**.

A private consumer (actenon-cloud) exists; its state is withheld from this public file (see the session report).

### 1.1 Reconciliation with the previous report (orphan branch `evidence/north-star-20261002`, captured 09:28–09:55Z)

| previous report | live at 18:06Z / re-measured here |
|---|---|
| kernel open PRs #37, #38, #36 | also **#39** and **#40**, opened by the owner at 10:25Z and 10:27Z from the 09:46Z/09:47Z branches |
| kernel PR #37 head `3c6ca76`: CI ✘, Link ✘ (Rust clippy) | #40 (`43fc7cc`, contains #37, drops vendored Go/Rust) CI ✔; Link ✘ persists (cause: README link to the private repo, not clippy) |
| "TS accepts / reference refuses: 23 → 0" (unverified, from an unpushed session) | **not reproduced**. Independently measured on a new frozen corpus: TS A = 8 (+3 in the addendum) before the fix; 0 through the new `verifyJSON` (§5) |
| kernel suite "813 passed" (unverified) | CI-equivalent on candidate: 798 passed, 3 skipped; full local env: 849 passed, 2 skipped, 1 deselected (§6) |
| Permit PR #11 = 2.0.0, not 1.5.0 | **reproduced independently**, same conclusion (§3) |
| protocol "protected but enforcement off" | unchanged |
| `@actenon/sdk@1.4.0` Node ESM import fails; non-ASCII v1 grant rejected in TS | **reproduced** (`permit-pr11/results-ts.txt`) |
| prior-session local commits `b97f38f`, `22a5e81`, `440302f`, `960da9a` absent from GitHub | still absent (`git cat-file`); no `backup/*` ref exists in any repo (`raw/git/*.ls-remote.txt`) |
| previous baseline cites `../02-g3/`, `../03-differential/`, `../04-ci/` | **those directories do not exist** on the orphan branch; the previous work stopped after §0/§1/§5. Nothing from them is cited here |
| previous report did not test released packages for H1/H2 | done here (§4) |
| previous report did not record `.github` | recorded above (read via git; the session cannot attach a repo whose name begins with `.`) |

---

## 2. Dependency graph and minimum versions

Edges are runtime dependencies as declared on main. "verified min" means a minimum established by executing tests here; "declared"
means it is only what the packaging metadata says.

```
actenon-protocol (py)  ◄── actenon-kernel (py) ◄── actenon-permit (py) ◄── (private consumer, withheld)
   │  declared >=1.1.0,<2      │ declared [asymmetric]>=1.0.0
   │  verified min 1.1.0       │ REQUIRED min for security: kernel 1.3.0 (candidate)
   │                           │
@actenon/protocol-types ◄── @actenon/protocol (runtime, unpublished)
                               │ (test coupling, not runtime)
   kernel conformance vectors ─┼─► sdk-go (fixtures/KERNEL_PIN 3c6ca76)  ◄─ kernel CI pins sdk-go 37700d0
                               └─► sdk-rust (KERNEL_PIN 3c6ca76)         ◄─ kernel CI pins sdk-rust 261ffbf
   kernel TS SDK (@actenon/verifier-sdk): no runtime deps; coupled to the same vectors
   @actenon/sdk (Permit TS): no runtime deps; coupled to Permit's token wire format (v1, and v2 in PR #11)
   blastradius: no Actenon dependency
```

| consumer (candidate) | dependency | minimum required | evidence |
|---|---|---|---|
| kernel 1.3.0rc1 | actenon-protocol | **1.1.0** | `minversions/kernel-candidate-vs-protocol-versions.txt`: conformance 51/51, 0 skipped, and the differential reference results byte-identical on 1.1.0, 1.2.0, 1.3.0 |
| kernel 1.3.0rc1 | cryptography | >=42 (declared); tested 50.0.2 | not bisected |
| permit (next) | actenon-kernel | **1.3.0** (security floor) | released kernel ≤1.2.1 has the BoundaryVerifier any-token defect, H1 and H2 (§4). With `>=1.0.0` the resolver may select a vulnerable kernel |
| permit 2.0.0 (PR #11) | actenon-protocol | ≥1.3.0 tested (PR #11 probe ran on 1.3.0) | whether protocol PR #18's canonicaliser fixes are required by v2 tokens was **not tested** |
| `@actenon/sdk` 2.0.0 | Permit token format v2 | must ship with Permit 2.0.0 | PR #11 changes no TS file; released TS 1.4.0 rejects all v2 tokens |
| sdk-go candidate | kernel vectors | kernel ≥ `3c6ca76` vectors (unchanged through candidate `2a7850c`) | `ci-local/kernel-ci-standalone-sdks-candidate.txt` (5 vendored files byte-identical) |
| sdk-rust candidate | kernel vectors | same | same |

## 3. Candidate releases and release order

Version labels are **proposals**. The owner decides. Nothing was published.

| repo | current released | candidate | reason for bump | classification | dependencies | downstream consumers | migration | security advisory |
|---|---|---|---|---|---|---|---|---|
| actenon-kernel | 1.2.1 (PyPI) | **1.3.0** (built as `1.3.0rc1` from `2a7850c`; owner may choose 2.0.0) | H1 + H2 fixes (§4); PR #37 fixes incl. BoundaryVerifier accepting any 16+ char token (reproduced on 1.2.1: `h1h2/boundary-verifier-any-token-probe.txt`); ActenonGate unusable under `ACTENON_ENV=production` (reproduced); TS `verifyJSON` | **security; behaviour-breaking for unconfigured deployments** (they now refuse to start). Kernel `VERSIONING.md` §1.4 permits this inside 1.x **only** with a published advisory naming affected versions. 2.0.0 is the conservative alternative | protocol ≥1.1.0 | permit, private consumer, SDK vector pins | set `ACTENON_REPLAY_DB` or pass a shared store; asymmetric signing; `ACTENON_ENV=development` (or `local_dev`) for demos; `ACTENON_ENV=demo` is **no longer** development intent; `verify-proof`/`verify-receipt` on demo artifacts need `ACTENON_ENV=development` | **required**: GHSA for kernel ≤1.2.1. Covers BoundaryVerifier (critical: any token VALID), H1 (single-use replay across workers/restarts), H2 (public HMAC secret under unset/unrecognised `ACTENON_ENV`) |
| `@actenon/verifier-sdk` (kernel TS) | never published | 0.2.0 | `verifyJSON` (new), strict base64url | additive + fail-closed tightening (0.x minor) | none | TS edges | use `verifyJSON` for untrusted bodies | none required (unreleased); note in kernel GHSA |
| sdk-go | v1.0.0 (proxy) | **v1.1.0** (`37700d0`, needs PR + merge + tag) | v1.0.0 refuses every proof with the current `ACTENON-JCS-STRICT-1` label (B = 49 of 179, §5); fractional timestamps; Ed25519 verifier added | fix (fail-closed → accepts valid proofs) + additive API → MINOR | kernel vectors `3c6ca76` | Go edges; kernel CI pin | none for callers; the published v1.0.0 cannot verify current proofs | not required (no A-type defect found); release note must state v1.0.0's incompatibility |
| sdk-rust | v0.1.0 tag; **crates.io: none** | **0.2.0** (main `261ffbf`) | same label incompatibility in v0.1.0 (B = 49); Ed25519; first crates.io publication (both publish runs failed 07-25) | MINOR (0.x) | kernel vectors `3c6ca76` | Rust edges | git dependents move to crates.io | not required |
| actenon-protocol | 1.3.0 | **1.4.0** (PR #18 `c30ac00`; version still 1.3.0 on branch) | `@actenon/protocol-types` 1.3.0 does not load in Node (reproduced); canonicaliser fixes (surrogates, int subclasses, key order by bytes, duplicate keys spelled with different escapes); +4 refusal codes catalogued | additive + fixes → MINOR | none | kernel (not required by kernel candidate), permit 2.0.0 (possibly), TS consumers | none | to decide: canonicaliser divergence fixes may be security-relevant; not assessed here |
| actenon-permit | 1.4.0 | **2.0.0** | PR #11 (v2 tokens, ACTENON-JCS-STRICT-1, `canonical_json` raises on floats) **is MAJOR** (§3.1); plus main's unreleased PR #21 security squash (e.g. "Boundary Kit accepted any token", "attenuation could widen scope", "revocation did not reach grandchildren", "budget bypass", "configured Ed25519 key silently downgraded to HMAC") | **breaking + security** | kernel ≥1.3.0; protocol ≥1.3.0 | `@actenon/sdk`, private consumer | v1 tokens still accepted; re-mint before 3.0.0; `canonical_json` callers stop passing floats | **required** for permit ≤1.4.0 (fixes on main since 09-26 are unreleased) |
| `@actenon/sdk` (Permit TS) | 1.4.0 | **2.0.0** | must read v2 tokens (PR #11 does not touch TS); Node ESM import is broken in 1.4.0; non-ASCII v1 grants rejected | breaking (wire) | Permit 2.0.0 | TS clients | upgrade with Permit 2.0.0 | mention in Permit advisory |
| blastradius | 0.4.0 | **0.5.0** (`d7f60a6`, needs PR + CI) | shell-semantics bypass fixes ("142 cases" regression suite) | security (bypass) → 0.x minor | none | users of the command guard | none | recommended (bypass class); not assessed in depth here |

### 3.1 Permit PR #11: 2.0.0, not 1.5.0 (independently reproduced)
Full write-up: `permit-pr11/PERMIT-VERSION-DETERMINATION.md`. Raw output: `results-python.txt`, `results-ts.txt`.
- Released Permit 1.4.0 rejects every v2 token PR #11 mints (`TokenError: unsupported token version`).
- `@actenon/sdk@1.4.0` (bun) rejects them too, and cannot be imported under Node ESM at all.
- Public `canonical_json({"a": 1.5})` changes from returning to raising.
- `SPEC.md` §9 forbids changing the canonical-JSON rule within the format version.

Three independent breaks make this **MAJOR**. PR #11 as written is also **not releasable**: it leaves Permit's own TS SDK unable to read
its tokens, it is 11 commits behind main, and Permit CI is disabled.

### 3.2 Release order (derived from §2, not from the previous plan)
1. **actenon-protocol 1.4.0.** It has no Actenon dependencies. The kernel does not need it (verified min 1.1.0), so it may go in parallel with step 2. It must precede Permit 2.0.0 only if Permit raises its protocol floor.
2. **actenon-kernel 1.3.0** (+ GHSA), with `@actenon/verifier-sdk` 0.2.0 if TS is to be offered. This is the security floor for everything downstream.
3. **sdk-go v1.1.0 and sdk-rust 0.2.0.** Both vendor kernel vectors pinned at `3c6ca76` (unchanged in the kernel candidate), and kernel CI pins them back. They need the kernel's vector set to be on a released kernel first; tagging an SDK whose `KERNEL_PIN` is an unreleased kernel commit would publish a test coupling to code users cannot install.
4. **actenon-permit 2.0.0 + `@actenon/sdk` 2.0.0 together** (+ GHSA), with `actenon-kernel>=1.3.0` and the TS v2 reader.
5. **blastradius 0.5.0.** Independent; any time.

Reversing 2 and 4 would publish a Permit whose kernel floor still admits the vulnerable kernel. Publishing Permit 2.0.0 without its TS SDK
splits Permit's own two-language contract.

---

## 4. H1 and H2: reproduction and secure defaults

### 4.1 H1 — single-use proofs replay across workers / restarts: **CONFIRMED**
Harness: `h1h2/run_h1.sh`, `h1_issuer.py`, `h1_worker.py`, `ed25519_harness.py`. Clean venv with the **released** PyPI wheels.
Ed25519 signing. Each worker is a separate OS process. Nothing is configured, the way the README shows the gate.

| build | ACTENON_ENV | side effects for ONE single-use proof (worker A ×2, worker B, A restarted) | control: shared `ACTENON_REPLAY_DB` |
|---|---|---|---|
| kernel 1.2.1 (PyPI) | unset | **3** | 1 |
| kernel 1.2.1 | `prd`, `production` | 0: `ActenonGate` cannot be constructed at all (hard-coded `LOCAL_DEBUG` disclosure) | 0 (same) |
| kernel `43fc7cc` (PR #37/#40, unreleased) | unset, empty, `prd`, `production`, `live` | **3** (`tests/g3-cross-process-tests-BEFORE-impl-43fc7cc.txt`) | — |
| **candidate `2a7850c` wheel** | unset, `prd`, `production` | 0: edge **refuses to start** (`InsecureDefaultRefusedError` naming `ACTENON_REPLAY_DB`) | **1** (`h1h2/h1-FINAL-candidate-2a7850c.txt`) |

Root cause: `default_replay_db_path()` uses a per-process `mkdtemp` deleted at exit. `BoundaryVerifier` used an in-memory set.

### 4.2 H2 — unset/unconventional `ACTENON_ENV` silently enables development signing: **CONFIRMED**
Harness: `h1h2/run_h2.sh`. An attacker forges a refund proof using only the public constant `LOCAL_PROOF_SECRET` shipped in the
wheel. Released kernel 1.2.1 + Permit 1.4.0 (`h2-released-kernel-1.2.1-permit-1.4.0.md`):

- For `ACTENON_ENV` unset, `''`, `prd`, `live`, `prod-eu`, `production-eu`, `Prod_EU`, `uat`, `preprod`, `qa`, `sandbox`, `perf`:
  - the public-secret signer constructs, and a verifier rooted in it **ACCEPTS the forged proof**;
  - **Permit's `resolve_signer()` silently returns the public-secret HMAC signer**;
  - `actenon-mcp --demo` starts.
- Only the denylist `prod, production, staging, release, ci` refused.
- E2E confirms it (`e2e/e2e-released-kernel-1.2.1-permit-1.4.0.txt` E10a/E10b): unconfigured Permit 1.4.0 mints HS256 proofs under
  empty and `prd` environments.
- The repo's own `examples/production-reference` sets `ACTENON_ENV="production-reference"`, signs with the public secret,
  exposes an unauthenticated `/mint-proof`, and sets `ACTENON_REPLAY_DB_URL`, which the kernel never reads.

### 4.3 Design implemented (kernel candidate)
Principle: **insecure development behaviour requires explicit development intent** (`actenon/security_posture.py`).

**Development intent** is either:
- `ACTENON_ENV` ∈ {`development`, `dev`, `local`, `test`}, case- and whitespace-insensitive (an **allowlist**); or
- a scoped code-level entry point: `ActenonGate.local_dev(...)`, `actenon-mcp --demo`, `actenon-kernel up|doctor|simulate|conformance run|coverage run`, `python -m actenon.demo.*`.

A code-level entry point is refused when `ACTENON_ENV` declares any other value. `ACTENON_PRODUCTION`, `ACTENON_CI_RELEASE` and
`ACTENON_RELEASE_BUILD` always win. The old production-name denylist is kept only as a secondary guard.

**Refused without intent**, at construction time:

| behaviour | unsafe override | notes |
|---|---|---|
| the public secret | none | — |
| per-process replay state | `ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY` | refused in gate, executor, middleware, `BoundaryVerifier`, MCP non-demo, `build_default_replay_store`; `BoundaryVerifier` now honours `ACTENON_REPLAY_DB` |
| `replay_protection="disabled"` | `ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED` | — |
| `replay_store_failure="fail_open"` | `ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN` | — |

Each override warns (`RuntimeWarning` plus a log record) and appears in `security_downgrades` (gate, executor,
`BoundaryVerifier.health()`). It is empty in a correctly configured deployment.

**Regression tests, written to fail before the implementation:**
- `tests/security/test_g3_explicit_development_intent.py`, from PR #39: **48 of 70 failed** at `43fc7cc`. I corrected one test that
  presented a freshly stamped second action (a test defect; the assertion is unchanged).
- `tests/security/test_g3_cross_process_single_use.py`, new; real interpreter processes: **17 of 18 failed** at `43fc7cc`, with the
  proof executed 3 times.
- TS: `sdk/typescript/tests/strict-input.test.ts`, **5 of 5 failed** before `verifyJSON`.

All pass on the candidate. Final H2 matrix on the candidate wheel: `h1h2/h2-FINAL-candidate-2a7850c-permit-1.4.0.md`. Every
non-development value refuses the public secret, including unset, `''`, `prd`, `live`, `uat` and `demo`.

**Demo usability preserved** (from the wheel, `ACTENON_ENV` unset):
- conformance, `simulate`, `python -m actenon.demo.local_proof`, `actenon-mcp --demo` and `make demo` succeed;
- all 31 example scripts behave as on base except three. Those three now declare `ACTENON_ENV=development` explicitly
  (`quickstart/`, `ci-local/`).

**Residual, by design:** `ActenonGate.local_dev()` with `ACTENON_ENV` unset is honoured as explicit intent. It trusts the public
secret, and the H2 matrix shows it executing a forged refund. The downgrade is visible in `security_downgrades`. Code that calls
`local_dev()` in production is still unsafe.

---

## 5. Differential testing

**Corpus `kernel_diff_v1`**: 179 cases, raw bytes (intent, PCCB, context), **frozen**.
- Generator `differential/gen_corpus.py`; read-only on disk.
- `CORPUS-HASH.txt` = **`1c2bc970d3c2b93b8d63e4fd3740d7802ae49ebc972ddad8b1de772d5c31264d`** (539 files; listing in `CORPUS-FILES.sha256`).
- Categories: duplicate members, canonicalisation, unicode, timestamps, case, whitespace, empty strings, missing fields,
  additional fields, array ordering, numeric boundaries, deep nesting, document size, escrow, single_use, signature malleability
  (incl. Ed25519 S+L), audience, target, tenant, subject, action, action hash, expiry, not-before, unsupported modes, malformed input.

**Addendum `kernel_diff_v1_addendum_precision`**: 14 cases, hash `3954555d…ea3e`. It was **designed after** seeing the v1 TS results,
is targeted, and is hashed separately. The v1 hash was re-verified as unchanged after the addendum was written.

**Oracle**: the Python kernel reference, installed from the candidate wheel. It parses raw bytes with the kernel's strict loader and
verifies with `LOCAL_DEBUG` codes. Its results are identical on the `490a0e1` and final `2a7850c` wheels, and identical to released
1.2.1 (179/179).

**Independence caveat**: the corpus was minted by the same reference that judges it. Author `hint`s that disagree with the oracle are
listed in `REFERENCE-HINT-DISAGREEMENTS.txt` (20), and four are reference findings (below).

Runners use **installed** packages only:
- TS: npm-packed tarball;
- Go: modules via the Go proxy, `VerifyJSON`;
- Rust: git revisions, `parse_*_json`;
- Python: wheel, asserting `site-packages`.

Raw rows are in `results*/`. A = implementation ACCEPT / reference REFUSE (dangerous). B = implementation REFUSE / reference
ACCEPT (fail-closed). C = both refuse with different codes. U = unsupported.

| implementation (artefact) | v1: A | v1: B | v1: U | addendum: A | addendum: B |
|---|---|---|---|---|---|
| Python kernel 1.2.1 (PyPI) | 0 | 0 | 0 | 0 | 0 |
| TS `@actenon/verifier-sdk` 0.1.0 **pre-fix**, `verify(JSON.parse(..))` | **8** | 7 | 5 (no EdDSA) | **3** | 0 |
| TS **final** `verify(JSON.parse(..))` (object API) | **7** | 10 | 5 | **3** | 0 |
| TS **final** `verifyJSON(raw)` | **0** | 9 | 5 | **0** | 0 |
| Go v1.0.0 (published) | 0 | **49** | 5 | 0 | 0 |
| Go `bbd1c0d` (main) | 0 | 49 | 5 | 0 | 0 |
| Go `37700d0` (candidate) | **0** | 6 | 0 | 0 | 0 |
| Rust v0.1.0 (`8b3d024`) | 0 | 49 | 5 | 0 | 0 |
| Rust `261ffbf` (candidate) | **0** | 7 | 0 | 0 | 0 |

**Dangerous disagreements**:
- **Pre-fix TS** (all through `JSON.parse`): 5 duplicate-member cases, `2500.0`, `2.5e3`, and a signature containing whitespace;
  the addendum adds `1.0`, `1e0` and `10e-1` presented for a signed `1`.
- **Hypothesis falsified**: "doubles let 2^53+1 pass for a signed 2^53" is false. TS refuses unsafe integers, and Go/Rust preserve lexemes.

**Fail-closed disagreements, reported rather than hidden**:
- **Go v1.0.0 / Rust v0.1.0**: 49 each. Most are `ACTION_HASH_ALGORITHM_INVALID` on the current `ACTENON-JCS-STRICT-1` label, i.e.
  the published Go SDK and the only tagged Rust SDK **cannot verify proofs the current kernel mints**.
- **Candidate SDKs**, B = 6–9: BOM accepted by the reference; space-separated timestamp; empty context `scope_capabilities`;
  padded / standard-alphabet / non-canonical-trailing-bit base64; integers above 2^53 (TS); 2^64+1 (Rust); `-0` literal (Rust).
- **Permit TS `@actenon/sdk` 1.4.0** has no PCCB verifier, so it is not a corpus target. On grant tokens it rejects a valid
  non-ASCII v1 grant (B) and every v2 token. Its Node import fails.

**Reference findings** (oracle behaviour, not changed here; need a protocol decision):
1. `PCCBVerifier` **never consults the context's `scope_capabilities`, `parameter_constraints` or `resource_selectors`**. An edge
   that declares "this endpoint performs `payments.read`" still accepts a valid `payments.refund` proof for a `payments.refund`
   intent. Binding is proof↔intent plus audience only.
2. A validly re-signed `scope.single_use=false` proof is accepted. The executor enforces replay regardless, so this is not a replay hole.
3. Signature encodings are lenient: padding, standard alphabet and non-canonical trailing bits are accepted. The replay key does not
   include the signature, so this is malleability, not forgery.
4. Integers above 2^53 and 2^64 are accepted. Other runtimes cannot represent them exactly; they fail closed.

---

## 6. CI truthfulness and enforcement

**Enforcement: none.**
- No repository requires any status check to merge to main. Protocol has a protection object with zero required checks.
- `branches/main/protection` returns 403 to this token, so its full settings could not be read.
- A workflow existing, or being green, does not gate anything.

| finding | where | effect |
|---|---|---|
| `bandit … \|\| true` (twice) | kernel `bandit.yml` | "Bandit ✔" can never fail |
| `pip-audit … \|\| true` + `continue-on-error: true` | kernel `supply-chain.yml` | vulnerability audit can never fail |
| `npm run typecheck --if-present`, but the script is `check` | kernel `ci.yml` (TS job) | typecheck step ran nothing. **Fixed in candidate** (`npm run check`). Null result: the real typecheck passes (`ci-local/kernel-ts-sdk-candidate.txt`) |
| CI runs `pytest tests/` only | kernel `ci.yml` | `examples/` tests never run (1 fails on base and candidate: langchain finance agent); langchain adapter tests skipped (not installed). With langchain installed, 1 fails on base and candidate (`TARGET_MISMATCH` vs expected `INTENT_MISMATCH`; both are refusals) |
| CI installs editable (`pip install -e`) | kernel, verify-claims | CI evidence is from editable installs, not built wheels (only `invariants.yml` does a clean install) |
| CI triggers only on PR / push to main | kernel and others | candidate branches without a PR get no CI. This programme's branch was verified **locally** (`ci-local/`) |
| CI disabled (`disabled_inactivity`) | permit CI, link check, protocol drift, version coherence, actenon-scan | Permit main `c1eea9c` (PR #21 squash of the security fixes) and PR #11 were **never CI-gated** |
| CI red on every commit incl. the published tag | sdk-go | v1.0.0 shipped with failing tests (vectors read from outside the repo) |
| tests only under Bun | permit `ts-sdk`, protocol TS | `@actenon/sdk@1.4.0` and `@actenon/protocol-types@1.3.0` fail to import in Node; CI green |
| Link check red on main | protocol, kernel | README links a private repository (404 to the public); red for weeks, not gating |
| `uv.lock` stale on kernel main | kernel | lock records `actenon-kernel` 0.1.0 and lacks the `cryptography` base dependency; not fixed here |

Kernel CI jobs reproduced locally on the candidate (`ci-local/`):
- Python job (3.11, CI's exact install): 798 passed, 3 skipped; `make demo` ✔; conformance 33 ✔.
- TS: `check` ✔, 48 tests ✔.
- Go `37700d0` and Rust `261ffbf`: fixtures byte-identical, tests ✔, clippy ✔.

---

## 7. Candidate artefacts and clean-install end-to-end

Artefacts, built from `git archive 2a7850c` (`artefacts/SHA256SUMS`):

| artefact | sha256 |
|---|---|
| `actenon_kernel-1.3.0rc1-py3-none-any.whl` | `2220de6b…8716d` |
| `actenon_kernel-1.3.0rc1.tar.gz` | `5dc5d27f…f4ec` |
| `actenon-verifier-sdk-0.1.0.tgz` (TS, npm pack) | `51e4260a…a1c` |
| Go module zip `v1.0.1-0.20261001220709-37700d01d6cb` (from the Go proxy) | `d96a5ca1…ba8` |
| Rust `actenon-verifier-sdk-0.1.0.crate` (`cargo package` at `261ffbf`, verified build) | `aea64f77…db9b` |

Permit was tested as the released PyPI 1.4.0; no Permit candidate was built (§3).

**E2E**: `e2e/run_e2e.sh`, separate processes for authority and edge. Permit 1.4.0 decides and mints Ed25519 proofs; the kernel
`ActenonGate` is the edge, with two workers plus a restart sharing `ACTENON_REPLAY_DB`; `ACTENON_ENV=production`. Every check
asserts the specific refusal code.

| check | candidate `2a7850c` + Permit 1.4.0 | released 1.2.1 + Permit 1.4.0 |
|---|---|---|
| E0 Permit grant with glob scope `payments.*` → edge | **FAIL** (`SCOPE_CAPABILITY_MISMATCH`: Permit puts the glob into `scope.capabilities`) | FAIL |
| E1 happy path → executed once → Receipt written | PASS | FAIL (gate cannot start) |
| E2 replay: worker B and restarted A | PASS (`DUPLICATE_REPLAY`, 1 side effect) | FAIL (gate cannot start) |
| E3 duplicated execution, 16+4 concurrent | PASS (1 side effect) | FAIL (gate cannot start) |
| E4 wrong audience | PASS (`AUDIENCE_MISMATCH`) | FAIL (gate cannot start) |
| E5 altered parameters | PASS (`ACTION_MISMATCH`) | FAIL (gate cannot start) |
| E6 forged proof: attacker Ed25519 key, same kid | PASS (`PROOF_INVALID`) | FAIL (gate cannot start) |
| E6b forged with the public HMAC secret | PASS (`PROOF_INVALID`) | FAIL (gate cannot start) |
| E7 expired proof | PASS (`PROOF_EXPIRED`) | FAIL (gate cannot start) |
| E8a revoked grant → Permit refuses to mint | PASS | PASS |
| E8b proof minted before revocation, presented after | **FAIL** (executes; `ActenonGate` has no revocation hook, Permit publishes no revocation feed) | FAIL (confounded: gate cannot start) |
| E9 missing replay configuration (`production`) | PASS (refuses to start) | PASS only because the gate cannot start at all |
| E9b missing replay configuration (`ACTENON_ENV=''`) | PASS | FAIL (starts with per-process replay) |
| E10a/b no signing config (`''`, `prd`) | PASS (no proof minted) | FAIL (mints HS256 with the public secret) |
| E10c invalid key file | PASS | PASS |
| E10d edge rooted in the public secret (`''`) | PASS (refused) | FAIL |

The first candidate E2E run used loose assertions. It reported E5/E8b as PASS when the refusals were `SCOPE_CAPABILITY_MISMATCH`.
It is kept as `e2e/e2e-RUN1-candidate-loose-assertions-SUPERSEDED.txt` and must not be cited as a pass.

**Quickstart / README commands** from the installed wheel (`quickstart/quickstart-FINAL-2a7850c-r2-with-08b.txt`):
- `--help`, `conformance run --require-complete` (51 tests, Actenon Verified), `simulate --incident replit`, `simulate --scenario all`,
  `python -m actenon.demo.local_proof`, `actenon-mcp --demo`: rc 0.
- `verify-proof` and `verify-receipt` on the demo artifacts: rc 0 with `ACTENON_ENV=development`, as the QUICKSTART now states;
  rc 1 without it, by design.
- `--demo` under `prd` and the MCP server with no key: refused, as required.
- Not executed: the README's `PCCBVerifier` / `BoundaryVerifier` snippets (they are fragments with undefined variables) and the
  docker-compose "production reference".

---

## 8. Gates

| gate | state | evidence | smallest concrete remaining action |
|---|---|---|---|
| **G1 Released fixes/advisories** | **FAIL** | §1, §3. Every fix exists only in unreleased candidates or branches. Kernel 1.2.1 on PyPI still has the BoundaryVerifier any-token defect, H1 and H2. Permit 1.4.0 lacks main's PR #21 security fixes. 0 advisories in any repo | Owner decision to publish kernel 1.3.0 from `2a7850c` (or a successor) **with a GHSA naming kernel ≤1.2.1**. Then Permit 2.0.0 with its GHSA |
| **G2 Required CI** | **FAIL** | §6. No repo enforces any check. Permit CI disabled. sdk-go CI red on main and its tag. Bandit and pip-audit cannot fail | Owner: in each repo's settings, require the CI jobs on `main`. Re-enable Permit's workflows. Then remove `\|\| true` / `continue-on-error` from the security jobs and fix sdk-go's test vector path (the candidate `37700d0` already does) |
| **G3 Secure defaults** | **FAIL** | §4: the kernel candidate meets the principle (tests, H1/H2 matrices and E2E on the built wheel). But no Permit candidate exists: released and main Permit still fall back to `build_local_proof_signer()` and declare `actenon-kernel>=1.0.0`, which admits kernels without the guard | Permit candidate: raise the floor to `actenon-kernel[asymmetric]>=1.3.0` and make `resolve_signer()` refuse when no key is configured unless development intent is declared. Re-run `h1h2/run_h2.sh` and `e2e/run_e2e.sh` against the built Permit wheel |
| **G4 Machine-checked public claims** | **FAIL** | §1, §6, §7. verify-claims checks neutrality, independence, dependency direction, conformance count and the MCP marker only. False/unchecked public claims include: `docs/PRODUCTION_INTEGRATION.md` §9 "production reference … Postgres replay store" (candidate retracts it; main does not); README badge "SDKs: Py · TS · Go · Rust" (published Go v1.0.0 and the Rust tag cannot verify current proofs; TS and Rust are unpublished); `VERSIONING.md` "Kernel version 1.0.0"; npm packages that do not import in Node | Add one verify-claims job per repo that installs each **published** artefact in a clean environment and runs `differential` case `baseline_valid_hs256` (and a Node import for each npm package). Fail the badge on mismatch |
| **G5 Cross-language parity** | **FAIL** | §5. A = 0 for every candidate through its raw entry point (Python, TS `verifyJSON`, Go `37700d0`, Rust `261ffbf`). But the TS object API still accepts 7 + 3 reference-refused proofs when fed `JSON.parse` output. TS cannot verify EdDSA, the algorithm Permit mints in production (5 unsupported). The published Go/Rust SDKs refuse 49/179 valid proofs | Remove `verify`/`verifyPayloads` from the public TS surface for untrusted input (or make `verifyJSON` the only exported entry) and add an EdDSA verifier to the TS SDK. Re-run `differential/runner_ts_strict.mjs` on both frozen corpora (target A = 0, U = 0) |
| **G6 AIRLOCK eligibility** | **FAIL** | Depends on G1–G5 (all FAIL). Its own defects: E8b, a proof whose authority was revoked still executes at the edge; E0, Permit glob-scoped grants produce proofs the kernel edge refuses | Wire a `revocation_checker` through `ActenonGate` and give Permit a revocation source the edge can consult. Then re-run `e2e/run_e2e.sh` (E8b must refuse) |

Release decisions and AIRLOCK-001 are the owner's. Nothing was published or started.
