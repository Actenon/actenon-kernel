# Actenon ecosystem baseline — 2026-10-02

Scope: actenon-protocol, actenon-kernel, actenon-permit, sdk-go, sdk-rust, blastradius. actenon-scan is excluded. Every fact below was taken
from the live GitHub/registry state between 09:28Z and 09:55Z on 2026-10-02, in a fresh container. Raw API responses are in
`raw/` (`*.rules-main.json`, `*.branch-main.json`, `*.workflows.json`, `*.runs.json`, `*.open-pulls.json`, `*.rulesets.json`,
`mcp-registry.json`) and in `../00-preservation/00-remote-snapshot/*.ls-remote.txt` (every ref of every repo at 09:28:44Z).

## 0. Preservation status of the previous session's local work

The previous session (`session_01AWNAfEkZsFvwvUGh6dF8bh`, "Actenon kernel MCP setup") produced local-only work that was **never pushed**:
kernel commits `b97f38f`, `22a5e81`, `440302f`, `960da9a` (TS parity: "TS accepts / reference refuses 23 → 0"); the `g3/secure-defaults`
kernel worktree; permit commits; and scratchpad evidence (`ECOSYSTEM-BASELINE-20261001.md`, the Permit version determination,
RELEASE-GRAPH draft, the CI audit, the E2E pre-registration and harness, and the `kernel_diff_v1` corpus with claimed hash
`ac4914a43c2bead4c0899aa006a48b4d2105b6cebf29a17da4623a69747e8721`).

- None of those commit objects exists on any `origin` ref of actenon-kernel (verified with `git cat-file` after fetching every head).
- No `backup/*` ref exists in any repo (`ls-remote`, 09:28Z).
- That session is idle and disconnected. The preservation checkpoint was relayed to it at ~09:22Z and ~09:26Z and had not been processed by 09:28Z.

**Status: UNAVAILABLE to this session, not lost by this session, and NOT CITED.** No result below depends on it. If that session
later pushes `backup/production-readiness-20261002*` refs, they should be compared against this programme's results; until then the
"23 → 0" TS parity claim, the "813 passed" kernel suite count and the "B = 48" TS observation are **unverified**.

## 1. Per-repository state

| | protocol | kernel | permit | sdk-go | sdk-rust | blastradius |
|---|---|---|---|---|---|---|
| main HEAD | `b45ef37` | `43e17ad` | `c1eea9c` | `bbd1c0d` | `261ffbf` | `df10b55` |
| version on main | 1.3.0 (py), `@actenon/protocol-types` 1.3.0, `@actenon/protocol` 1.0.0 | 1.2.1; TS `@actenon/verifier-sdk` 0.1.0 | pyproject 1.4.0 / `__version__` **"1.1.0"** (mismatch); `@actenon/sdk` 1.4.0 | module, no version file | Cargo 0.1.0 | 0.4.0 |
| latest tag | v1.3.0 (+ ts-types-v1.3.0) | v1.2.1 (`238b3ab`) | v1.4.0, ts-sdk-v1.4.0 | v1.0.0 (`89a23b4`) | v0.1.0 | v0.4.0 |
| published | PyPI 1.3.0; npm `@actenon/protocol-types` 1.3.0; npm `@actenon/protocol` **not published** | PyPI 1.2.1; MCP Registry 1.2.1 and 1.2.2 (1.2.2 = metadata-only, installs PyPI 1.2.1); npm `@actenon/verifier-sdk` **not published** | PyPI 1.4.0; npm `@actenon/sdk` 1.4.0 | Go proxy v1.0.0 = `89a23b4` (**not** main `bbd1c0d`) | **crates.io: none** (publish run on 2026-07-25 failed); git dependency only | PyPI `actenon-blastradius` 0.4.0 |
| commits on main since latest tag | — | 6 (docs/CI only) | — | 2 (`0402df3`, `bbd1c0d`) | — | — |
| open PRs | #18 (programme, `c30ac00`) | #37 (programme, `3c6ca76`), #38 dependabot cryptography 50, #36 external fork | #11 `fix!: canonicalise via ACTENON-JCS-STRICT-1` (`ef20ad7`), #7 integrate protocol v1.0.0 (`97b675a`, stale) | none | none | #1 codex/auditable-milestone (`f7161d8`) |
| programme branch `claude/actenon-kernel-mcp-setup-qolk0h` | `c30ac00`, 22 ahead, unmerged | `3c6ca76`, 17 ahead, unmerged (PR #37) | `08d60fe`: main contains an earlier merge (#21); branch has 28 files of later unmerged work | `37700d0`, 20 ahead, unmerged, **no PR** | `7fda4b4`: tree **identical** to main (merged via #3) | `d7f60a6`: main = squash of an earlier head (#2); 9 files of later unmerged work, **no PR** |
| workflows (state) | all 8 active | all 14 active | **CI, Link check, Protocol drift gate, Version coherence and actenon-scan: `disabled_inactivity`**; Publish (PyPI, npm) and Verify claims active | CI active; actenon-scan disabled_inactivity | CI and Publish active | CI and Publish active |
| latest CI on main | Link check **failure** (sched. 10-01); Verify claims, Version coherence success; no CI run on main in last 100 runs | Link check **failure**; Bandit, Protocol drift, Verify claims, Version coherence success | last CI run was on `7c9c9cd` (**before** current main); none on `c1eea9c`. Verify claims (dispatch) success on `c1eea9c` | **CI failure on `bbd1c0d`** (push 07-26) | CI success on `261ffbf` | CI success on `df10b55` |
| CI on programme head | `c30ac00`: all success | `3c6ca76`: **CI failure**, **Link check failure**, others success | none (workflows disabled) | none on `37700d0` | `7fda4b4`: success | none on `d7f60a6` (last branch run at `04059ad`) |
| branch protection on main | **protected, but required status checks `enforcement_level: off`, contexts []** | not protected | not protected | not protected | not protected | not protected |
| rulesets (`/rules/branches/main`, `/rulesets`) | none | none | none | none | none | none |

**Enforcement conclusion: no repository requires any CI check to pass before a merge to `main`.** Protocol's protection object
exists but requires zero checks. A workflow file existing, or even being green, does not gate anything. Changing this is a
repository-settings action (owner/admin), and can't be made in a commit.

## 2. Declared dependency edges (as written on main)

| consumer | dependency | declared constraint | where | technically enforced? |
|---|---|---|---|---|
| kernel 1.2.1 | actenon-protocol | `>=1.1.0,<2` | pyproject | yes, by the resolver |
| permit 1.4.0 | actenon-kernel[asymmetric] | `>=1.0.0` (no upper bound) | pyproject | yes, but the floor admits every kernel with the unfixed BoundaryVerifier/executor defects (see §3) |
| permit 1.4.0 | actenon-protocol | `>=1.1.0,<2` | pyproject | yes |
| `@actenon/protocol` 1.0.0 | `@actenon/protocol-types` | `^1.0.0` | package.json | yes (not published, so moot) |
| `@actenon/sdk` 1.4.0 | none | — | package.json | n/a: reimplements canonicalisation and HMAC itself |
| kernel TS SDK | none | — | package.json | n/a: reimplements the verifier |
| sdk-go / sdk-rust | none | — | go.mod / Cargo.toml | n/a: reimplement the verifier; the vendored kernel vectors are the only coupling |
| blastradius | none on Actenon packages | — | pyproject | n/a |

## 3. Discrepancies with the previous session's report (reconciled)

| previous claim | live finding today |
|---|---|
| "permit main c1eea9c equals the tree of a14244c" | not checkable here (a14244c is not on any origin ref); main `c1eea9c` = merge of PR #21 |
| "sdk-rust main aacd2cb is a merge of 3e26af2" | main is now `261ffbf` = merge of PR #3; its tree equals programme head `7fda4b4` |
| "blastradius branch d7f60a6 pushed (342 tests)" | `d7f60a6` exists remotely; main `df10b55` is PR #2 squash of `04059ad`; `d7f60a6` is 9 files ahead and has no CI run |
| "protocol PR #18 11/11 green" | 5 workflow runs on `c30ac00` all success (some jobs aggregate) |
| "kernel PR #37 17/19: Rust SDK clippy + lychee" | `3c6ca76`: CI failure + Link check failure confirmed; job-level cause re-checked in `../04-ci/` |
| "permit workflows disabled" | confirmed: 5 of 8 `disabled_inactivity`, including CI |
| local kernel HEAD 22a5e81 / 960da9a | absent from GitHub (§0) |
| "TS accepts / reference refuses: 23 → 0" | unverifiable (§0); re-measured from scratch in `../03-differential/` |

## 4. Facts noticed while baselining (followed up elsewhere)
- `@actenon/sdk@1.4.0` (npm, latest) **fails to import under Node.js ESM** (`ERR_MODULE_NOT_FOUND`: `dist/index.js` does `export * from "./protocol"` without a `.js` extension). It works under Bun. Evidence: `../05-release/pr11-probe/RESULTS.txt`.
- Released Permit 1.4.0 grant tokens with a non-ASCII `agent_id` are **rejected by `@actenon/sdk@1.4.0` `verifyGrantToken`** (signature mismatch; ASCII works). This is a fail-closed cross-language defect. Same file.
- Permit main `src/actenon_permit/__init__.py` declares `__version__ = "1.1.0"` while pyproject/PyPI is 1.4.0.
- The published Go module v1.0.0 is `89a23b4`. main `bbd1c0d` has CI red, and the programme branch with the kernel-vector lock has no PR.
