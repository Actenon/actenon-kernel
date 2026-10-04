# Current state, 2026-10-03 16:10 UTC (after the recovery of ce339cf)

Read from the repositories, the GitHub API and the public registries in this session; nothing below is
carried over from memory. Detail lives in the documents linked; this file only classifies.

## Candidates (verified)

| Repo | PR | Head = candidate | NS1 identity (task brief) | `main` |
|---|---|---|---|---|
| actenon-protocol | Actenon/actenon-protocol#19 (draft) | e988c4d | 45b7753, ancestor (+5 commits) | b45ef37, contained in the PR |
| actenon-kernel | Actenon/actenon-kernel#41 (draft) | ce339cf (code 185e0fd; ce339cf adds the skip-gate allowlist and evidence only) | 142364f, 6d6c630: ancestors | 43e17ad, contained |
| sdk-go | Actenon/sdk-go#2 (draft) | 0198ef5 | e3649cd, ancestor (+4) | bbd1c0d, contained |
| sdk-rust | Actenon/sdk-rust#4 (draft) | c149ab6 | 0a16a84, ancestor (+3) | 261ffbf, contained |
| actenon-permit | Actenon/actenon-permit#22 (draft) | a0d2b8d (+ `rehearsal/permit-release-prep-v4.patch` at step 5) | a5467ab, ancestor (+5) | c1eea9c, contained |

The NS1 identities are superseded by the fixes listed in FINAL-GATES.md ("Defects found and fixed"); full
SHAs and trees are in CANDIDATE-HASHES.txt. Registries today: PyPI actenon-protocol 1.3.0, actenon-kernel
1.2.1, actenon-permit 1.4.0; npm @actenon/sdk 1.4.0, @actenon/verifier-sdk absent; Go sdk-go v1.0.0;
crates.io actenon-verifier-sdk absent. No release tag for any candidate version exists.

## PROVEN
- GitHub PR CI, latest head: protocol 12/12 green; sdk-go 4/4; sdk-rust 5/5; kernel ce339cf 19 of 21 checks
  green, 1 skipped, 1 expected failure (below) (Python 3.10/3.11/3.12, pip-audit, scan, actenon-scan, Bandit, lychee, PostgreSQL 16 replay, TS/Go/Rust
  verifier SDKs, clean-install closure, base-install conformance, invariants, drift-gate, SBOM,
  version coherence, required-check names; Sigstore signing is skipped by design on PRs).
- The skip-gate fix: on 715f4e7 the gate reports 1 unexpected skip; on ce339cf 921 executed / 0 unexpected
  (local and GitHub).
- Candidate-artefact results of rehearsal 3 (not release results): FRESH-CONSUMER.md 40/40, CROSS-LANGUAGE-PARITY.md
  (A = 0, U = 0, B enumerated), FULL-E2E.md 25/25 on SQLite and on PostgreSQL 16, controls/ (old public
  artefacts fail all 7 discriminating controls).
- Recovery of ce339cf: candidate SHAs/trees, CI-gate matrix, hashes, protection payloads, org-profile patch,
  SHA256SUMS (601 files) all reproduced the recorded outputs (commit message of ce339cf).

## CURRENTLY RUNNING
- Nothing.

## EXPECTED FAILURE (RELEASE_ORDER_DEPENDENCY, not a code defect)
- kernel#41 `Verify README claims (machine-enforced)`: the README is rendered by protocol 1.4.0; CI renders
  with PyPI protocol 1.3.0 (no sdk-go/sdk-rust rows). Green after release-graph step 1.
- permit#22 `Verify README claims (machine-enforced)`: same, and `pip install .` also needs kernel 1.3.0 on
  PyPI (step 2).

## REAL FAILURE
- The prepared branch-protection payloads (`owner/branch-protection-*.json`) require 1 approving review with
  `enforce_admins`, but each repository has exactly one collaborator (rossbuckley1990-hash, admin). GitHub
  forbids self-approval, so applying them unchanged would block every merge, the release PRs included.
  `owner/apply-owner-actions.sh` applies the same required checks with `REQUIRED_REVIEWS=0` (default) and
  keeps the human gate in the pypi/npm environment reviewers.

## OWNER ACTION (blocks release-graph step 0; nothing has been merged, tagged or published)
- A1 Permit workflows `ci.yml`, `link-check.yml`, `protocol-drift.yml`, `version-coherence.yml`,
  `actenon-scan.yml`: still `disabled_inactivity` (GitHub API, today). 6 of Permit's 8 required checks have
  never run on the candidate.
- A3 branch protection: `main` is unprotected in actenon-kernel, actenon-permit, sdk-go and sdk-rust;
  protocol `main` is protected with unknown rules.
- A4 tag rulesets, A5 environments with reviewers, A6 PyPI trusted publishers, A7 `NPM_TOKEN_ACTENON`,
  A8 `CARGO_REGISTRY_TOKEN`, A9 signed `conformance-v1.1.0`: not readable from this session; the session
  has no admin API and no registry credentials. A1-A5 are one command:
  `APPLY=1 bash evidence/release/north-star/owner/apply-owner-actions.sh` (dry run without `APPLY`).
- A10 advisories: drafts stay private; publish after each fixed version is installable.

## NOT YET TESTED
- Every release-graph step (RELEASE-GRAPH.md 1-6) and every published-artefact check: G1, G3, G4, G5 are
  defined over released artefacts (FINAL-GATES.md).
- Permit's CI on GitHub (A1).
- Merge commits of the five PRs on `main` (CI on merge commits).

**ACTENON ECOSYSTEM NORTH STAR: NOT PASS.** OWNER RELEASE ACTION REQUIRED: OWNER-ACTIONS A1-A9 (step 0).
