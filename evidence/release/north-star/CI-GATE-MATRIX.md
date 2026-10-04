# CI gate matrix (north-star)

Status legend: **LOCAL** = the check's commands were run by this session; **PR-CI** = conclusion of that check-run on the candidate PR head; **REQUIRED-CHECK** = enforced by branch protection on `main` (cannot be read or set from this session: OWNER_ACTION_REQUIRED, see OWNER-ACTIONS.md); **PUBLISH-GATED** = listed in `release` of `.github/required-checks.json`, so `scripts/release_gate.py gate` refuses to publish unless it succeeded on the tagged commit.

An unexecuted workflow is never counted as PASS.

## actenon-protocol — Actenon/actenon-protocol#19 @ e988c4d

| Check | Workflow | LOCAL | PR-CI | REQUIRED-CHECK | PUBLISH-GATED | Note |
|---|---|---|---|---|---|---|
| Conformance suite (Python 3.10) | `ci.yml` | PASS (pytest conformance/python: 290 passed, 20 skipped) | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025970/job/111180059509) | OWNER_ACTION_REQUIRED | yes |  |
| Conformance suite (Python 3.11) | `ci.yml` | PASS | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025970/job/111180059570) | OWNER_ACTION_REQUIRED | yes |  |
| Conformance suite (Python 3.12) | `ci.yml` | PASS | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025970/job/111180059482) | OWNER_ACTION_REQUIRED | yes |  |
| Lint + format check | `ci.yml` | PASS (ruff check/format python/ conformance/python/) | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025970/job/111180059358) | OWNER_ACTION_REQUIRED | yes |  |
| TypeScript types check | `ci.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025970/job/111180059687) | OWNER_ACTION_REQUIRED | yes |  |
| TypeScript runtime (@actenon/protocol) | `ci.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025970/job/111180059559) | OWNER_ACTION_REQUIRED | yes |  |
| Verify README claims (machine-enforced) | `verify-claims.yml` | PASS (every step, run_wf_steps) | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025914/job/111180058872) | OWNER_ACTION_REQUIRED | yes |  |
| pyproject / tag / PyPI agree | `version-coherence.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025872/job/111180058902) | OWNER_ACTION_REQUIRED | no (PR only) |  |
| scan | `actenon-scan.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025900/job/111180059056) | OWNER_ACTION_REQUIRED | no (PR only) |  |
| Required-check names exist | `ci.yml` | PASS (release_gate.py validate) | [SUCCESS](https://github.com/Actenon/actenon-protocol/actions/runs/37115025970/job/111180059611) | OWNER_ACTION_REQUIRED | yes |  |

Not required (informational): lychee = success

## actenon-kernel — Actenon/actenon-kernel#41 @ 715f4e7

| Check | Workflow | LOCAL | PR-CI | REQUIRED-CHECK | PUBLISH-GATED | Note |
|---|---|---|---|---|---|---|
| Python tests (3.10) | `ci.yml` | PASS (894 passed / 5 skipped; skip gate 0 unexpected after the allowlist fix) | [FAILURE](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036703) | OWNER_ACTION_REQUIRED | yes | FAILED on 715f4e7 only in the skip gate: test_concurrent_cold_start_creates_the_schema_once (runs in postgres-replay) was not allow-listed; fix committed locally, push pending network |
| Python tests (3.11) | `ci.yml` | not run locally | [FAILURE](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036737) | OWNER_ACTION_REQUIRED | yes | same as 3.10 |
| Python tests (3.12) | `ci.yml` | PASS (same) | [FAILURE](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036758) | OWNER_ACTION_REQUIRED | yes | same as 3.10 |
| Required-check names exist | `ci.yml` | PASS (release_gate.py validate) | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036740) | OWNER_ACTION_REQUIRED | yes |  |
| Replay store on PostgreSQL 16 | `ci.yml` | PASS (real PostgreSQL 16 server: 3/3 incl. concurrent cold start) | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036624) | OWNER_ACTION_REQUIRED | yes |  |
| TypeScript verifier SDK | `ci.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036666) | OWNER_ACTION_REQUIRED | yes |  |
| Go verifier SDK (standalone, pinned) | `ci.yml` | PASS (check_standalone_sdk_fixtures.py; go test against this lock) | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036732) | OWNER_ACTION_REQUIRED | yes |  |
| Rust verifier SDK (standalone, pinned) | `ci.yml` | PASS (check_standalone_sdk_fixtures.py; cargo test against this lock) | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910203/job/111211036698) | OWNER_ACTION_REQUIRED | yes |  |
| Invariant tests | `invariants.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910136/job/111211036371) | OWNER_ACTION_REQUIRED | yes |  |
| Clean-install closure check | `invariants.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910136/job/111211036225) | OWNER_ACTION_REQUIRED | yes |  |
| Base-install conformance (no extras) | `invariants.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910136/job/111211036342) | OWNER_ACTION_REQUIRED | yes |  |
| Bandit scan (actenon/, severity >= medium, gating) | `bandit.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910221/job/111211036636) | OWNER_ACTION_REQUIRED | yes |  |
| Audit dependencies (pip-audit) | `supply-chain.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910224/job/111211036675) | OWNER_ACTION_REQUIRED | yes |  |
| Generate SBOM (CycloneDX) | `supply-chain.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910224/job/111211036836) | OWNER_ACTION_REQUIRED | no (PR only) |  |
| Verify README claims (machine-enforced) | `verify-claims.yml` | PASS except the ecosystem step with PyPI protocol 1.3.0 (release order); PASS with protocol 1.4.0 | [FAILURE](https://github.com/Actenon/actenon-kernel/actions/runs/37125910187/job/111211036576) | OWNER_ACTION_REQUIRED | yes | release order: green once actenon-protocol 1.4.0 is on PyPI (comment on the PR) |
| pyproject / tag / PyPI agree | `version-coherence.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910185/job/111211036394) | OWNER_ACTION_REQUIRED | no (PR only) |  |
| drift-gate | `protocol-drift.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910208/job/111211036920) | OWNER_ACTION_REQUIRED | no (PR only) |  |
| scan | `actenon-scan.yml` | not run locally | [SUCCESS](https://github.com/Actenon/actenon-kernel/actions/runs/37125910172/job/111211036456) | OWNER_ACTION_REQUIRED | no (PR only) |  |

Not required (informational): lychee = success, Sigstore-sign release wheel = skipped

## sdk-go — Actenon/sdk-go#2 @ 0198ef5

| Check | Workflow | LOCAL | PR-CI | REQUIRED-CHECK | PUBLISH-GATED | Note |
|---|---|---|---|---|---|---|
| Test (Go 1.22) | `ci.yml` | PASS (go vet + go test, Go 1.24 toolchain) | [SUCCESS](https://github.com/Actenon/sdk-go/actions/runs/37114988337/job/111179954320) | OWNER_ACTION_REQUIRED | yes |  |
| Test (Go stable) | `ci.yml` | PASS | [SUCCESS](https://github.com/Actenon/sdk-go/actions/runs/37114988337/job/111179954257) | OWNER_ACTION_REQUIRED | yes |  |
| Vendored kernel vectors match the pinned kernel | `ci.yml` | PASS (lock test with the kernel's lock) | [SUCCESS](https://github.com/Actenon/sdk-go/actions/runs/37114988337/job/111179954344) | OWNER_ACTION_REQUIRED | yes |  |
| Required-check names exist | `ci.yml` | PASS (release_gate.py validate) | [SUCCESS](https://github.com/Actenon/sdk-go/actions/runs/37114988337/job/111179954317) | OWNER_ACTION_REQUIRED | yes |  |

## sdk-rust — Actenon/sdk-rust#4 @ c149ab6

| Check | Workflow | LOCAL | PR-CI | REQUIRED-CHECK | PUBLISH-GATED | Note |
|---|---|---|---|---|---|---|
| fmt + clippy + doc | `ci.yml` | PASS (cargo fmt --check, clippy -D warnings) | [SUCCESS](https://github.com/Actenon/sdk-rust/actions/runs/37114989493/job/111179958107) | OWNER_ACTION_REQUIRED | yes |  |
| Test (Rust 1.88) | `ci.yml` | not run locally | [SUCCESS](https://github.com/Actenon/sdk-rust/actions/runs/37114989493/job/111179958179) | OWNER_ACTION_REQUIRED | yes |  |
| Test (Rust stable) | `ci.yml` | PASS (37 tests) | [SUCCESS](https://github.com/Actenon/sdk-rust/actions/runs/37114989493/job/111179958058) | OWNER_ACTION_REQUIRED | yes |  |
| Vendored kernel vectors match the pinned kernel | `ci.yml` | PASS | [SUCCESS](https://github.com/Actenon/sdk-rust/actions/runs/37114989493/job/111179958009) | OWNER_ACTION_REQUIRED | yes |  |
| Required-check names exist | `ci.yml` | PASS (release_gate.py validate) | [SUCCESS](https://github.com/Actenon/sdk-rust/actions/runs/37114989493/job/111179957932) | OWNER_ACTION_REQUIRED | yes |  |

## actenon-permit — Actenon/actenon-permit#22 @ a0d2b8d

| Check | Workflow | LOCAL | PR-CI | REQUIRED-CHECK | PUBLISH-GATED | Note |
|---|---|---|---|---|---|---|
| test-python (3.11) | `ci.yml` | PASS (uv run pytest: 558 passed, 1 skipped, kernel pin b1b175d) | NOT RUN | OWNER_ACTION_REQUIRED | yes |  |
| test-python (3.12) | `ci.yml` | PASS (same suite) | NOT RUN | OWNER_ACTION_REQUIRED | yes |  |
| kernel-conformance | `ci.yml` | not run locally | NOT RUN | OWNER_ACTION_REQUIRED | yes |  |
| test-ts | `ci.yml` | not run locally | NOT RUN | OWNER_ACTION_REQUIRED | yes |  |
| Verify README claims (machine-enforced) | `verify-claims.yml` | not run locally | [FAILURE](https://github.com/Actenon/actenon-permit/actions/runs/37115066267/job/111180174889) | OWNER_ACTION_REQUIRED | yes | release order: protocol 1.4.0 renderer, then kernel 1.3.0 on PyPI for `pip install .` |
| pyproject / tag / PyPI agree | `version-coherence.yml` | not run locally | NOT RUN | OWNER_ACTION_REQUIRED | no (PR only) |  |
| drift-gate | `protocol-drift.yml` | not run locally | NOT RUN | OWNER_ACTION_REQUIRED | no (PR only) |  |
| Required-check names exist | `ci.yml` | PASS (release_gate.py validate) | NOT RUN | OWNER_ACTION_REQUIRED | yes |  |

## Permit: workflows disabled for inactivity

`ci.yml`, `link-check.yml`, `protocol-drift.yml`, `version-coherence.yml` and `actenon-scan.yml` in Actenon/actenon-permit are in state `disabled_inactivity` (GitHub API, 2026-10-03). Every required check they produce is NOT RUN on the candidate. Re-enabling them is an owner action; until then Permit's PR-CI status is FAIL, not PASS.

