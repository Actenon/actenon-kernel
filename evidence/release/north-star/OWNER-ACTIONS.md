# Owner actions (OWNER_ACTION_REQUIRED)

These steps need repository-admin or registry credentials that this session does not have. Nothing below
was done. Each item names the exact action and what it unblocks. The commands use the GitHub CLI as an org
admin.

## A. Before the first publication (blocking)

| # | Action | Exact command / place | Unblocks |
|---|---|---|---|
| A1 | Re-enable Permit's disabled workflows (state `disabled_inactivity`: CI, Link check, Protocol drift gate, Version coherence, actenon-scan) | `for w in ci.yml link-check.yml protocol-drift.yml version-coherence.yml actenon-scan.yml; do gh workflow enable "$w" -R Actenon/actenon-permit; done`, then re-run CI on `Actenon/actenon-permit#22` | 6 of Permit's 8 required checks (test-python ×2, kernel-conformance, test-ts, drift-gate, version-coherence) and the `Required-check names exist` job: they have never run on the candidate |
| A2 | Re-enable sdk-go's disabled `actenon-scan` workflow | `gh workflow enable actenon-scan.yml -R Actenon/sdk-go` | parity with the other repos (not a required check) |
| A3 | Branch protection on `main`, exact required checks from each repo's `.github/required-checks.json` | `gh api -X PUT repos/Actenon/<repo>/branches/main/protection --input owner/branch-protection-<repo>.json` for actenon-protocol (10 checks), actenon-kernel (18), sdk-go (4), sdk-rust (5), actenon-permit (8). The JSON is `scripts/release_gate.py print-protection`; regenerate it if required-checks.json changes. | REQUIRED-CHECK column of CI-GATE-MATRIX.md (currently OWNER_ACTION_REQUIRED everywhere; this session cannot read branch protection) |
| A4 | Tag rulesets: only maintainers may create release tags | Repository → Settings → Rules → Rulesets → New tag ruleset, target `v*` (all five repos), plus `ts-types-v*`, `ts-runtime-v*` (protocol), `verifier-sdk-v*`, `conformance-v*` (kernel), `ts-sdk-v*` (permit); restrict creations/updates/deletions to the release team. **sdk-go needs this most:** a Go module version *is* its tag, and no publish job can gate it. | tag integrity; for sdk-go the only control on what becomes `v1.1.0` |
| A5 | Deployment environments with required reviewers | Settings → Environments: `pypi` (protocol, kernel, permit) and `npm` (protocol, kernel, permit), each with ≥1 required reviewer and "deployment branches and tags: selected tags" matching the tag patterns above. sdk-rust's `publish.yml` names no environment: either rely on A4 for `v*`, or add `environment: crates-io` to that job in a follow-up. | a human approval between the release gate and the upload |
| A6 | PyPI trusted publishing (preferred) or tokens | pypi.org → each project (`actenon-protocol`, `actenon-kernel`, `actenon-permit`) → Publishing → Add a GitHub publisher: owner `Actenon`, repository, workflow `publish.yml`, environment `pypi`. If an API token is used instead, store it as environment secret `PYPI_API_TOKEN` (the workflows fall back to it only when it is set). | the three PyPI uploads |
| A7 | npm token | Organisation/environment secret `NPM_TOKEN_ACTENON` (environment `npm`) for actenon-protocol, actenon-kernel and actenon-permit, from an npm account with publish rights on the `@actenon` scope. `@actenon/verifier-sdk` has never been published: the first publish creates it, so the account must be allowed to create packages in the scope. | `@actenon/protocol-types` 1.4.0, `@actenon/verifier-sdk` 0.2.0, `@actenon/sdk` 2.0.0 |
| A8 | crates.io token | Repository secret `CARGO_REGISTRY_TOKEN` in Actenon/sdk-rust from the crates.io account that will own `actenon-verifier-sdk` (first publish creates the crate). | `actenon-verifier-sdk` 0.2.0 |
| A9 | Signed annotated tag for the kernel conformance release | `git tag -s conformance-v1.1.0 <kernel release commit> -m "Actenon Conformance 1.1.0"` with a key GitHub verifies (`conformance-release.yml` refuses an unverified tag), then push it. | the `Actenon Conformance 1.1.0` GitHub release (vector bundle + provenance) |
| A10 | Private security advisories (do NOT publish before the fixed artefacts are on the registries) | File as private GHSA drafts from the session's drafts (not in any public repository): actenon-kernel (affected ≤ 1.2.1, patched 1.3.0), actenon-permit + @actenon/sdk (affected ≤ 1.4.0, patched 2.0.0), actenon-blastradius (affected ≤ 0.4.0, patched 0.5.0, pending). Publish each only after its fixed version is installable from the public registry and its post-publish verification job is green. | coordinated disclosure |

## B. After publication

| # | Action | Exact command / place |
|---|---|---|
| B1 | Organisation profile (Actenon/.github) still advertises Conformance 1.0.0 / 51 vectors, sdk-go v1.0.0, sdk-rust v0.1.0 (git only), @actenon/sdk v1.4.0, protocol-types v1.3.0, a public link and product claims for the private actenon-cloud, and a **broken** `go get github.com/actenon/sdk-go@v1.0.0` (lower-case owner; Go module paths are case-sensitive). | Apply `POST-RELEASE-org-profile.patch` (in this directory) to Actenon/.github **after** every version it names is installable. This session cannot push to that repository. |
| B2 | GitHub repository description of Actenon/actenon-kernel says "51 conformance vectors". | Settings → General → Description: the suite is Conformance 1.1.0 (53 tests). |
| B3 | blastradius: merge the bypass fixes and release 0.5.0 (see BLASTRADIUS.md). | PR from `claude/actenon-kernel-mcp-setup-qolk0h` (d7f60a6) to `main` with the version bumped to 0.5.0 and release notes; CI green; then tag `v0.5.0`. |
