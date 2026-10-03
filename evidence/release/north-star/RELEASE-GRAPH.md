# Release graph (north-star) — not executed

Nothing here has been merged, tagged or published. Each step starts only when the previous one is fully
verified, and **any failed step stops the graph** (see "Stop conditions"). Merges are **merge commits**
(never squash or rebase): the SDKs pin kernel commit `b1b175d` (`fixtures/KERNEL_PIN`), the kernel's
`sdk/standalone-sdk-pins.json` pins sdk-go `0198ef5` and sdk-rust `c149ab6`, and Permit's pre-release pin
named kernel `b1b175d`. Every one of those commits must remain reachable from `main`.

Every publish workflow runs `scripts/release_gate.py gate`. It requires the tag to equal the declared
version, the tagged commit to be on `origin/main`, and every `release` check in
`.github/required-checks.json` to have succeeded on that exact commit. It refuses anything else.

## Candidates (rehearsal 3 built and verified from exactly these commits)

| Repo | Branch head used | PR | Version(s) |
|---|---|---|---|
| actenon-protocol | e988c4d | Actenon/actenon-protocol#19 | 1.4.0 (PyPI `actenon-protocol`, npm `@actenon/protocol-types`) |
| actenon-kernel | 185e0fd (+ the skip-allowlist commit, which changes no artefact: `scripts/` is not packaged) | Actenon/actenon-kernel#41 | 1.3.0 (PyPI `actenon-kernel`), npm `@actenon/verifier-sdk` 0.2.0, Conformance 1.1.0 |
| sdk-go | 0198ef5 | Actenon/sdk-go#2 | v1.1.0 (Go module `github.com/Actenon/sdk-go`) |
| sdk-rust | c149ab6 | Actenon/sdk-rust#4 | 0.2.0 (crates.io `actenon-verifier-sdk`) |
| actenon-permit | a0d2b8d + release preparation (`rehearsal/permit-release-prep-v4.patch`, committed in step 5) | Actenon/actenon-permit#22 | 2.0.0 (PyPI `actenon-permit`, npm `@actenon/sdk`) |
| actenon-blastradius | — | — | **not in this release**: BLOCKED (BLASTRADIUS.md) |

## Steps

**0. Pre-flight.** OWNER-ACTIONS.md A1–A9 done. Required checks green on each PR head (CI-GATE-MATRIX.md).
The kernel's and Permit's `Verify README claims` turn green only after step 1 (release order), and Permit's
also needs kernel 1.3.0 on PyPI (step 2).

**1. actenon-protocol 1.4.0** (first: the kernel's and Permit's README checks render with it)
```
merge Actenon/actenon-protocol#19 (merge commit); wait for CI green on the merge commit
git tag -a v1.4.0 <merge> -m "actenon-protocol 1.4.0" && git push origin v1.4.0        # publish.yml → PyPI, then verify-registry installs actenon-protocol[types]==1.4.0 and runs the conformance runner
git tag -a ts-types-v1.4.0 <merge> -m "@actenon/protocol-types 1.4.0" && git push origin ts-types-v1.4.0   # publish-ts-types.yml → npm (pack, smoke, publish --provenance, smoke from registry)
```
Verify: `pip download actenon-protocol==1.4.0` content = rehearsal-3 (`rehearsal/compare_artefact_contents.py`);
npm tarball sha256 = `c01c86b6…0992a5` (deterministic); re-run CI on kernel#41 and permit#22 (`Verify README claims` must now pass the ecosystem step).

**2. actenon-kernel 1.3.0 + @actenon/verifier-sdk 0.2.0 + Conformance 1.1.0**
```
merge Actenon/actenon-kernel#41 (merge commit); CI green on the merge commit
git tag -a v1.3.0 <merge> && git push origin v1.3.0                   # publish.yml (PyPI, wheel conformance before upload, Sigstore, verify-registry) + publish-mcp-registry.yml
git tag -a verifier-sdk-v0.2.0 <merge> && git push origin verifier-sdk-v0.2.0   # publish-verifier-sdk.yml → npm
git tag -s conformance-v1.1.0 <merge> -m "Actenon Conformance 1.1.0" && git push origin conformance-v1.1.0   # signed (owner action A9)
scripts/verify_published.sh python && scripts/verify_published.sh ts       # must print PASS
```
Verify: wheel content = rehearsal-3; npm `@actenon/verifier-sdk` tarball sha256 = `adfa3bcc…57e8bb`.

**3. sdk-go v1.1.0** (needs b1b175d on kernel `main`, guaranteed by step 2's merge commit)
```
merge Actenon/sdk-go#2 (merge commit); CI green
git tag -a v1.1.0 <merge> && git push origin v1.1.0                   # verify-tag.yml
GOPROXY=https://proxy.golang.org go list -m github.com/Actenon/sdk-go@v1.1.0
scripts/verify_published.sh go v1.1.0                                  # in actenon-kernel
```
Verify: sum.golang.org records `github.com/Actenon/sdk-go v1.1.0 h1:Q368pwEy+sNg/hb5++Vr1QzE/G90QvSqyX4WS83xMew=` and
`/go.mod h1:yeOA1lt5N4bb9uLRW4jLbLf7f4GwM5WNdhbi3f22Rgs=` (the rehearsal-3 module). These are content hashes, so they match exactly when the merge commit's tree equals the PR head 0198ef5's tree, which holds as long as sdk-go `main` has not moved since the PR branched.

**4. sdk-rust 0.2.0**
```
merge Actenon/sdk-rust#4 (merge commit); CI green
git tag -a v0.2.0 <merge> && git push origin v0.2.0                   # publish.yml: gate, cargo publish --locked, download from crates.io, cargo test
scripts/verify_published.sh rust                                       # in actenon-kernel
```
Verify: crate sha256 = rehearsal-3 `actenon-verifier-sdk-0.2.0.crate` if the tagged tree equals c149ab6.

**5. actenon-permit 2.0.0 + @actenon/sdk 2.0.0** (needs kernel 1.3.0 on PyPI)
```
on the PR branch: apply rehearsal/permit-release-prep-v4.patch (removes [tool.uv.sources], version 2.0.0,
  kernel floor >=1.3.0,<2, @actenon/sdk 2.0.0, README/CHANGELOG), then `uv lock` (now against PyPI) and push
CI green (needs OWNER-ACTIONS A1) → merge (merge commit)
git tag -a v2.0.0 <merge> && git push origin v2.0.0                   # publish.yml → PyPI, verify-registry runs the demo
git tag -a ts-sdk-v2.0.0 <merge> && git push origin ts-sdk-v2.0.0     # publish-ts-sdk.yml → npm
```
Verify: wheel content = rehearsal-3 (built from the same patch); npm tarball sha256 = `0322270b…cebe6b6f`.

**6. After the last publication**
- Rerun the north-star checks against the public registries only (fresh-consumer harness without the
  rehearsal registry, `controls/` in candidate mode, full E2E) and record RELEASED-ARTEFACTS.json and
  PUBLISHED-CONFORMANCE.json.
- Publish the advisories (OWNER-ACTIONS A10), apply the org-profile patch (B1), and fix the kernel repo description (B2).
- Only then may AIRLOCK-001 start (AIRLOCK-001.md).

## Stop conditions
Stop the graph without the next step if any of these occurs:
- a release gate refuses;
- a publish or verify-registry job fails;
- `verify_published.sh` does not print PASS;
- a published artefact's content differs from rehearsal 3 other than through the documented, step-5 Permit preparation;
- a required check is red on a merge commit;
- a post-publish smoke import fails.

**Rollback:** registries are immutable. Never delete or overwrite a version. If a published version is
wrong, yank it (PyPI yank; `npm deprecate`; `cargo yank`; for Go, a `retract` directive in a new patch
release), fix forward with the next patch version, and keep every earlier tag and evidence file.
