# Final gates G1–G6 (north-star), 2026-10-03

Values: **PASS** / **FAIL** / **OWNER_ACTION_REQUIRED**. Published-artefact results are the final authority (rule 5).
Because nothing has been published (the programme stopped at RELEASE GATE READY), no gate that is defined over
released artefacts can be PASS. Candidate-artefact results are reported next to each value for contrast, not
as the value.

| Gate | Value | Candidate-artefact state (rehearsal 3) | Why the value is not PASS / what turns it PASS |
|---|---|---|---|
| **G1** Released fixes / advisories | **FAIL** (OWNER_ACTION_REQUIRED to proceed) | Every fix is in a release-numbered artefact built from an exact commit and verified by a fresh consumer (FRESH-CONSUMER.md: 40/40). | The registries still serve the defective versions: all 7 discriminating controls fail on what is published today (controls/PUBLISHED-CONTROL-REHEARSAL-3.json). Needs: owner actions A1–A10, then RELEASE-GRAPH.md steps 1–5, then the advisories. |
| **G2** Required CI | **OWNER_ACTION_REQUIRED** | PR CI on GitHub: protocol 11/11, sdk-go 4/4, sdk-rust 5/5 green. Kernel: every required check green on 715f4e7 except (a) Python ×3, red only in the skip gate (allowlist fix committed locally, push blocked by a network outage), and (b) `Verify README claims` (release order, resolves at step 1). Permit: only 1 of 8 required checks can run (CI-GATE-MATRIX.md). | Branch protection is unreadable and unset from this session (A3). Permit's workflows are disabled (A1). Kernel and Permit need step 1 of the graph. |
| **G3** Secure defaults | **FAIL** against released artefacts (released kernel 1.2.1 and Permit 1.4.0 are the phase-2 insecure versions); candidate: PASS | E2E E9/E9b/E9c/E10a–e on the rehearsal-3 artefacts: missing replay store (SQLite or PostgreSQL), no declared capabilities, and no or invalid signing key are each refused, with nothing minted (FULL-E2E.md). H1/H2 from phase 2, unchanged code paths. | Becomes PASS when kernel 1.3.0 and Permit 2.0.0 are published and the E2E driver passes against them. |
| **G4** Machine-checked public claims | **FAIL** | The machine checks exist and run in CI (PUBLIC-CLAIMS.md "Machine checks"). They pass on the candidates; `verify-published.yml` and the controls fail on today's registries, as they must. | G4 is PASS only when the machine check exists **and** the released artefacts satisfy it: after the release, `PUBLISHED-CONFORMANCE.json` must record "ALL FOUR PUBLISHED ARTEFACTS PASS CURRENT RELEASE CONFORMANCE". Org profile and repo description: OWNER-ACTIONS B1/B2. |
| **G5** Cross-language parity | **FAIL** against released artefacts (the published SDKs are not at parity: see controls/); candidate: PASS | CROSS-LANGUAGE-PARITY.md: A = 0 and U = 0 for TS, Go (both decodings) and Rust on three frozen corpora; B enumerated and justified; the Python reference is identical on 3.10/3.11/3.12; E2E: four edges agree on all 14 shared checks. | PASS when the parity run is repeated on the published artefacts. |
| **G6** AIRLOCK eligibility | **FAIL** (blocked by G1, G2, G4) | Glob-scope and revoked-proof regressions pass on four edges (FULL-E2E.md E0, E8b–E8e). | AIRLOCK-001.md: not started, by instruction. |

## Defects found and fixed during this programme (all preserved with evidence)
1. Kernel timestamps depended on the Python version (3.10 refused valid RFC 3339; 3.11+ accepted non-RFC
   forms). Found by the fresh-consumer rehearsal; frozen addendum c84f7b4 before the fix; fixed in 8c5c25e.
   sdk-go accepted `,` fractions: fixed in 8a87d6f.
2. PostgreSQL replay store: concurrent cold starts failed (139/160). Also present, but unclassified, in phase-2
   evidence. Fixed in 38dd580 + 185e0fd.
3. The kernel conformance suite changed content under the "1.0.0" label. Now Conformance 1.1.0 (b1b175d); the
   SDKs re-vendored (0198ef5, c149ab6).
4. `conformance-release.yml` was not release-gated (4a7c71a).
5. Twelve false or stale public claims across protocol, kernel and Permit (PUBLIC-CLAIMS.md).
6. blastradius: the published 0.4.0 is bypassable; the fixes are unmerged (BLASTRADIUS.md, BLOCKED).

## Verdict
**ACTENON ECOSYSTEM NORTH STAR: NOT PASS.** Exact blockers:
1. Nothing is published (G1). Execute RELEASE-GRAPH.md after OWNER-ACTIONS A1–A9.
2. Required checks are not enforced on `main` (A3), and Permit's CI cannot run (A1).
3. The published-artefact conformance statement is false until step 6 (G4, G5).
4. AIRLOCK-001 has not started (G6).
5. blastradius 0.5.0 is not on `main` or a registry (B3).
6. The kernel's skip-allowlist commit and this evidence are not yet pushed: outbound network outage in this
   session (DNS and the egress proxy both failing since about 13:30 UTC).
