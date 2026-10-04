# Published-artefact controls, run 1 (rehearsal 2) — preserved as-is

controls.tsv: 6 FAIL, 1 PASS (exit 1). Classification of each row:

| Row | Observed | Classification |
|---|---|---|
| actenon-kernel 1.2.1 (PyPI) vs current verifier vectors | FAIL (14 failed) | VALID control: E1-E5 edge-binding/revocation vectors fail on the released kernel. |
| @actenon/verifier-sdk (npm) | FAIL (E404) | VALID control: not published. |
| @actenon/protocol-types, @actenon/sdk plain-node import | FAIL | **VACUOUS — HARNESS DEFECT.** `npm init -y` refused the work directory name `imp-@actenon-…` ("Invalid name"); the packages were never installed. Not counted. Fixed in the script (sanitised directory names); rerun as run 2. |
| sdk-go v1.0.0 (proxy.golang.org) vs current vectors via public API | FAIL (`undefined: verifier.RevocationChecker`) | VALID control: v1.0.0's public API cannot express protocol 13 revocation. |
| actenon-verifier-sdk (crates.io) | FAIL (no matching package) | VALID control: not published. |
| actenon-protocol 1.3.0 (PyPI) vs release-tag runner | PASS | **CRITERION DEFECT (the expectation, not the artefact).** Protocol 1.4.0 deliberately changes no wire field, schema or canonicalisation, and the tag's runner reads the archive's own `schemas/`, so 1.3.0 passing is correct. This row is kept, reclassified as non-discriminating. Control v2 targets 1.4.0's actual change: the standalone runner outside a checkout, with only the installed package's schemas (1.3.0 lacked `execution_result.v1.json` / `boundary_manifest.v1.json`). |
