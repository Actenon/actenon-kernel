# Canonical wire repair candidate — not a release

Base Kernel: `9dd6af89622f070e3131c39d335be44e3f30149d`.
Normative Protocol and dependency pin: `8e5bc9e342f694767508bae9a392749c6a8df2cc` (source 1.6.0 / wire 1.3, unpublished candidate).

## Contract correction

Protocol owns `ACTENON-JCS-STRICT-1`: canonical root depth zero, maximum 32.
Kernel had conflated the separate 128-level transport envelope with canonical
signing depth. Both accepted canonicalization labels use this implementation;
the legacy `RFC8785-JCS` label is not a distinct, wider signing profile. Original
128-level fixtures and earlier evidence are retained. The versioned
`fixtures/protocol_canonicalisation/legacy-expectation-correction.json` records
the two old 120/124-level signed interop cases which now refuse. No prior refusal
becomes an acceptance. `legacy-proof-replay-after.json` records the actual
Kernel SDK refusal for those unchanged proofs.

The TypeScript raw parser dropped literal `__proto__` parameters through
`Object.assign`. `before-prototype-parameter-verified.log` reproduces an actual
`verifyJSON` acceptance after adding that parameter to an already-signed intent
and PCCB. Object spread now preserves the member, so the signed mutation is
refused. `before-prototype-parameter.log` is an earlier harness error, not an
engine finding.

The frozen 26-case wire corpus records raw bytes/hashes, expected decisions and
exact canonical bytes/hashes derived from Protocol. Python had accepted UTF-16
and UTF-8 BOM bytes; its ingress now requires strict UTF-8. TypeScript used
UTF-16 key ordering; it now orders by UTF-8 bytes. The TypeScript verifier still
supports safe JavaScript integers only; three valid larger integers are explicit
SAFE_REJECT results. This is not universal numeric parity.

## Reproduction and actual results

- `PIP_CONSTRAINT="$PWD/.github/candidate-constraints.txt" PYTHONPATH=. python -m pytest -q -rs`: **973 passed, 5 existing skips, 323 subtests passed** (`full-after-pinned.log/xml`). Three skips require the real PostgreSQL CI job; two existing reconciliation placeholders remain unimplemented.
- In `sdk/typescript`, `npm ci; npm test; npm run check; npm run build`: **96 tests passed**, typecheck/build passed. `typescript-full-parity-after.log` is the final suite.
- `uv lock --check`: resolves the exact Protocol pin. All active pyproject, lock and CI constraint pins match.
- Set `ACTENON_PARITY_RESULTS` when running the raw-corpus tests to write every case's decision and canonical hash. `raw-corpus-after.json` and `typescript-raw-after.json` preserve this run.

`full-after.log` preserves the earlier 971-pass run with a clean-wheel install
failure when local candidate constraints were omitted. `typescript-raw-before.log`
is an incorrect-working-directory harness invocation; the corrected invocation
is `typescript-raw-before-verified.log`. That corrected log also contained three
safe integer rejections whose profile label in the runner was misspelled; the
UTF-8 ordering mismatch in that log is the actual implementation finding.

Scope: raw JSON canonicalization plus the specific signed-parameter regression.
This evidence does not close all programme B tests, protected execution,
external-agent usefulness, release artifacts, or independent reproduction.
No merge, tag, package publication or release is performed by this candidate.
