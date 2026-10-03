# Cross-language parity — CANDIDATE-ARTIFACT PASS (rehearsal 3)

**Scope.** These are *candidate-artefact* results. The runners imported the installed rehearsal-3 artefacts:
the kernel wheel on Python 3.10, 3.11 and 3.12, the `@actenon/verifier-sdk` 0.2.0 npm tarball, the
`github.com/Actenon/sdk-go` v1.1.0 module and the `actenon-verifier-sdk` 0.2.0 crate. Each was resolved by
its normal package manager from a registry-protocol server (fresh-consumer/). This is **not** a
published-artefact result: that run happens after release (RELEASE-GRAPH.md step 6).

Evidence: `fresh-consumer/runs/rehearsal-3-final/PARITY.json`, `PARITY.txt`, and the per-language JSONL
files, produced by `fresh-consumer/parity.py`.

## Criteria (versioned, defined before the runs they judge)
- **v1** (phase 2, frozen): on `kernel_diff_v1` (179 cases) and the precision addendum (14), A = 0, U = 0,
  and every implementation's B set **and every row** (outcome and code) equal to its phase-2 FINAL candidate.
  The Python reference must equal the phase-2 FINAL reference on every interpreter.
- **v2** (2026-10-03, defined before the post-fix run): on the timestamp-grammar addendum (53 cases, frozen
  and committed in c84f7b4 before any implementation ran it), A = 0, U = 0, py3.10 rows = py3.12 rows, the
  reference = the a-priori RFC 3339 hint on every ACCEPT/REFUSE case, and a B only on a DEVIATION-labelled
  case or for go-sdk-strict.

**Result: PASS (v1 and v2).**

| Corpus | Implementation | cases | agree | A | B | C (code differs) | U |
|---|---|---|---|---|---|---|---|
| kernel_diff_v1 | TS @actenon/verifier-sdk 0.2.0 (`verifyJSON`) | 179 | 170 | **0** | 9 | 63 | **0** |
| kernel_diff_v1 | Go sdk-go v1.1.0, context decoded as `float64` | 179 | 133 | **0** | 46 | 57 | **0** |
| kernel_diff_v1 | Go sdk-go v1.1.0, context decoded with `UseNumber` | 179 | 174 | **0** | 5 | 56 | **0** |
| kernel_diff_v1 | Rust actenon-verifier-sdk 0.2.0 | 179 | 173 | **0** | 6 | 58 | **0** |
| precision addendum | all four | 14 | 14 | **0** | 0 | 1–14 | **0** |
| timestamp grammar | TS | 53 | 49 | **0** | 4 | 33 | **0** |
| timestamp grammar | Go float64 / UseNumber | 53 | 33 / 49 | **0** | 20 / 4 | 33 | **0** |
| timestamp grammar | Rust | 53 | 53 | **0** | 0 | 33 | **0** |

The Python reference (kernel 1.3.0) gives identical rows on Python 3.10, 3.11 and 3.12 for all three corpora,
and on the two frozen corpora it equals the phase-2 FINAL reference row for row.

## Every B (the implementation refuses what the reference accepts: fail closed), with justification

| B case(s) | Implementations | Why it is acceptable |
|---|---|---|
| `sig_padded_base64url`, `sig_std_base64_alphabet`, `sig_noncanonical_trailing_bits` | TS, Go, Rust | Non-canonical base64url signature encodings. The SDKs require the canonical encoding; the Python reference decodes leniently. The signature bytes are the same, so refusing loses nothing an honest issuer emits (issuers emit canonical base64url). |
| `unicode_bom_prefix` | TS, Go, Rust | A UTF-8 BOM before the intent JSON. RFC 8259 §8.1 says implementations MUST NOT add a BOM and MAY ignore one; the SDKs' strict parsers refuse it. |
| `time_pccb_space_separator`; timestamp-grammar `*_space_separator` | TS, Go | `2026-01-01 12:05:00Z`. RFC 3339 §5.6 NOTE leaves the space separator to applications. The reference and Rust accept it; TS and Go accept only `T`. |
| timestamp-grammar `*_lowercase_t` | TS, Go | RFC 3339 permits a lower-case `t`; the reference and Rust accept it, TS and Go do not. |
| `num_2p53`, `num_2p53_plus1`, `num_2p63`, `num_2p64_plus1` | TS | Integers at or beyond 2^53 cannot be represented exactly as JS numbers, so the TS SDK refuses them rather than compare a rounded value. |
| `num_2p64_plus1` | Rust | Beyond u64/i64; refused rather than rounded. |
| `canon_neg_zero_literal_text` | Rust | The text `-0`; Rust's strict number handling refuses it (`ACTION_MISMATCH`). |
| 41 further `PARAMETER_MISMATCH` cases (46 − 5) and 16 timestamp-grammar cases | Go with `float64` context only | The Go SDK documents that edge parameter constraints decoded as `float64` cannot be checked exactly and refuses them. Decoding the edge's own declaration with `json.Decoder.UseNumber` (the documented way) removes all of them. The UseNumber row is the comparison. |

No A: no implementation accepts any case the reference refuses, on any corpus.

## Go `UseNumber` comparison (preserved from phase 2)
Both Go variants run on every corpus: `diff*-go-sdk-strict.jsonl` (the phase-1 `float64` runner, frozen) and
`diff*-go-sdk-usenumber.jsonl` (phase-2 runner). Their rows equal the phase-2 FINAL rows for `e3649cd`.
sdk-go's only change since then (`8a87d6f`: refuse `,` fractional seconds) affects no case in the two frozen
corpora, and removes the one A that the timestamp addendum would otherwise have shown once the reference
became RFC-strict.

## Old releases (negative control)
The currently published artefacts fail the current checks (controls/PUBLISHED-CONTROL-REHEARSAL-3.json).
For example, kernel 1.2.1 fails 14 verifier-vector tests, and sdk-go v1.0.0's public API cannot express
revocation. The phase-1 record of released SDKs accepting 4–5 cases the reference refuses stays in
`../differential/COMPARE-phase1-and-released-results-vs-78efcf1-reference.txt`.
