# Fresh-consumer dry run 3 (harness development) — rehearsal-1 artefacts

Preserved as-is. Artefacts: rehearsal-1 (`../../../rehearsal/rehearsal-1/SHA256SUMS`), protocol tag archive of ed8904d.
37 steps, 3 FAIL, 1 N/A. Parity (`PARITY.json`): FAIL.

Defects found, with their classification:

| Finding | Class | Disposition |
|---|---|---|
| `protocol tag vectors match vectors.sha256` FAIL ×3 | HARNESS DEFECT | checked from `conformance/`; the lock's paths are relative to `conformance/vectors/` (as `scripts/check_vector_lock.py` reads it). Fixed in the harness. |
| Rust differential U=5 on EdDSA cases | HARNESS DEFECT | the preserved phase-1 runner gates Ed25519 behind cargo feature `ed25519` (as the Go runner uses `-tags ed25519`); the generated Cargo.toml omitted it. Fixed. |
| python-py310 differs from the reference on `time_fraction_short_form_in_intent`, `time_fraction_7_digits_in_intent` (REFUSE `SCHEMA_INVALID` vs ACCEPT) | PRODUCT DEFECT (actenon-kernel) | `parse_timestamp` delegates to `datetime.fromisoformat`, whose grammar differs between Python 3.10 and 3.11+. Not detected by CI: no shipped vector covers it. Addendum `differential/corpus-addendum-timestamp-grammar` frozen BEFORE the fix. |
| python-py310 permit steps N/A | DECLARED | actenon-permit `Requires-Python >=3.11`. |
