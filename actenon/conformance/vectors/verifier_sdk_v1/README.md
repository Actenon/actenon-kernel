# Verifier SDK Conformance Vectors v1

These deterministic vectors are the shared verifier-edge contract for the
Python, TypeScript, Go, and Rust SDKs.

Every SDK reads the same `cases.json`, `action_intent.json`, and `pccb.json`
files. The cases cover exact-action binding, audience, scope, tenant, subject,
target, action hash, signature validation, and clock-skew boundaries.

`timestamp_cases.json` adds proofs minted by the kernel today: the
`ACTENON-JCS-STRICT-1` action-hash label and fractional-second timestamps
(`.500000`, written in the intent as `.500` and in `not_before` with a
`+00:00` offset, and `.123456`), plus microsecond window boundaries. Every SDK
must re-serialise each timestamp exactly as the Python reference does before
hashing and signature verification — UTC, `Z`, and six fractional digits only
when the microsecond is non-zero (finer digits truncated) — and compare
`not_before` / `expires_at` at microsecond precision.

Refused cases assert both the stable `reason_code` and the public-safe message.
Messages intentionally omit supplied identifiers, raw signatures, digests,
credentials, exception text, and trust-store internals.

Run all SDK vector runners:

```bash
bash scripts/verify_sdk_conformance.sh
```
