# Verifier SDK Conformance Vectors v1

These deterministic vectors are the shared verifier-edge contract for the
Python, TypeScript, Go, and Rust SDKs.

Every SDK reads the same `cases.json`, `action_intent.json`, and `pccb.json`
files. The cases cover exact-action binding, audience, scope, tenant, subject,
target, action hash, signature validation, and clock-skew boundaries.

Refused cases assert both the stable `reason_code` and the public-safe message.
Messages intentionally omit supplied identifiers, raw signatures, digests,
credentials, exception text, and trust-store internals.

Run all SDK vector runners:

```bash
bash scripts/verify_sdk_conformance.sh
```
