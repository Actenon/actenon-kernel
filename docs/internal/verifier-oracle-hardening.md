# Verifier Oracle-Hardening Design

> **Phase 2A design note.** This document specifies the security
> objective, the refusal-disclosure policy, and the implementation plan
> for hardening the kernel's `PCCBVerifier` against proof-forging oracles.
> It does NOT implement the fix - only the tests and this design note ship
> in Phase 2A.
>
> **Central invariant preserved:** No valid proof, no execution.

## The Problem

The current `PCCBVerifier.verify()` (in `actenon/proof/service.py:117-208`)
performs 9 semantic checks (time, audience, scope, intent, tenant,
subject, action, target, action_hash) BEFORE checking the signature at
line 203. Each semantic check raises a distinct `ProofVerificationError`
with a distinct `refusal_code` (e.g., `AUDIENCE_MISMATCH`,
`TENANT_MISMATCH`, `TARGET_MISMATCH`, `PROOF_EXPIRED`).

A forger who presents a structurally-valid-but-wrong-signature PCCB with
field mutations learns **which** field is wrong without ever needing to
forge the signature. The current `public_proof_refusal_message` function
(`actenon/proof/refusal_messages.py`) makes this worse by emitting a
distinct human-readable message per code that confirms which check
failed.

**The oracle:** An attacker can probe the verifier field-by-field,
revealing the exact bound action parameters that a valid proof must
carry, before obtaining a valid signature.

## Security Objective

Unauthenticated or invalidly-signed forged proofs must not use detailed
public refusal codes as a field-by-field semantic oracle.

The verifier must perform only the **minimum safe work needed for
authentication** before signature verification:

1. bounded structural parsing
2. total input-size checks
3. JSON-depth checks
4. strict type and encoding validation
5. required-field presence checks needed to identify the verification key
6. safe issuer and key resolution
7. canonicalisation of the unsigned proof
8. signature verification

**Detailed semantic checks must occur only after the proof is
cryptographically authentic.**

Post-authentication semantic checks (may include):
- time bounds (`not_before`, `expires_at`)
- audience
- scope
- capability
- intent identifier
- tenant
- subject
- action
- target
- action hash
- policy constraints

## Refusal-Disclosure Policy

Three semantic modes govern how much detail the verifier exposes in its
public refusal result:

### `public_generic` (default, production-safe)

- Invalidly-signed or unauthenticated proof returns ONE generic public
  result.
- Preferred code: `PROOF_INVALID`.
- Public output must NOT reveal which signed field was wrong.
- Forged field values must NOT appear in public receipts, API responses,
  caller-visible exceptions, or public error metadata.
- Receipts emitted for forged-proof refusals must NOT include the
  attacker-supplied field values; only the structural refusal reason
  (`PROOF_INVALID`) is recorded.

### `trusted_detailed` (post-authentication, default for validly-signed proofs)

- After cryptographic authenticity is established, existing detailed
  semantic refusal codes remain available.
- Examples: `AUDIENCE_MISMATCH`, `TENANT_MISMATCH`, `ACTION_MISMATCH`,
  `TARGET_MISMATCH`, `PROOF_EXPIRED`.
- A validly-signed proof with the wrong audience still returns
  `AUDIENCE_MISMATCH` - because the issuer is authentic, the operator
  is allowed to know which policy check failed.

### `local_debug` (development only - fail-closed)

- Full diagnostics are allowed ONLY in explicit local development.
- It must be IMPOSSIBLE to enable accidentally in a production-like
  environment.
- Fail-closed environment guard: `ACTENON_ENV=production` (or any
  non-`local`/`dev`/`test` environment) refuses `local_debug` mode at
  verifier construction time with a hard `ValueError`.
- When `local_debug` is active, the verifier MAY emit granular
  pre-signature refusal codes (the current behaviour) for debugging.

## Semantic Distinction (Preserved)

The current refusal-code taxonomy distinguishes:

- **`INTENT_MISMATCH`** - the signed `intent_id` differs.
- **`ACTION_MISMATCH`** - the bound action or action parameters differ.
- **`TARGET_MISMATCH`** - the target differs.

These distinctions MUST be preserved for **validly-signed** proofs
(post-authentication). They are collapsed to `PROOF_INVALID` for
**invalidly-signed** proofs (pre-authentication).

## Compatibility Handling

Existing public refusal codes are NOT renamed. The change is:

1. **Pre-authentication failures** (forged/unauthenticated) collapse
   to `PROOF_INVALID`. This is a NEW code; existing codes remain.
2. **Post-authentication failures** (validly-signed but policy-denied)
   keep existing codes unchanged (`AUDIENCE_MISMATCH`,
   `TENANT_MISMATCH`, `ACTION_MISMATCH`, `TARGET_MISMATCH`,
   `PROOF_EXPIRED`, etc.).
3. The existing `FailureCode` taxonomy (`actenon/outcomes.py`) maps
   `PROOF_INVALID` to `FailureCode.SIGNATURE_INVALID` (the existing
   pre-authentication failure code). No taxonomy change required.
4. The `public_proof_refusal_message` function gains a `PROOF_INVALID`
   entry: `"The proof could not be verified."` - generic, no field hint.
5. Callers that inspect `refusal_code` for specific codes continue to
   work for validly-signed proofs. Callers that previously inspected
   pre-authentication codes (e.g., `SIGNATURE_INVALID`) will now see
   `PROOF_INVALID` for forged proofs - a strict narrowing of detail,
   not a renaming.

## What Does NOT Change

- SSRF protection in well-known key resolver (unchanged).
- Constant-time signature comparison (unchanged).
- Input size limits (1 MB raw, 128 depth, 1 MB canonicalised - unchanged).
- Conformance suite vectors (unchanged - they test validly-signed
  proofs and structural refusals, which are not affected).
- The `FailureCode` taxonomy and `refusal_code_to_failure_code` mapping
  (unchanged - `PROOF_INVALID` maps to `SIGNATURE_INVALID`).
- The 9 semantic checks themselves (reordered, not removed - they run
  after signature verification for forged-proof safety).

## Implementation Plan (Phase 2B - not in this commit)

1. Add a `VerifierDisclosureMode` enum to `actenon/proof/service.py`:
   `PUBLIC_GENERIC`, `TRUSTED_DETAILED`, `LOCAL_DEBUG`.
2. `PCCBVerifier.__init__` accepts a `disclosure_mode` parameter
   defaulting to `PUBLIC_GENERIC`. Construction with `LOCAL_DEBUG` in
   a production-like environment raises `ValueError`.
3. Restructure `verify()` into two phases:
   - **Phase A (pre-authentication):** structural parse, size/depth
     checks, type validation, required-field presence for key
     resolution, issuer/key resolution, canonicalisation, signature
     verification. Any failure here returns `PROOF_INVALID` in
     `public_generic` mode.
   - **Phase B (post-authentication):** the 9 semantic checks in their
     current order. Failures here return the existing detailed codes
     (in `trusted_detailed` mode) or `PROOF_INVALID` (in
     `public_generic` mode - the proof was authentic but the action
     didn't match; the operator still gets `PROOF_INVALID` because the
     forged field values must not be echoed).
4. Add `PROOF_INVALID` to `public_proof_refusal_message` and to
   `_REFUSAL_CODE_MAP` (maps to `FailureCode.SIGNATURE_INVALID`).
5. Receipts emitted for pre-authentication refusals must NOT include
   attacker-supplied field values. The `RefusalFactory` will be taught
   to redact forged-proof details.

## Why Pre-Authentication Detail is an Oracle

Consider an attacker who has stolen the structure of a valid PCCB but
does not have the issuer's signing key. They want to learn the exact
audience, tenant, action, and target that a valid proof must carry so
they can attempt to obtain a forged proof from a compromised-but-logged
issuer.

Under the current verifier:

| Probe | Current response | Leaked information |
|---|---|---|
| Wrong audience | `AUDIENCE_MISMATCH` | "audience is wrong, fix it" |
| Wrong tenant | `TENANT_MISMATCH` | "tenant is wrong, fix it" |
| Wrong target | `TARGET_MISMATCH` | "target is wrong, fix it" |
| Expired | `PROOF_EXPIRED` | "timestamp is wrong, fix it" |

Each probe reveals one field. After 4-9 probes, the attacker knows the
exact bound parameters without ever presenting a valid signature.

Under the hardened verifier, all of these return `PROOF_INVALID` with
no field hint. The attacker cannot distinguish "wrong audience" from
"wrong signature" - both are `PROOF_INVALID`.

## Test Coverage (Phase 2A - this commit)

The 11 regression tests in `tests/security/test_verifier_oracle_hardening.py`
cover:

1. forged proof with wrong audience returns `PROOF_INVALID` (not `AUDIENCE_MISMATCH`)
2. forged proof with wrong tenant returns `PROOF_INVALID` (not `TENANT_MISMATCH`)
3. forged proof with wrong target returns `PROOF_INVALID` (not `TARGET_MISMATCH`)
4. forged proof with expired timestamp returns `PROOF_INVALID` (not `PROOF_EXPIRED`)
5. forged proof with several changed fields returns the same `PROOF_INVALID`
6. validly-signed audience mismatch returns `AUDIENCE_MISMATCH` (preserved)
7. validly-signed action mismatch returns `ACTION_MISMATCH` (preserved)
8. validly-signed target mismatch returns `TARGET_MISMATCH` (preserved)
9. internal diagnostics retain precise reasons (in `local_debug` mode)
10. public receipts exclude forged field values
11. `local_debug` mode cannot activate in a production-like environment

Tests 1-5 and 9-11 are expected to FAIL until Phase 2B implements the
hardening. Tests 6-8 are expected to PASS (they verify the
post-authentication semantic checks are preserved).
