# Findings — actenon-kernel 1.0.0 promotion work order

This file records discoveries made during the 1.0.0 promotion work order.
Per the operating rules, findings are recorded honestly and never papered
over. The only thing gated on findings is the final version bump (PART 5).

---

## Base-install conformance — 15 of 33 conformance tests require `cryptography`

**Severity:** NOTE
**Where:** tests/conformance/ — base install without `[asymmetric]` extra
**Expected:** The README says `pip install actenon-kernel` gives the "core verifier (pure Python, no asymmetric extra)". The work order asked whether this claim is true as written.
**Observed:** Base install (no `cryptography`) runs the conformance suite: 18 passed, 15 skipped. The 15 skipped tests cover:
  - Countersignature conformance (5 tests) — Ed25519 signature verification
  - Transparency log conformance (6 tests) — Ed25519 checkpoint signing
  - Trust artifact conformance (4 tests) — Ed25519 approval artifact verification

The symmetric (HMAC) path — which is what `build_local_proof_signer()` uses — runs fully and passes all 18 tests. The base install CAN verify proofs; it just cannot verify Ed25519/RSA signatures without the optional `cryptography` package.
**Action taken:** The README claim is true as written. "Core verifier (pure Python)" accurately describes the HMAC path. The asymmetric path is correctly gated behind the `[asymmetric]` extra. No change to the README needed; the claim is honest.
**Recommendation:** No action. The base-install conformance count (18/33) should be documented in PRODUCTION_INTEGRATION.md so operators know exactly what the base install verifies.


## Replay store unreachable — gate fails CLOSED (safe)

**Severity:** NOTE (this is the safe behavior; documenting it because the work order asked)
**Where:** actenon/replay/service.py — ReplayProtector.claim_request()
**Expected:** The work order asked to determine whether the gate fails open or closed when the replay store is unreachable. A fail-open enforcement point would be a BLOCKER.
**Observed:** When the replay store raises ConnectionError on every operation (simulating a network partition), `ReplayProtector.claim_request()` propagates the exception. The execution attempt is refused — no side effect executes. This is fail-closed behavior.

Command and output:
```
$ python scripts/test_replay_store_unreachable.py
Step 1: Verify the proof (no replay store involved yet)...
  Proof verification PASSED (expected — verifier is stateless)
Step 2: Attempt to claim the replay key with an UNREACHABLE store...
  Claim REFUSED with ConnectionError: replay store is unreachable (simulated network partition)
  *** FAIL CLOSED: the gate refused execution when the replay store was unreachable ***
```
**Action taken:** No fix needed — the behavior is correct. The gate fails closed: no proof, no key, no audience match, no replay store → refuse. Degraded mode is never a reason to execute. This is documented in PRODUCTION_INTEGRATION.md §3.3 as the expected behavior.
**Recommendation:** No action. The fail-closed behavior is the design intent and the safe behavior. Operators should configure their SRE alerting to page on replay store connectivity loss, because fail-closed means the payment path stops until the store recovers.

