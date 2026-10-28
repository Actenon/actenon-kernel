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



## RESOLVED: base-install conformance — cryptography moved to base dependencies

**Supersedes:** "Base-install conformance — 15 of 33 conformance tests require
`cryptography`" (NOTE, 1.0.0 run)

**Why the original conclusion was wrong:** The finding defended the base
install by pointing at the symmetric HMAC path — "which is what
`build_local_proof_signer()` uses" — running fully. But Part 4 of the same
work order demoted `build_local_proof_signer()` from the quickstart as
development-only: it signs with a public test secret and is unfit for
production. The base install was therefore justified by reference to the one
path the same run had just labelled unusable for the real thing. Meanwhile
the reference broker (`actenon-permit`) declares `actenon-kernel[asymmetric]`
and mints Ed25519 proofs in production, so a third party running
`pip install actenon-kernel` got a verifier that could not verify the
artifacts this ecosystem actually produces. "The README claim is true as
written" was accurate and beside the point: the ecosystem's north-star claim
is that *any party can verify without trusting Actenon*, and that fails if
the default install cannot verify the real thing. The zero-dependency
property is genuinely valuable in `actenon-scan`, where the scanner must
install into a codebase that has adopted nothing; for a verifier, being
unable to verify costs more than a dependency does.

**Action taken:** `cryptography>=42` moved from the `[asymmetric]` extra into
`[project].dependencies` (kernel 1.1.0 — additive under the compatibility
promise). The `[asymmetric]` extra is retained for backward compatibility and
now restates the base dependency. The invariants CI job that previously
asserted cryptography is absent from a base install now asserts it is present
and hard-fails on any skipped conformance test. Install guidance across
README / QUICKSTART / boundary docs updated to present the base install as
the full verifier.

**Result:** Clean venv, `pip install actenon-kernel` (no extras): **33 of 33
conformance tests execute and pass, zero skips** (previously 18 passed / 15
skipped). A freshly minted Ed25519 receipt counter-signature verifies end to
end on the base install; WO-9 dependency-direction and clean-install closure
invariants unchanged.

---

## Coordinated ecosystem staging for `1.3.0` (2026-10-28 run)

**Severity:** NOTE — intentional staged bump across the topological DAG.
**Where:** `pyproject.toml` (`version = "1.3.0"`) and `scripts/check_version_coherence.py`
**Observed:** `1.3.0` was staged while `actenon-protocol` (`1.6.0`), `sdk-go`, `sdk-rust`, `actenon-permit` (`2.0.0rc1`), and `actenon-airlock` completed cross-repo conformance verification against `ACTENON-JCS-STRICT-1` and `ACTENON-EFFECT-1` before cutting public registry tags (`v1.3.0`).
**Action taken:** `scripts/check_version_coherence.py` checks `FINDINGS.md` as specified by its ASSERT C diagnostic when a staged bump awaits coordinated publication tags.

