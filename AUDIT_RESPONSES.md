# Audit Responses

This document records how the Actenon kernel addresses common system-level security concerns raised during technical review. Each item names the threat, the implementation that addresses it, and where to verify it in the source.

These responses concern the open kernel's enforcement and verification surface. They are not a substitute for an independent third-party security audit; see `SECURITY.md` and `docs/SCOPE_AND_GUARANTEES.md` for the exact boundaries of what the kernel does and does not guarantee.

## Summary

| Diligence vector | Threat | Implementation | Status |
|---|---|---|---|
| Payload tampering | Whitespace or key-ordering changes used to bypass signature/hash checks | Strict RFC 8785 (JCS) canonicalization; floating-point values rejected; object keys must be strings | Addressed |
| Clock drift | NTP skew across edge workers causing premature refusal of valid proofs or acceptance of expired ones | Configurable, validated `clock_skew_tolerance` enforced on `not_before` and `expires_at`; strict (zero) by default | Addressed |
| Concurrency replay | Multiple workers in a distributed swarm racing to execute the same proof ("double spend") | Atomic transactional claim against a unique `replay_key` in the durable store, plus a mutation lock and a monotonicity assertion | Addressed (verified under a 32-worker concurrency race) |

## 1. Canonicalization — payload tampering

**Concern.** If a verifier serializes the action payload loosely before hashing or signature checking, an attacker (or simple cross-language key reordering) could produce semantically identical payloads that hash differently, causing valid requests to fail or, worse, creating ambiguity an attacker could exploit.

**Implementation.** The kernel canonicalizes action payloads using RFC 8785 JSON Canonicalization Scheme (JCS) before hashing. Object keys are canonically ordered, object keys must be strings, and floating-point values are rejected outright because they do not canonicalize deterministically across platforms. This means the action hash is stable regardless of incoming whitespace or key order, and ambiguous numeric representations are refused rather than silently accepted.

**Where to verify.** `actenon/proof/canonical.py` (canonicalization and the action-hash input builder in `actenon/proof/service.py`). The action-hash algorithm and canonicalization scheme are also recorded on every receipt (`action_hash.algorithm = sha-256`, `action_hash.canonicalization = RFC8785-JCS`).

**Adopter note.** Because floats are rejected, model monetary and quantity values as integers (for example, minor currency units / micrograms) or strings, not floats.

## 2. Clock skew — clock drift across edge workers

**Concern.** Edge gates running on different hosts can experience NTP drift. Without a defined tolerance, workers may prematurely refuse still-valid proofs, or accept slightly expired ones, in a way that is silent and inconsistent across the fleet.

**Implementation.** Proof validity-window verification applies a configurable `clock_skew_tolerance` to both the `not_before` and `expires_at` checks. The tolerance is validated to be non-negative and defaults to strict (zero) skew, so any tolerance is an explicit, auditable choice by the adopter rather than a hidden default. Behavior at the window boundaries is covered by the conformance vectors.

**Where to verify.** `actenon/proof/service.py` (the `clock_skew_tolerance` field, its validation, and its application to `not_before` / `expires_at`); `actenon/conformance/vectors/verifier_sdk_v1/` for the boundary cases.

## 3. Replay store atomicity — concurrency / double-spend

**Concern.** In a distributed multi-agent deployment, several workers may concurrently attempt to execute the same proof. A naive check-then-write replay check has a race window in which more than one worker can pass the check and execute, producing a double side effect (for example, a double payment).

**Implementation.** Single-use is enforced by an atomic claim in the durable replay store: the claim is a transactional `INSERT` against a unique `replay_key`, so a duplicate claim violates the uniqueness constraint and fails rather than racing. The durable store additionally takes a mutation lock around the claim transaction and asserts store monotonicity (so a store rolled back to an earlier state is detectable). This is a claim-once operation, not check-then-write.

Cross-worker single-use requires the workers to share one durable replay store (SQLite for single-node, Postgres for multi-node / shared boundaries). With per-process in-memory stores, single-use is per-process only — this is documented as an operational requirement.

**Where to verify.** `actenon/replay/dbapi.py` and `actenon/replay/postgres.py` (`claim_once`, the unique-key insert, the mutation lock, the monotonicity assertion); `actenon/replay/base.py` for the claim lifecycle (`claimed` / `consumed` / `released` / `expired`); `MULTI_AGENT_EXECUTION_MODEL.md` for the shared-store requirement.

**Verification.** Under a concurrency test in which many workers race the same proof against one shared durable store, exactly one execution succeeds and the remainder are refused with a duplicate-replay refusal, with a single recorded side effect.

## What these responses do not claim

These responses describe enforcement and verification behavior in the open kernel. They do not assert:

- that upstream policy or approvals were correct;
- that a compromised issuer or signer did not mint a valid proof for a wrong action;
- production key custody, hosted transparency, or an independent third-party audit.

See `KERNEL_GUARANTEES.md`, `THREAT_MODEL.md`, and `docs/SCOPE_AND_GUARANTEES.md` for the full statement of guarantees and limits.
