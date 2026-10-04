# Cryptographic review status

> **Status: no external cryptographic review has been performed.**
> **Automated static analysis (bandit) has been run; results below.**

This document records what needs external review, where the review
entry points are, and what the current self-review covers. It exists
because an external evaluator correctly noted that
[`AUDIT_RESPONSES.md`](AUDIT_RESPONSES.md) — which records our own
answers to our own diligence questions — is good practice but is not
a substitute for an independent pair of eyes on the crypto surface.

## Automated static analysis

**Tool:** [bandit](https://github.com/PyCQA/bandit) 1.9.4 (Python AST
static analysis security tool).

**Scope:** `actenon/proof/` and `actenon/replay/` — the cryptographic
and replay-prevention surfaces.

**Date:** 2026-07-25

**Results:** 3 findings, all assessed as **false positives**:

| # | Severity | Confidence | Test ID | File:Line | Finding | Assessment |
|---|---|---|---|---|---|---|
| 1 | LOW | MEDIUM | B105 | `actenon/proof/signers/local.py:17` | Possible hardcoded password: `ACTENON_LOCAL_HMAC_SECRET` | **False positive.** This is the *environment variable name* (`ACTENON_LOCAL_HMAC_SECRET`), not a password value. The actual secret at line 16 (`LOCAL_PROOF_SECRET = b"actenon-local-proof-secret-v1"`) is explicitly public and the code warns it is dev-only: "The default local proof secret is public; production must use asymmetric signers." |
| 2 | MEDIUM | HIGH | B310 | `actenon/proof/signers/proof_seal.py:84` | Audit url open for permitted schemes | **False positive.** The `urlopen` call is to a configured proof-seal service URL (not user-controlled). The URL scheme is validated by the proof-seal client configuration. |
| 3 | MEDIUM | LOW | B608 | `actenon/replay/dbapi.py:417` | Possible SQL injection via string-based query construction | **False positive.** The query uses a parameterized placeholder (`?`) for the user-controlled `replay_key` value. `SELECT_FIELDS` is a module-level constant, not user input. No injection vector. |

**Addendum 2026-10-02 (production-readiness phase 2).** The assessment of
finding #2 above was wrong. `HttpProofSealClient` did not validate the URL
scheme, so a `file://` or custom-scheme endpoint reached `urlopen`. The
endpoint is operator configuration, not request input, so the impact was low.
Now `actenon.core.http_url.require_http_url` rejects every scheme but
http/https at construction, for `HttpProofSealClient`,
`HttpExecutionGraphClient` and the local runtime's status probe. The new test
is `tests/unit/test_proof_seal_client.py::HttpProofSealClientSchemeTests`,
and its before-state is in `evidence/release/phase2/tests/proof-seal-scheme-*`.

From this date bandit scans all of `actenon/` and fails CI on any unsuppressed
finding of medium severity or above. Each suppression is an inline
`# nosec <id>` on the flagged line, with its justification:

| File:line | Test | Justification |
|---|---|---|
| `actenon/proof/signers/proof_seal.py` (`urlopen`) | B310 | http(s) only: `require_http_url` at construction |
| `actenon/execution_graph.py` (`urlopen`) | B310 | http(s) only: `require_http_url` at construction |
| `actenon/local_runtime.py` (`_http_json_status`) | B310 | http(s) only: `require_http_url` before the request |
| `actenon/replay/dbapi.py` (`_select_row`) | B608 | `SELECT_FIELDS` is a module constant; `replay_key` is a bound parameter |
| `actenon/escrow/sqlite.py` (`_select_row`) | B608 | `SELECT_FIELDS` is a module constant; `escrow_id` is a bound parameter |

Finding #1 (B105, low severity) is below the gate and remains as assessed.

**Command to reproduce:**
```bash
bandit -r actenon/proof/ actenon/replay/ -f json -o bandit-results.json
```

**Limitations of automated analysis:**
- Bandit is an AST-based tool; it cannot verify cryptographic correctness
  (e.g., whether canonicalisation is RFC 8785-conformant, whether
  constant-time comparisons are actually constant-time, whether the
  replay atomicity holds under concurrent access).
- Bandit cannot detect logic errors in the key-lifecycle state machine.
- Bandit cannot verify cross-language canonicalisation equivalence.
- **Automated analysis is not a substitute for manual cryptographic review.**

## What has been self-reviewed

The kernel's [`AUDIT_RESPONSES.md`](AUDIT_RESPONSES.md) records
self-review across these vectors:

| Vector | Self-review status | Where |
|---|---|---|
| Canonicalisation (payload tampering) | Addressed | `actenon/proof/canonical.py` |
| Clock skew (NTP drift) | Addressed | `actenon/proof/service.py` |
| Concurrency replay (double-spend) | Addressed (32-worker race verified) | `actenon/replay/` |
| Key lifecycle (5-state machine) | Addressed | `actenon/proof/signers/key_lifecycle.py` |
| Signature verification (Ed25519 + HMAC) | Addressed | `actenon/proof/signers/` |
| Refusal oracle (two-layer disclosure) | Addressed | `actenon/proof/refusal_messages.py` |

**Self-review is not external review.** The self-review answers were
written by the same engineers who wrote the code. An external reviewer
would check whether the answers are correct, not just whether they
exist.

## What needs external review

The following surfaces handle cryptographic correctness. Each is listed
with the exact files a reviewer should read and the specific questions
they should answer.

### 1. Canonicalisation — `ACTENON-JCS-STRICT-1`

**Files:**
- [`actenon/proof/canonical.py`](../actenon/proof/canonical.py)
- [`canonicalisation/ACTENON-JCS-STRICT-1.md`](../../canonicalisation/ACTENON-JCS-STRICT-1.md) (spec)
- [`conformance/vectors/canonicalisation/`](../../conformance/vectors/canonicalisation/) (test vectors)

**Questions for a reviewer:**
- Is the RFC 8785 subset correctly implemented? Are there edge cases
  (Unicode normalisation, surrogate pairs, deeply nested structures)
  where the implementation diverges from the spec?
- Is the float-rejection policy sound? Does it close all
  parser-differential vectors, or are there non-float numeric types
  (e.g., integers near 2^53, BigInt, Decimal) that could cause
  cross-language divergence?
- Is the duplicate-key rejection enforced before canonicalisation, not
  after? Could a maliciously crafted JSON document with duplicate keys
  produce a different canonical form across implementations?
- Are the 1 MiB output limit and 32-level depth limit sufficient to
  prevent resource-exhaustion attacks?

### 2. Replay atomicity

**Files:**
- [`actenon/replay/service.py`](../actenon/replay/service.py)
- [`actenon/replay/sqlite.py`](../actenon/replay/sqlite.py)
- [`actenon/replay/postgres.py`](../actenon/replay/postgres.py)
- [`actenon/replay/base.py`](../actenon/replay/base.py)

**Questions for a reviewer:**
- Is the claim-once operation truly atomic under the SQLite and
  Postgres backends? Is there a TOCTOU window between the check and
  the write?
- Does the replay store correctly handle crash recovery? If a worker
  claims a proof and then crashes before emitting a receipt, is the
  proof permanently consumed or can it be retried?
- For swarm deployments with a shared durable store: is the
  distributed locking correct? Could two workers in different regions
  both claim the same proof during a network partition?
- Is the replay key derivation correct? Could two different
  (action, target, audience, nonce) tuples produce the same replay
  key?

### 3. Key lifecycle

**Files:**
- [`actenon/proof/signers/key_lifecycle.py`](../actenon/proof/signers/key_lifecycle.py)
- [`actenon/proof/signers/aws_kms.py`](../actenon/proof/signers/aws_kms.py)
- [`actenon/proof/signers/local.py`](../actenon/proof/signers/local.py)
- [`actenon/proof/signers/hsm.py`](../actenon/proof/signers/hsm.py)

**Questions for a reviewer:**
- Is the 5-state lifecycle (active / retired / suspended / revoked /
  hard_revoked) correctly enforced? Can a suspended key still sign?
  Can a retired key still verify?
- Is the hard-revocation + external-anchor recovery path sound? Can a
  hard-revoked key's historical artefacts be verified without trusting
  the revoking party's honesty about the compromise date?
- Is the KMS backend's key-rotation logic correct? Does it leave a
  window where a key is neither in KMS nor locally cached?
- Are constant-time comparisons used everywhere a secret or signature
  is compared?

### 4. Attestation envelopes

**Files:**
- [`spec/outcome-attestation/SPEC.md`](../spec/outcome-attestation/SPEC.md)
- [`docs/REVOCATION_AND_RECEIPT_DURABILITY.md`](REVOCATION_AND_RECEIPT_DURABILITY.md)

**Questions for a reviewer:**
- Is the v2alpha1 attestation envelope's signature binding correct?
  Could an attacker strip the attestation and present the inner
  receipt as if it were independently signed?
- Is the external-anchor recovery path for hard-revoked keys sound?
  Could an attacker forge a historical artefact by backdating the
  anchor?
- Is the attestation's key lifecycle separate from the proof-signing
  key lifecycle? If not, could compromising the attestation key
  compromise proof verification?

## What this is not

This document is not:
- A security audit. No external auditor has reviewed this code.
- A vulnerability disclosure. We are not aware of specific
  vulnerabilities in the surfaces listed above.
- A substitute for adoption-stage diligence. Anyone deploying Actenon
  in production should commission their own review of the surfaces
  relevant to their deployment.

## How to get a review done

If you are a security researcher interested in reviewing the Actenon
crypto surface:

1. Read [`SCOPE_AND_GUARANTEES.md`](SCOPE_AND_GUARANTEES.md) first to
   understand what the kernel claims to guarantee.
2. Read [`AUDIT_RESPONSES.md`](AUDIT_RESPONSES.md) to see the
   self-review already done.
3. Use the file pointers above to navigate to each surface.
4. File findings in [GitHub Security Advisories](https://github.com/Actenon/actenon-kernel/security/advisories/new) or email
   security@actenon.org.

We welcome external review and will publish findings (with credit,
anonymised if preferred) in this document.
