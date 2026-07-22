# Actenon Kernel

> The open verifier. Defines what a valid proof is. Verifies proofs; issues nothing; enforces nothing.

## What this is

The Kernel is the **trust anchor** of the Actenon ecosystem. It is:

- **Independent** — runs without Permit, Cloud, or Scan.
- **Stateless** (mostly) — the verifier is stateless; the executor holds replay state.
- **Conformance-locked** — 51 conformance vectors define exactly what "a valid PCCB" means.
- **Multi-language** — Go, Rust, TypeScript SDKs all conform to the same vectors.

## What the Kernel does

```
Action intent  →  PCCBMinter.mint()  →  PCCB (proof)
                                        ↓
Action intent  →  PCCBVerifier.verify()  →  ✓ or ProofVerificationError
                                        ↓
ProtectedExecutor  →  replay check  →  credential acquisition  →  handler execution  →  receipt
```

## The 15-step verification pipeline

| Phase | Steps | What's checked |
|---|---|---|
| **A: Pre-auth** | 1-5 | Structure, protocol version, canonicalisation, key resolution, signature |
| **B: Post-auth** | 6-13 | Time validity, audience, boundary, target, action, parameter digest, authority, revocation |
| **C: Stateful** | 14-15 | Replay (deferred to executor), execution eligibility |

Pre-auth failures collapse to `PROOF_INVALID` (public-safe). Post-auth failures disclose the specific code (`AUDIENCE_MISMATCH`, `ACTION_MISMATCH`, etc.) only to trusted callers.

## Install

```bash
pip install actenon-kernel
```

## Use as a verifier

```python
from actenon.proof import PCCBVerifier, build_local_proof_signer

signer = build_local_proof_signer()  # pilot: local Ed25519
verifier = PCCBVerifier(signer=signer)

# Verify a proof (raises ProofVerificationError on any failure)
verifier.verify(intent, pccb, context)
```

## Use as a boundary verifier (Boundary Kit)

```python
from actenon.boundary import BoundaryVerifier, BoundaryVerificationRequest

verifier = BoundaryVerifier()
result = verifier.verify_boundary(BoundaryVerificationRequest(
    proof_token="v1.eyJ...",
    action_type="payment.refund",
    action_hash="abc123...",
    audience="service:payments",
))
# result.valid → True/False
# result.refusal_code → "PROOF_INVALID" | "REPLAY_DETECTED" | ""
# result.proof_id → "proof_..." (for receipt)
```

## What the Kernel does NOT do

- Issue grants or proofs (that's Permit's job)
- Resolve credentials (that's the broker's job)
- Execute provider calls (that's the adapter's job)
- Manage tenants (that's Cloud's job)

## Signing backends

| Backend | Status | Use case |
|---|---|---|
| `development_local_hmac` | Dev-only | Local testing (NOT for production) |
| `pilot_local_eddsa` | Pilot-ready | Real Ed25519, key on disk. Requires `ACTENON_ALLOW_PILOT_LOCAL_EDDSA_IN_PRODUCTION=1` |
| `external_managed` | Interface ready | AWS KMS / GCP KMS / HSM (deployment wires the provider) |

## Conformance

```bash
python -m actenon.cli conformance run --require-complete
# 51 tests pass. Mark: Actenon Verified (Conformance 1.0.0)
```

## Independence

The Kernel depends only on `actenon-protocol`. It does NOT depend on Permit, Cloud, or Scan. A third-party proof that conforms to the Kernel's conformance vectors will be accepted by the Kernel verifier.

## License

Apache-2.0
