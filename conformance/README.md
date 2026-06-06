# Conformance Package

This directory is the publishable documentation surface for compatibility targets in the open kernel.

## What This Package Is For

Use this package when you want to understand or run the repository's public compatibility target for:

- Action Intent
- PCCB
- Protected Endpoint
- Replay
- Receipt
- Refusal
- Outcome Attestation
- Receipt Counter-Signature
- Transparency Log Proofs

The central behavioral compatibility surface is the Protected Endpoint. The suite is built around whether the execution edge verifies proof, enforces replay when claimed, and refuses execution before side effects when the public rules fail.

Outcome Attestation coverage is opt-in and additive: it validates signed envelopes around v1 Receipt and Refusal artifacts without changing those v1 payload semantics.

Receipt Counter-Signature coverage is verifier-only: it validates a witness
signature over a Receipt digest against a pinned public key set, including
historical key IDs.

Transparency Log coverage is verifier-only: it validates signed checkpoints,
Merkle inclusion, append-only consistency, monitor updates, and rejection of
counter-signatures whose digest is not included in the verified checkpoint.

## Contents

- [MATRIX.md](MATRIX.md): coverage matrix for the public conformance suite
- [../docs/guides/COMPATIBILITY_FAQ.md](../docs/guides/COMPATIBILITY_FAQ.md): short answers for public compatibility and claim-boundary questions

## Fastest Commands

```bash
actenon conformance run
```

```bash
python3 -m unittest discover -s tests/conformance -p 'test_*.py'
```

Broader public-release gate:

```bash
make public-verify
```

For most external implementers, `actenon conformance run` is the fastest path to a meaningful compatibility signal. `make public-verify` delegates to `scripts/verify_release_gate.sh` and is the full release blocker for this distribution.

## Claim Boundary

A passing result supports compatibility claims only for the repository's active public surfaces.

It does not support compatibility claims for reserved surfaces such as Reconciliation or Policy Bundle, and it does not imply hosted or paid-layer compatibility.

It also does not imply that every route in a larger deployment is protected; compatibility claims should stay scoped to the implemented active public surfaces.

## Reference Documents

- [../CONFORMANCE.md](../CONFORMANCE.md)
- [../docs/guides/CONFORMANCE_TESTS_GUIDE.md](../docs/guides/CONFORMANCE_TESTS_GUIDE.md)
- [../docs/reference/EXECUTION_SEMANTICS.md](../docs/reference/EXECUTION_SEMANTICS.md)
