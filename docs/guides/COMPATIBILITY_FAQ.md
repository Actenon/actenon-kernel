# Compatibility FAQ

## What does active v1 compatibility mean here?

It means compatibility with the repository's active public `/spec` surfaces only:

- Action Intent
- PCCB
- Protected Endpoint
- Replay
- Receipt
- Refusal

If a surface is reserved rather than active, it is not part of active v1 compatibility.

## What is the central behavioral compatibility surface?

The Protected Endpoint.

This repository's core claim is proof-bound consequential execution at the execution edge. Upstream approval or orchestration is not a substitute for protected-endpoint verification.

## What does a passing conformance run justify?

It justifies a scoped public claim that an implementation targets the Actenon Kernel active v1 compatibility surface and passes the public conformance suite for those active surfaces.

It does not justify claims about reserved surfaces, paid-layer behavior, provider-backed reconciliation or finality, issuer correctness, or adapter truthfulness.

## Can we claim compatibility with Reconciliation or Policy Bundle?

No.

Those names remain reserved public surfaces. They are not active v1 standards, and they are not public compatibility targets until a future version explicitly activates them.

## Does a passing run prove our whole production system is protected?

No.

A passing run supports claims only for the implemented paths that actually honor the active v1 public surface. If other production routes bypass protected-endpoint proof verification or replay enforcement, those routes are outside the justified claim.

## Are Receipt and Refusal cryptographic attestations of origin?

Not by themselves.

In active v1 they are canonical structured artifacts with stable public meaning. They are not portable cryptographic proofs of origin if copied outside trusted transport or storage.

If a deployment needs portable origin verification, use the active opt-in Outcome Attestation v2alpha1 envelope and verify it against a trusted key.

## Is Outcome Attestation active yet?

Yes, as an opt-in v2alpha1 envelope around v1 `Receipt` and `Refusal` artifacts.

Outcome Attestation is active only for the signed envelope surface. It does not change v1 `Receipt` or `Refusal` payload semantics.

See [`../../spec/outcome-attestation/SPEC.md`](../../spec/outcome-attestation/SPEC.md) and [`../../RECEIPT_V2_DESIGN.md`](../../RECEIPT_V2_DESIGN.md).

## What is the fastest operational path to a meaningful compatibility signal?

```bash
make install
actenon conformance run
```

Start there before broader demo, packaging, or framework-integration work.
