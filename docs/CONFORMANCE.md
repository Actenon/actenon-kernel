# Conformance

Current suite version: **1.0.0**

## Purpose

This document defines the public compatibility surface for the open kernel.

It is meant for:

- third-party verifier implementers
- ecosystem integrators
- packagers and distributors
- teams evaluating whether their deployment still honors the public contract surface

## What Compatibility Means

Compatibility with this repository means honoring the active public contracts and active behavior specs the repository publishes today.

For v1, that means:

- Action Intent contract semantics
- PCCB contract semantics
- Protected Endpoint behavior
- Replay behavior
- Receipt artifact shape and semantics
- Refusal artifact shape and semantics
- execution state transition invariants used by the conformance suite

This repository is therefore an emerging public compatibility target, not only a reference implementation.

For behavioral compatibility, proof binding happens at the protected endpoint. Replay compatibility applies only where the replay path is actually enforced at that protected endpoint.

Active v1 compatibility is intentionally narrow. It does not include reserved surfaces, paid-layer behavior, provider-backed finality, or any unpublished execution semantics.

## Active Compatibility Target

The active compatibility target is the set of active surfaces in [SPEC_INDEX.md](SPEC_INDEX.md):

- `spec/action-intent/SPEC.md`
- `spec/pccb/SPEC.md`
- `spec/receipt/SPEC.md`
- `spec/refusal/SPEC.md`
- `spec/outcome-attestation/SPEC.md`
- `spec/countersignature/SPEC.md`
- `spec/transparency-log/SPEC.md`
- `spec/issuer-status/SPEC.md`
- `spec/approval-artifact/SPEC.md`
- `spec/protected-endpoint/SPEC.md`
- `spec/replay/SPEC.md`

The Protected Endpoint is the central behavioral compatibility surface: a consequential execution edge must verify the PCCB and required local context before side effects.

## Public References

- [SPEC_INDEX.md](SPEC_INDEX.md)
- [docs/reference/EXECUTION_SEMANTICS.md](docs/reference/EXECUTION_SEMANTICS.md)
- [docs/guides/CONFORMANCE_TESTS_GUIDE.md](docs/guides/CONFORMANCE_TESTS_GUIDE.md)
- [docs/guides/COMPATIBILITY_FAQ.md](docs/guides/COMPATIBILITY_FAQ.md)
- [EXECUTION_GAP_SCANNER.md](EXECUTION_GAP_SCANNER.md)
- [conformance/README.md](conformance/README.md)
- [conformance/MATRIX.md](conformance/MATRIX.md)

## Fastest Operational Path

```bash
make install
actenon-kernel conformance run
make public-verify
```

Use `actenon-kernel conformance run` when you want the active compatibility suite only.

Use `make public-verify` when you want the broader public-release gate for installability, packaging, and archive hygiene as well.

If you are building an external compatible implementation, the fastest operational path is:

1. target the active `/spec` surfaces in [SPEC_INDEX.md](SPEC_INDEX.md)
2. implement Protected Endpoint and Replay behavior before provider-specific integrations
3. run `actenon-kernel conformance run`
4. use the broader repo verification path only if you are validating this repository's packaged distribution

## Reserved Surfaces Are Not Compatibility Targets

The following public names are reserved but are not active v1 conformance targets:

- Reconciliation
- Policy Bundle

They remain reserved surfaces until a future active contract is published under `/spec` with explicit schema, semantics, and versioning. Reserved surfaces are not active v1 standards.

Existing mapper interfaces, local receipt fields, or ecosystem guidance do not by themselves create a Reconciliation compatibility target. For the current activation threshold, see [RECONCILIATION_ACTIVATION_PLAN.md](RECONCILIATION_ACTIVATION_PLAN.md).

External projects should not claim compatibility with reserved surfaces, and should not imply roadmap activation from the presence of a reserved spec placeholder.

## What Conformance Does Not Mean

Conformance to this repository does not imply:

- provider-backed production execution
- hosted approval workflows
- provider-authenticated reconciliation or finality
- compatibility with a paid control plane that is not represented in the public specs
- portable cryptographic attestation of origin for copied artifacts unless an applicable Outcome Attestation or Receipt Counter-Signature is present and verified against a trusted key
- that an issuer, signer, or external control plane made the correct business decision before minting proof
- that a downstream adapter told the truth after control passed to it
- that a deployment which bypasses the replay path still has replay protection

## Scanner Versus Conformance

The shipped [EXECUTION_GAP_SCANNER.md](EXECUTION_GAP_SCANNER.md) is related to conformance, but it is not the same thing.

- conformance is the active public compatibility target for the published v1 surfaces
- the execution gap scanner is a shipped kernel-adjacent local adoption tool for detecting likely execution-boundary failures in CI, GitHub Actions, and engineering review
- scanning can help teams find obvious boundary regressions before or outside a full compatibility claim
- scanning does not itself create a conformance result or a new public contract surface

Local scanner command:

```bash
actenon-kernel scan --target replay-harness
```

GitHub Action wrapper:

- [`.github/actions/execution-gap-scan`](.github/actions/execution-gap-scan/README.md)

## Run The Suite

```bash
actenon-kernel conformance run --require-complete
```

Equivalent direct test command:

```bash
python3 -m unittest discover -s tests/conformance -p 'test_*.py'
```

## Compatibility Areas

- proof verification
- protected-endpoint refusal before side effects
- replay refusal behavior
- refusal artifact shape
- receipt artifact shape
- opt-in Receipt/Refusal outcome attestation creation and verification
- opt-in receipt counter-signature verification against pinned public keys
- opt-in transparency checkpoint, inclusion, consistency, and monitor verification
- execution state transition invariants

## What A Passing Result Supports

A passing result supports a scoped compatibility claim against the repository's active public surface.

The versioned self-certification wording for the current suite is:

> Actenon Verified (Conformance 1.0.0)

That wording is gated on the unmodified hash-locked vectors passing with no
skipped checks. The claim must also state the implementation and tested
revision. See [conformance/suite.json](conformance/suite.json) and
[docs/SECURITY_ASSURANCE.md](docs/SECURITY_ASSURANCE.md).

It supports saying that an implementation targets the OSS kernel compatibility surface for the active v1 contracts and behavior specs above. Where an implementation also emits and verifies Outcome Attestation v2alpha1 envelopes, it supports the scoped claim that those envelopes follow the public attestation contract.

It does not support saying that an implementation conforms to unpublished, reserved, private, or paid-layer behavior. It also does not prove provider-backed reconciliation or finality, issuer integrity, or adapter honesty.

In particular, a passing result does not by itself prove that every production route in a larger system actually goes through the protected endpoint. It only justifies claims about the paths that implement the published active public surfaces and pass the suite.

## Safe Public Claim Wording

If you want to describe a passing result publicly, keep the claim scoped to the active OSS surface.

Example:

> This implementation targets the Actenon Kernel active v1 compatibility surface for Action Intent, PCCB, Protected Endpoint, Replay, Receipt, and Refusal, supports the opt-in Outcome Attestation v2alpha1 envelope where used, and is Actenon Verified (Conformance 1.0.0) at the stated implementation revision.

Stronger but still safe:

> This implementation targets the Actenon Kernel active v1 compatibility surface, keeps proof binding at the protected endpoint, enforces replay on protected execution paths, and passes the public conformance suite shipped by this repository.

Do not extend that claim to:

- Reconciliation
- Policy Bundle
- hosted approvals or evidence workflows
- provider-authenticated reconciliation or finality
- paid-layer behavior outside the public specs

## What This Does Not Solve

- conformance does not guarantee that every deployment path actually routes consequential execution through protected-endpoint proof verification
- replay conformance does not help if a host bypasses replay enforcement in production
- in v1, Receipt and Refusal conformance validates canonical structured artifacts; portable origin checks require verifying an Outcome Attestation envelope
- conformance does not prove issuer correctness, control-plane integrity, or adapter truthfulness

## Third-Party Guidance

If you are implementing a compatible verifier or execution edge:

1. start with the contract specs under `/spec`
2. implement Protected Endpoint verification and replay semantics before adding provider integrations
3. validate your build against the conformance suite
4. treat any deviation from published contract or execution semantics as a compatibility risk

If you need a concise boundary check before making a public compatibility claim, read [docs/guides/COMPATIBILITY_FAQ.md](docs/guides/COMPATIBILITY_FAQ.md).
