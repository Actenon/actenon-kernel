# Conformance Tests Guide

## Purpose

The repository ships conformance material so implementers can validate that a verifier build still honors the public contract and proof verification behavior.

Current suite version: **1.0.0**

This guide complements:

- [../../CONFORMANCE.md](../../CONFORMANCE.md)
- [../../conformance/README.md](../../conformance/README.md)
- [../reference/EXECUTION_SEMANTICS.md](../reference/EXECUTION_SEMANTICS.md)

## Canonical Spec Surface

Use [../../SPEC_INDEX.md](../../SPEC_INDEX.md) as the source of truth for the surfaces under conformance.

The central behavioral compatibility surface is the Protected Endpoint. External implementations should treat the protected execution edge, not upstream approval or orchestration, as the place where compatibility is won or lost.

## Fastest Path

```bash
make install
actenon conformance run --require-complete
```

Broader public-release validation:

```bash
make public-verify
```

Before a launch build, run the explicit release gate:

```bash
bash scripts/verify_release_gate.sh
```

If you are evaluating compatibility rather than the full demo path, stop here first. `actenon conformance run` is the shortest meaningful operational signal for the active public kernel surface.

## Test Location

- `tests/conformance/`

Current conformance modules:

- `tests/conformance/test_verifier_sdk_conformance.py`
- `tests/conformance/test_replay_conformance.py`
- `tests/conformance/test_artifact_shape_conformance.py`
- `tests/conformance/test_execution_state_conformance.py`
- `tests/conformance/test_outcome_attestation_conformance.py`
- `tests/conformance/test_countersignature_conformance.py`
- `tests/conformance/test_transparency_log_conformance.py`
- `tests/conformance/test_trust_artifacts_conformance.py`

## Covered Behaviors

- portable local proof demo runs successfully
- valid local proof verifies successfully
- audience mismatch is refused
- action mutation is refused
- expired proof is refused
- duplicate execution is replay-refused
- replay refusal artifacts preserve the public refusal shape
- receipt artifacts preserve the public receipt shape
- opt-in Receipt/Refusal outcome attestations can be created and verified
- attested outcomes fail verification after tampering or with the wrong key
- receipt counter-signatures verify offline by `kid`, including retired historical keys
- unknown counter-signing keys, wrong public keys, and altered Receipt digests fail closed
- transparency checkpoints, inclusion proofs, and consistency proofs verify offline
- signed forks, rewinds, unknown checkpoint keys, and orphan counter-signatures fail closed
- signed issuer status rejects revoked, stale, expired, missing, or unverifiable assertions
- signed approvals verify by `kid`, bind to the exact action, and reject forgery or laundering
- execution state transition invariants hold

The Python Receipt Counter-Signature, Transparency Log, Issuer Status, and
Approval Artifact cases require the
optional `asymmetric` extra. The public CI and release gate install that extra;
core-only installs skip those Ed25519 cases with an explicit message.

Skipped checks are not eligible for the versioned `Actenon Verified` mark.
Self-certification therefore uses `--require-complete`.

Those checks are deliberately concentrated around the active public kernel targets. Outcome Attestation is additive and opt-in; it does not change active v1 Receipt or Refusal semantics or turn reserved or paid-layer surfaces into implied standards.

## Repo Command

```bash
python3 -m unittest discover -s tests/conformance -p 'test_*.py'
```

CLI shortcut:

```bash
actenon conformance run
```

Public-release gate:

```bash
make public-verify
```

`make public-verify` delegates to `scripts/verify_release_gate.sh`, which
blocks on keystone tests, the full kernel suite, Ruff, public boundary
validation, and public archive validation.

## Packaged Distribution Command

```bash
bash ./scripts/verify_portable_distribution.sh
```

## How Third Parties Should Use This

Third-party implementers should:

1. implement the public contracts and behavioral semantics under `/spec`
2. use [../reference/EXECUTION_SEMANTICS.md](../reference/EXECUTION_SEMANTICS.md) as the behavioral state reference
3. verify `conformance/suite.json` and `conformance/vector-lock.json`
4. run the complete suite against their verifier or packaged distribution
5. treat failing conformance tests as compatibility failures unless they have intentionally moved to a new public version
6. state the conformance version and tested implementation revision
7. keep public compatibility claims scoped to the active public surfaces that actually pass

The machine-readable suite declaration includes the mandatory vector families,
SDK targets, and mark requirements. P10-PUB, P11-PUB, and P12-PUB coverage is
represented by `receipt_countersignature_v1`, `transparency_log_v1`, and
`trust_artifacts_v1`; the shared SDK command runs them against Python,
TypeScript, Go, and Rust.

## What A Passing Run Means

A passing run supports a scoped compatibility statement against the active public OSS surface only.

It does not activate compatibility claims for reserved surfaces or any paid-layer behavior.

It also does not prove issuer correctness, adapter honesty, provider finality, or that every route in a larger system is protected in production.

## Expected Outcome

The portable distribution is acceptable only if the packaged conformance tests pass without importing excluded hosted or control-plane modules.

For concise public-claim boundaries and common evaluator questions, see [COMPATIBILITY_FAQ.md](COMPATIBILITY_FAQ.md).
