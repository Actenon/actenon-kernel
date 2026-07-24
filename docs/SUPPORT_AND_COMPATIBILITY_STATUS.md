# Support And Compatibility Status

## Purpose

This document states what contributors and adopters can rely on today from the public OSS kernel.

It is intentionally narrower than a product brochure. It describes tested support, active compatibility scope, and the current CI posture.

## Active Public Compatibility Surface

The active v1 OSS compatibility surface is:

- Action Intent
- PCCB
- Receipt
- Refusal
- Protected Endpoint
- Replay

Reference points:

- [SPEC_INDEX.md](SPEC_INDEX.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [VERSIONING_POLICY.md](VERSIONING_POLICY.md)

Reserved public surfaces such as Reconciliation and Policy Bundle are not active v1 compatibility targets.

## Python Kernel Support

The Python package metadata declares:

- `requires-python >=3.10`

The public Python support claim is:

- Python 3.10, 3.11, and 3.12 are active support targets for the OSS kernel path

GitHub Actions reflects that claim with:

- a Python matrix over 3.10, 3.11, and 3.12
- package build on each matrix entry
- `python -m pytest tests/ -q` on each matrix entry
- the conformance suite (`tests/conformance/`) runs on every push and PR, not just on `conformance-v*` tags
- a separate public release gate via the `conformance-release.yml` workflow on `conformance-v*` tags

### Why not Python 3.9?

Python 3.9 reached end-of-life in October 2025. The kernel uses `match` statements, PEP 604 union syntax, and other 3.10+ features. If you need 3.9 support, file an issue — but the default posture is to track supported Python versions.

## TypeScript Verifier Support

The TypeScript verifier SDK declares:

- Node `>=20`

For launch, the repository CI covers:

- `npm ci`
- `npm test`

under `sdk/typescript/`.

For local contributor verification, use:

- `make sdk-typescript-test`

This is verifier-edge coverage only. It does not imply a broader Node control-plane product.

## Go Verifier Support

The Go verifier SDK declares:

- Go `1.22`

For launch, the repository CI covers:

- `go test ./...`

under `sdk/go/`.

For local contributor verification, use:

- `cd sdk/go && go test ./...`

This supports the honest public Go claim for launch:

- the Go verifier is a tested public verifier-edge path
- the root OSS compatibility and release-readiness claims remain centered on the Python kernel path
- Go CI does not imply replay enforcement, receipt/refusal generation, or a broader Go control-plane product

## Rust Verifier Support

The Rust verifier SDK declares:

- Rust `1.81`

For launch, the repository CI covers:

- `cargo test`

under `sdk/rust/`.

For local contributor verification, use:

- `cd sdk/rust && cargo test`

This supports the honest public Rust claim for launch:

- the Rust verifier is a tested public verifier-edge path
- the root OSS compatibility and release-readiness claims remain centered on the Python kernel path
- Rust CI does not imply replay enforcement, receipt/refusal generation, or a broader Rust control-plane product

## Conformance Status

Conformance is the public compatibility check for the active OSS surface.

Contributors and adopters should rely on:

- `actenon-kernel conformance run`
- the tests under `tests/conformance/`

## Replay Store Support

The Python kernel includes:

- `SqliteReplayStore` for local, demo, test, and single-node use
- `PostgresReplayStore` for production-grade OSS multi-instance replay storage

PostgreSQL support is optional. Install it with:

```bash
pip install "actenon-kernel[postgres]"
```

Support claim boundary:

- PostgreSQL replay support means the OSS kernel has a concrete transactional replay backend suitable for shared replay state across workers or nodes.
- It does not mean Actenon provides a hosted database, hosted runtime, managed replay service, tenant administration, or control-plane operations in this repo.
- the public guidance in [CONFORMANCE.md](CONFORMANCE.md)

A passing conformance result supports a scoped compatibility claim against the active OSS surface only.

It does not support claims about:

- reserved surfaces
- provider-authenticated reconciliation
- hosted approvals or evidence workflows
- paid-layer behavior outside the published OSS specs

## What Contributors Should Rely On

Contributors should rely on these as the stable public anchors:

- `/spec` as the normative documentation entry point
- `/schemas` as the versioned machine-readable contract source
- `CONFORMANCE.md` and `tests/conformance/` for active compatibility behavior
- `scripts/public_repo_verify.sh` for public release readiness
- the Python 3.9 to 3.12 CI matrix for kernel support confidence
- the TypeScript, Go, and Rust verifier CI jobs for verifier-edge SDK confidence

## What Contributors Should Not Rely On

Do not rely on:

- unpublished control-plane behavior
- reserved surfaces becoming active without spec and conformance updates
- local demo signers as a statement about production key custody
- Receipt or Refusal acting as portable cryptographic attestations of origin in v1
- draft Receipt/Refusal attestation groundwork as if it were already an active compatibility target
