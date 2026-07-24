# SDK Selection Guide

## Purpose

Use this guide when you want the fastest route to the right verifier-edge SDK or kernel path.

The key question is simple:

- do you need the full Python kernel reference path
- or do you only need protected-endpoint proof verification inside an existing service

## Fast Chooser

| Choose this path | When you need | What you get |
| --- | --- | --- |
| [Python kernel and verifier path](docs/guides/INTEGRATION_QUICKSTART.md) | the full open-kernel reference path, local proof mode, CLI verification, protected endpoint helpers, and conformance-adjacent examples | kernel plus verifier-first adoption |
| [TypeScript verifier SDK](sdk/typescript/README.md) | verifier-edge proof checking in Node or TypeScript services | verifier-only SDK |
| [Go verifier SDK](sdk/go/README.md) | verifier-edge proof checking in Go services | verifier-only SDK |
| [Rust verifier SDK](sdk/rust/README.md) | verifier-edge proof checking in Rust services or systems components | verifier-only SDK |

## Choose Python When

Choose the Python path if you want:

- the canonical open-kernel reference implementation
- local proof mode and artifact generation
- the CLI for proof, receipt, refusal, and conformance checks
- a standalone `actenon-kernel verify-proof` command for verifying an Action Intent and PCCB pair from the terminal with explicit local audience context
- protected-endpoint examples in the same language as the kernel
- the fastest way to inspect the full Action Intent -> PCCB -> Protected Endpoint -> Receipt or Refusal flow

Start here:

- [QUICKSTART.md](QUICKSTART.md)
- [docs/guides/INTEGRATION_QUICKSTART.md](docs/guides/INTEGRATION_QUICKSTART.md)
- [docs/reference/verifier/VERIFIER_SDK_REFERENCE.md](docs/reference/verifier/VERIFIER_SDK_REFERENCE.md)

## Choose TypeScript When

Choose the TypeScript SDK if your protected endpoint already lives in:

- Node.js
- TypeScript services
- Express routes
- JavaScript-heavy app stacks

Start here:

- [sdk/typescript/README.md](sdk/typescript/README.md)
- [examples/express_protected_route/README.md](examples/express_protected_route/README.md)

## Choose Go When

Choose the Go SDK if your protected endpoint already lives in:

- a Go HTTP service
- a Go edge service
- a Go infrastructure service that only needs verifier-side proof checks

Start here:

- [sdk/go/README.md](sdk/go/README.md)

## Choose Rust When

Choose the Rust SDK if your protected endpoint already lives in:

- a Rust service
- a Rust edge component
- a Rust infrastructure or systems path that only needs verifier-side proof checks

Start here:

- [sdk/rust/README.md](sdk/rust/README.md)

## Verifier-Only Deployment Model

Protected endpoints verify proof. They do not need to mint proof.

For verifier-only deployments:

- Python now exposes `actenon.proof.SignatureVerifier`
- TypeScript exposes `SignatureVerifier`
- Go exposes `SignatureVerifier`
- Rust exposes `SignatureVerifier`

The local signer shipped in this repository exists for:

- local proof mode
- tests
- runnable examples

It is not the repo's claim about production key custody.

Production deployments can provide a verifier-compatible trust root without turning the protected endpoint into a signer service.

All four SDK paths also verify the open Receipt Counter-Signature v1 format
offline. Relying parties pass a pinned `key_discovery v1` public-key set, and
the verifier selects the exact active or historical key by `kid`. See
[spec/countersignature/SPEC.md](spec/countersignature/SPEC.md).

If you are starting from the public launch path, use this order:

1. [QUICKSTART.md](QUICKSTART.md)
2. [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
3. [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
4. then choose the SDK that matches your protected endpoint runtime

## What Every SDK Path Still Requires

No SDK removes the protected-endpoint responsibilities. Your endpoint still has to supply:

- the Action Intent payload
- the PCCB payload
- exact local audience identity
- exact capability context
- verification time
- replay and single-use enforcement where required by the execution path

## What None Of These SDKs Are For

They are not:

- approval systems
- provider runtime services
- reconciliation operations
- audit archives
- billing or tenant administration layers

They are verifier-edge adoption paths for the open kernel.
