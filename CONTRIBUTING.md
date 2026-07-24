# Contributing

## Scope

This repository is the open execution kernel and verifier-side adoption layer.

Please keep contributions inside that boundary:

- kernel behavior
- public contracts
- verifier SDK
- local proof mode
- protected endpoint examples
- documentation
- tests
- packaging and release hygiene

Do not add hosted control-plane features in this repository unless the scope is explicitly changed first.

## Community Standards

Before opening an issue or pull request, read:

- `CODE_OF_CONDUCT.md`
- `SECURITY.md`

Use the GitHub issue templates for:

- bug reports
- feature requests
- compatibility and integration questions

Use the pull request template to document boundary, compatibility, and validation impact.

## Stable And Active Public Surface

Treat these as the active v1 public compatibility surface:

- Action Intent
- PCCB
- Receipt
- Refusal
- Protected Endpoint
- Replay

Reference points:

- `SPEC_INDEX.md`
- `CONFORMANCE.md`
- `VERSIONING_POLICY.md`

Reserved surfaces such as Reconciliation and Policy Bundle are published names, not active v1 compatibility targets. Do not treat them as stable implementation targets in this repository.

## Development Setup

```bash
make install
```

## Core Commands

```bash
make verify
make judge
make local-proof
make portable-verify
make public-verify
```

If you touch the TypeScript verifier SDK, also run:

```bash
cd sdk/typescript
npm ci
npm test
```

## Contribution Standards

- keep naming generic
- do not invent provider-backed behavior that does not exist
- prefer clear, testable, minimal implementations
- update docs when behavior changes
- keep the open-source boundary explicit

For changes that touch active specs, verifier behavior, or artifact semantics:

- preserve compatibility unless you are intentionally making a major-version change
- update `/spec` and conformance material together
- keep protected endpoints verifier-only unless the change is explicitly about local proof mode or proof minting internals

## Public Repository Discipline

Keep the public tree curated. Do not commit generated implementation reports, acceptance notes, maintainer scratch files, release-session audits, macOS archive debris, test caches, or local runtime state.

Generated files such as `*_REPORT.md`, `*_AUDIT.md`, `.DS_Store`, `__MACOSX/`, `.pytest_cache/`, `.actenon/`, `artifacts/`, and local SQLite files belong outside the public repository unless they are explicitly promoted into a durable public document.

## Before Opening A Change

Run:

```bash
make verify
make judge
make public-verify
```

If you touch portable packaging or verifier-side behavior, also run:

```bash
make portable-verify
```

If you touch active public surface behavior, also run:

```bash
actenon-kernel conformance run
```

## Documentation To Update When Needed

- `README.md`
- `QUICKSTART.md`
- `docs/guides/FIRST_10_MINUTES.md`
- `MCP_HERO_PATH.md`
- `SDK_SELECTION_GUIDE.md`
- `SUPPORT_AND_COMPATIBILITY_STATUS.md`
- `docs/guides/INTEGRATION_QUICKSTART.md`
- `CONFORMANCE.md`
- `SPEC_INDEX.md`
- `OPEN_SOURCE_BOUNDARY.md`
