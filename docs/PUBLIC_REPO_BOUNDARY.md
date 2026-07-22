# Public Repository Boundary

This document defines what may ship in the public Actenon Kernel repository and
in public release archives.

## Public OSS Scope

The public repository may contain:

- `actenon/`: the open kernel implementation
- `sdk/`: open verifier SDKs and fixtures
- `examples/`: public protected-endpoint examples
- `schemas/`: public contract schemas
- `spec/`: public protocol and contract specifications
- `conformance/`: public conformance vectors and documentation
- `tests/`: public test coverage for the open kernel
- `docs/`: public guides, references, and educational material
- `scripts/`: public verification and release scripts
- public root documents such as `README.md`, `QUICKSTART.md`,
  `THREAT_MODEL.md`, `KERNEL_GUARANTEES.md`, `OPEN_SOURCE_BOUNDARY.md`,
  `SPEC_INDEX.md`, `CONFORMANCE.md`, `SECURITY.md`, `GOVERNANCE.md`, and this
  boundary file
- `pyproject.toml`, `Makefile`, and `LICENSE`

The public kernel may also include local-only OSS examples for proof-bound
execution, replay protection, credential brokering, receipt/refusal generation,
and conformance. These examples must not require private Cloud source or private
commercial material.

## Private Or Non-Shipping Material

The public repository and public release archive must not include:

- `AI Agent Execution Control Layer/`
- `actenon-cloud/`
- Cloud/control-plane source code
- private design-partner documents
- SOW templates, pricing assumptions, ICP rubrics, objection handling, or GTM
  working documents
- private pilot material or customer-specific content
- local runtime state such as `.actenon/`
- local SQLite or database files
- generated artifacts such as `artifacts/`, `build/`, `dist/`, or
  `*.egg-info/`
- dependency folders such as `node_modules/`
- macOS/archive debris such as `.DS_Store`, `__MACOSX/`, or AppleDouble files
- embedded `.git` directories
- maintainer scratch notes, generated implementation reports, or local
  acceptance artifacts not intended for public release

Private material may exist elsewhere on a developer workstation, but it must not
be tracked, packaged, or copied into a public release archive.

## Release Archive Boundary

The public release archive is allowlist-based. It may include only:

- `actenon/`
- `sdk/` if present
- `examples/`
- `schemas/`
- `spec/`
- `conformance/`
- `tests/`
- `docs/`
- public root documents
- public scripts
- `pyproject.toml`
- `Makefile`
- `README.md`
- `LICENSE`

Archive creation must still apply deny rules inside those public paths so local
state, dependency folders, generated artifacts, private reports, and metadata
debris are excluded even if they are present in the working tree.

## Package Boundary

Python package builds must not package private Cloud or GTM material. The open
kernel package should include the public kernel modules and public examples
needed for local adoption. Cloud/control-plane code must remain a separate
private or commercial repository.

## Validation Commands

Use these commands before public release:

```bash
scripts/validate_public_boundary.sh
scripts/create_public_release_archive.sh
```

`scripts/validate_public_boundary.sh` checks tracked private-path patterns,
package build artifacts, and the generated public release archive. The release
archive script builds from a public allowlist and excludes local/private debris.
