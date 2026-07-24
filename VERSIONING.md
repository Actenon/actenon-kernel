# Kernel Versioning

## Current version

**Kernel version:** `1.0.0`
**Protocol version range:** `actenon-protocol>=1.1.0,<2`
**Conformance version:** see `conformance/VERSION`
**Python support:** `>=3.10` (kernel alone); `>=3.11` (composed stack with actenon-permit)

## What this document is

A 1.0.0 without a written compatibility promise is just a bigger number.
This document is what makes the promotion mean something. It states, in
unambiguous terms, what the kernel guarantees about its public surface
across the 1.x series, and what it explicitly does not guarantee.

## 1.1 What 1.0 covers — the stable surface

The following are part of the 1.0 compatibility promise. Within the 1.x
series, no release will break them except to fix a security defect (see
§1.4).

- **The public Python API** exported from `actenon/__init__.py`:
  `ActenonGate`, `ActionIntent`, `GateOutcome`, `PCCB`. These names,
  their constructors' signatures, and their public methods are stable.

- **The verifier's decision semantics**: which inputs produce ALLOW, and
  which produce which typed refusal code. The mapping from (proof, intent,
  context) to (allow, refusal_code) is the kernel's core contract. A
  proof that verifies under 1.0.0 verifies under any 1.x.y.

- **The refusal taxonomy**: the set of refusal codes defined in
  `actenon-protocol`'s `refusals/catalogue.v1.yaml`. Codes are
  additive-only within 1.x — no code is removed or given new meaning. New
  codes may be added in minor releases; consumers MUST treat unknown
  codes as `OUTCOME_UNKNOWN` (per the protocol's unknown-version
  behaviour).

- **The conformance vector corpus** at the pinned conformance version
  (see `conformance/VERSION`). An implementation that passes the
  conformance suite at 1.0.0 will keep passing it at any later 1.x.y.
  Vectors are hash-locked and never mutated.

- **The CLI's command names and exit codes**: `actenon-kernel` (the
  console script) exposes a stable set of subcommands. Existing
  subcommand names, their required arguments, and their exit codes (0 for
  success, non-zero for failure) are stable within 1.x. New subcommands
  may be added in minor releases.

## 1.2 What 1.0 explicitly does NOT cover

The following are NOT part of the 1.0 compatibility promise and may
change within the 1.x series without a major bump:

- **Anything under a module named `_private`, `_internal`, or prefixed
  with `_`.** These are implementation details. If you import them
  directly, you are on your own.

- **Anything documented as alpha or beta.** This includes Outcome
  Attestation while it remains `v2alpha1` (see §4.2 and the README).
  Alpha/beta surfaces may change or be removed in any release.

- **The wire format of any artefact.** The wire format of Action Intent,
  PCCB, Receipt, Refusal, and ExecutionResult is defined by
  `actenon-protocol`, not by the kernel. The kernel targets
  `actenon-protocol>=1.1.0,<2`. If the protocol publishes a breaking
  change (a 2.0.0), the kernel will publish a corresponding major bump.

- **Integration adapters under `actenon/adapters/`.** The LangChain,
  MCP, and FastAPI adapters track their upstream frameworks. If a
  framework publishes a breaking change, the corresponding adapter may
  follow within a kernel minor release. The adapter's public constructor
  signature is stable; the integration glue is not.

- **The local demo signers** (`actenon.demo.local_proof`,
  `actenon.demo.portable_local_proof`). These exist for development and
  demos. They are not part of the production surface and may change
  freely.

- **The SQLite and Postgres replay store schemas.** The schema is
  managed by migrations within the kernel. The public Python class
  interface (`SqliteReplayStore`, `PostgresReplayStore`) is stable; the
  underlying DDL is not.

## 1.3 The promise

| Bump | When | Effect on verified proofs |
|---|---|---|
| **PATCH** | Bug fix. No behaviour change to any ALLOW/refuse decision. | A proof that verified before still verifies. |
| **MINOR** | Additive only. New refusal codes, new adapters, new optional parameters, new conformance vectors. | A proof that verified under 1.x verifies under any later 1.y. |
| **MAJOR** | May change decision semantics. Required if any input that previously produced ALLOW would now be refused, or vice versa. | A proof that verified before MIGHT stop verifying. Requires migration. |

## 1.4 The decision-semantics rule

This is the promise that matters most for this component:

> Within 1.x, no release will cause an artefact that previously verified
> to stop verifying, except where doing so fixes a security defect. Any
> such exception will be published as a security advisory with the
> affected versions named.

This means: if your proof verifies against kernel 1.0.0, it will verify
against 1.0.1, 1.1.0, 1.2.0, …, up to but not including 2.0.0. The only
exception is a security fix that MUST change a decision to be safe; that
fix ships as a PATCH or MINOR with a security advisory, and the advisory
names the exact versions affected.

## 1.5 Supported versions

| Version | Status | Support window |
|---|---|---|
| 1.0.x | Current | Full support |
| 0.1.x | EOL | No support; upgrade to 1.0.0 |

**Python floor:**
- The kernel alone supports `requires-python >=3.10`.
- The composed stack (kernel + permit + protocol) requires `>=3.11`
  because `actenon-permit` requires `>=3.11`. If you are deploying the
  full Actenon stack, use Python 3.11+. If you are deploying the kernel
  alone (verifier-only edge), Python 3.10 is sufficient.

## 1.6 Deprecation policy

- A public API element slated for removal in a future major version
  receives a `DeprecationWarning` for at minimum one minor release cycle
  before removal.
- Deprecations are announced in:
  - The `CHANGELOG.md` entry for the release that introduces the
    deprecation.
  - The `DeprecationWarning` message itself, which names the replacement
    (if any) and the target removal version.
- Security-critical deprecations (e.g. a signer algorithm found weak)
  follow the security advisory process, not the standard deprecation
  calendar.

## See also

- [CHANGELOG.md](CHANGELOG.md) — release history
- [SECURITY.md](SECURITY.md) — security policy and supply chain posture
- [docs/PRODUCTION_INTEGRATION.md](docs/PRODUCTION_INTEGRATION.md) —
  self-contained production guidance (Apache-2.0)
- [Protocol Versioning](https://github.com/Actenon/actenon-protocol/blob/main/VERSIONING.md) —
  the protocol's own versioning policy
