# Unified Kernel candidate — 2026-10-04

This branch preserves both parents: production candidate #41
`533c029d63b5ce070a1eb8d8513e8e57a75ec703` and capability-provenance #43
`f40253eb4efd1a4a6e32cd4cdc587e3c236a1a09`.

The older candidate already contained cryptographic boundary verification,
E1–E5 edge binding, signed extensions and revocation. Those implementations
remain, including durable replay and explicit development intent, independent
edge parameter/resource declarations, signature-first validation, strict parsing,
public disclosure controls, clean-wheel checks, PostgreSQL cold-start locking,
standalone SDK checks and the preserved release evidence.

The newer Airlock contract tests and local-dev constructor arguments are added.
The minter now uses Protocol 1.5's exact-capability validation; empty and wildcard
issuance scopes refuse rather than substituting the attempted capability. Verification
uses the same capability membership and authority-reference parsing contract.

The Rust edit in #43 targeted an embedded SDK removed by #41. The standalone
Actenon/sdk-rust candidate is the canonical SDK; no embedded Rust tree is restored.

## Candidate checks and registry release

Package minimum is Protocol 1.5.0, wire 1.2.0. Until it is genuinely published,
CI's `.github/candidate-constraints.txt` installs the immutable merged Protocol
commit `eba78d3dbd41a0b6c86166ece0f34cc8d7b7a002`. This is coordinated-source testing,
not registry-consumer evidence. Every existing required check remains required.
The release gate refuses all publication while that constraints file exists.
After publishing and independently verifying Protocol 1.5.0, remove the file and
its workflow references, rerun every required check and repeat clean public-artifact
consumer verification. No package or tag on this candidate is authorized yet.

SDK vector pins are frozen after the Kernel core is committed, then the Kernel
pins those tested SDK commits. This avoids a circular commit-pin dependency.

Old PRs remain open until the unified candidate demonstrates parity and its full
required CI matrix is green. The historical North Star evidence is preserved;
its old candidate/artifact hashes are not claims about this new candidate.

## Final verifier pins

Kernel core `c6564b90be8bdb7a871c176df5673d5b3a4ab5fc` freezes the unified proof/vector implementation. The coordinated Go candidate is `bf9fbc15a32cdb49fbd6f308cb5d4b154d94591a`; Rust is `e7984d4df5534b4a7f0cb40c554b94ba3480c8fa`. They vendor that core lock. Kernel then pins those SDK commits without changing the vector/core bytes, avoiding a circular commit-hash dependency. This is one ancestor-descendant candidate line, not alternative Kernel implementations.

Protocol contract documentation and its canonical source pin are finalized at `4cbd8f04e0db331b2ffd490d50c0a7aede2d35ff` ([Protocol #22](https://github.com/Actenon/actenon-protocol/pull/22)); source integration still does not imply registry publication.
