# Security Assurance

## Purpose

Actenon's open conformance suite is a security-relevant compatibility artifact.
It tests deterministic verification behavior across the active public contract
surface. A passing result is evidence about that stated surface and version; it
is not a blanket certification of an implementation, deployment, issuer, or
operated service.

## Conformance Version And Mark

The current suite version is declared in:

- `conformance/VERSION`
- `conformance/suite.json`
- `actenon/conformance/version.py`

The versioned public claim is:

> Actenon Verified (Conformance 1.0.0)

An implementation may use that claim only when it:

1. runs the unmodified hash-locked vectors for version 1.0.0;
2. passes every mandatory check with no skips;
3. identifies the implementation, tested revision, SDK, and conformance version;
4. keeps the claim scoped to the active public compatibility surface.

Use:

```bash
python -m actenon.cli conformance run --require-complete
bash scripts/verify_sdk_conformance.sh
```

The mark is a self-certification compatibility statement, not an endorsement,
security audit, warranty, or claim that a deployment has no bypass path.

## Versioned And Signed Releases

Conformance releases use semantic versioning and tags of the form
`conformance-vMAJOR.MINOR.PATCH`. Vector contents are locked by SHA-256 in
`conformance/vector-lock.json`.

The release workflow accepts only a cryptographically signed Git tag, builds a
deterministic archive, publishes its SHA-256 digest, and creates GitHub artifact
provenance using OIDC/Sigstore. Relying parties should verify the signed tag,
the artifact provenance, and the digest before trusting a downloaded vector
bundle.

Vector meaning never changes in place:

- PATCH: corrections or additions that do not change existing expected results.
- MINOR: new backward-compatible surfaces or mandatory cases.
- MAJOR: changed validity, interpretation, or expected behavior.

Changes are recorded in `conformance/CHANGELOG.md`.

## Reassessment Cadence

The public assurance program follows this minimum cadence:

- every release: automated conformance, full tests, lint, package, and public-boundary gates;
- quarterly: maintainer review of the threat model, open security findings,
  dependency alerts, conformance coverage, and disclosure status;
- annually: a documented security reassessment of the active cryptographic,
  verification, replay, and protected-edge surfaces;
- trigger-based: reassessment before release of any change to signing,
  key-custody, counter-signing, transparency anchoring, checkpoint signing,
  canonicalization, proof binding, or trust-anchor distribution infrastructure.

A trigger-based reassessment is required even if the annual review is recent.
Operated signing or anchoring services are outside this OSS repository, but any
public format, verifier, key-distribution contract, or conformance change they
depend on remains subject to this policy.

Material findings update the threat model, relevant specifications, conformance
vectors, changelog, and security advisory as appropriate.

## Vulnerability Disclosure

Public security contact:

- Email: `ross.buckley1990@gmail.com`
- Subject prefix: `[ACTENON SECURITY]`

Do not open a public issue for a suspected vulnerability before coordination.
Include the affected revision, impact, prerequisites, reproduction, and whether
the issue concerns the OSS kernel, an adapter, or an operated deployment.

Response targets:

- acknowledgement within 3 business days;
- initial triage within 7 business days;
- coordinated disclosure target of 90 days after acknowledgement, adjusted when
  active exploitation, ecosystem coordination, or user safety requires a
  shorter or longer window.

Reporters may publish after the coordinated date. Maintainers will credit
reporters who request credit, preserve confidentiality for reporters who do
not, and publish a security advisory when users need remediation guidance.

No response target is a promise that every report is a vulnerability or that a
fix can always be delivered within the target window.

## Scope

Assurance is bounded by [SCOPE_AND_GUARANTEES.md](SCOPE_AND_GUARANTEES.md).
Actenon gates explicit execution-edge actions. It does not inspect prompts,
model output, or in-band response content, and it does not prove that every
production path routes through a protected edge.
