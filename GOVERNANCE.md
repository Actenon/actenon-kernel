# Governance

This document defines how the Actenon Kernel public standard surface changes.

It applies to the open kernel's active public contracts, active behavior specs, reserved public surfaces, and public conformance claims. It does not govern private or paid-layer behavior that is outside the repository's published OSS surface.

The governance principle is:

```text
Neutralize the standard. Monetize the operation.
```

VAR-compatible implementations must not need Actenon's permission or Actenon
Cloud. Operated commercial services can build around the standard, but the
standard surface itself should remain independently implementable.

## 0. Staged Governance Model

This repository does not claim independent foundation governance today.

Governance should progress in stages:

- Phase 0: Actenon initial stewardship, public RFC/change process, public
  conformance suite, public versioning discipline, and clear OSS/paid boundary.
- Phase 1: future Technical Steering Committee with reserved external seats
  once meaningful external implementations or integrations exist.
- Phase 2: future foundation, alliance, or consortium pathway if adoption
  thresholds justify neutral multi-stakeholder governance.

Phase 0 is the current operating model. Phase 1 and Phase 2 are intentions and
criteria for future governance, not claims about current control.

## 1. Spec RFC Process

Normative changes to the public surface should begin in GitHub Discussions using a `spec-rfc` flow.

The expected process is:

1. Open a GitHub Discussion marked or titled with `spec-rfc`.
2. State the problem, the affected public surface, the proposed normative change, and the compatibility impact.
3. Include concrete examples, edge cases, and any required conformance updates.
4. Make the OSS versus paid-layer boundary explicit when the topic could blur that line.
5. Convert accepted proposals into a pull request that references the Discussion and updates the relevant public documents.

A `spec-rfc` proposal should be used for:

- changes to `/spec`
- changes to versioned schemas under `/schemas`
- changes to active conformance semantics
- activation of a reserved public surface
- claim-language changes that affect what the public standard means

Editorial clarifications that do not change public meaning may go directly through pull requests, but maintainers may still route them into a `spec-rfc` Discussion if the compatibility impact is unclear.

## 2. Breaking Change Policy

Breaking changes are defined against the active public contracts and active compatibility surfaces, not against internal implementation details.

For the Actenon Kernel, a change is breaking if it changes the validity, required interpretation, or required behavior of an active public surface listed in [SPEC_INDEX.md](SPEC_INDEX.md) and scoped in [CONFORMANCE.md](CONFORMANCE.md).

That includes changes such as:

- renaming or removing a field in an active contract
- making an optional field required in an active contract
- changing the meaning of an active contract field
- changing canonicalization, hash, identifier, timestamp, or signature rules for an active surface
- changing Protected Endpoint or Replay behavior in a way that invalidates previously compatible implementations
- changing Receipt or Refusal semantics in a way that alters a valid public conformance claim

Breaking changes require a new major version for the affected active surface, plus explicit migration guidance and intentional conformance updates.

The following are not breaking by themselves:

- wording clarifications that do not change public meaning
- additional non-normative examples
- internal refactors
- changes to reserved surfaces that are not yet active compatibility targets

## 3. Reserved Surface Activation Policy

Reconciliation and Policy Bundle are reserved public surfaces. They are named extension boundaries, but they are not active standards and they are not active conformance targets today.

They may become active only through an explicit activation path:

1. An accepted `spec-rfc` Discussion defines the problem, boundary, and activation scope.
2. A human-readable normative spec is published under `/spec`.
3. A versioned machine schema is published under `/schemas` when the surface is a portable contract rather than a behavior-only surface.
4. Compatibility semantics, versioning expectations, and examples are published clearly enough for third parties to implement.
5. Conformance scope is added intentionally, with tests and safe public claim language updated as needed.
6. The activation change states what remains outside the OSS kernel and outside the active standard.

Until that activation path is complete, Reconciliation and Policy Bundle must be treated as reserved names only. They must not be presented as active kernel standards, active conformance targets, or safe public conformance claims.

## 4. Stewardship Statement

Actenon is the initial steward of the Actenon Kernel public standard surface.

That stewardship includes:

- maintaining the published `/spec` and `/schemas` surfaces
- operating the `spec-rfc` intake and decision process
- curating versioning and breaking-change discipline
- maintaining the public conformance suite and safe claim language

This repository does not claim neutral multi-stakeholder governance today. It
does commit to a public RFC/change process for public standard surfaces and to
keeping compatibility claims separate from paid service adoption.

The long-term intent is to move toward broader governance if and when the
ecosystem warrants it, using the staged model above.

## 5. Conformance Claim Policy

Public conformance claims must stay scoped to the active public compatibility surface.

A passing result supports a statement like:

> This implementation targets the Actenon Kernel active v1 compatibility surface for Action Intent, PCCB, Protected Endpoint, Replay, Receipt, and Refusal, and passes the public conformance suite shipped by this repository.

It does not support claims about:

- Reconciliation
- Policy Bundle
- hosted approvals or evidence workflows
- provider-authenticated reconciliation
- paid-layer behavior outside the public specs

Passing the public suite is evidence about the active OSS surface only. It is not a certification of unpublished behavior, private extensions, or hosted operational products.

## 6. Neutrality And Permission

The neutral VAR surface must stay implementable without Actenon's permission.

Public conformance should support independent implementation by:

- competitors
- payment rails
- identity providers
- insurers
- guardrail vendors
- agent frameworks
- MCP and protected-tool platforms
- enterprise internal platforms

Actenon may operate commercial services around issuance, approvals, signing,
archive, reporting, and future network or reputation layers. Those services must
not become a permission gate for issuing, verifying, or implementing the neutral
VAR standard.
