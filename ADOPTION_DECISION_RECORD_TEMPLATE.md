# Adoption Decision Record Template

Use this template when an enterprise architecture, platform, or security team wants to document why it adopted the Actenon Kernel active v1 OSS surface for consequential execution.

This template is intentionally scoped to the open kernel. It does not assume adoption of any paid control-plane product.

---

# ADR: Adopt Actenon Kernel For Proof-Bound Consequential Execution

## Metadata

- ADR ID: `<adr-id>`
- Title: `<decision title>`
- Status: `<proposed | accepted | superseded | rejected>`
- Date: `<yyyy-mm-dd>`
- Decision owners: `<name / team>`
- Reviewers: `<security / platform / architecture / compliance reviewers>`
- Related systems or programs: `<services, tools, endpoints, frameworks>`

## Decision Summary

- Decision:
  `<Adopt the Actenon Kernel active v1 OSS surface for protected execution on the following consequential paths: ...>`
- In scope:
  `<protected tools, protected HTTP endpoints, MCP tools, provider-facing execution routes, internal service actions, etc.>`
- Out of scope:
  `<approvals product, evidence workflow product, provider runtime service, reconciliation operations, dashboard/archive product, billing/admin layer, etc.>`

## Decision Drivers

- Primary driver:
  `<execution-gap closure / security review finding / enterprise control requirement / platform standardization>`
- Secondary drivers:
  `<portability / auditability / verifier-first integration / standards alignment / partner requirement>`
- Non-drivers:
  `<features or workflows this ADR is explicitly not trying to adopt>`

## Context And Problem Statement

### System context

- Consequential actions in scope:
  `<money movement, permission changes, data export, provider operations, other irreversible side effects>`
- Current architecture:
  `<planner/orchestrator/framework/tool/endpoint/provider path>`
- Current upstream controls:
  `<authentication, policy engine, approval workflow, audit logging, idempotency, human review, etc.>`

### Problem statement

Document the execution-boundary problem this ADR is solving.

- What can currently say "allow" upstream?
  `<services, workflow engines, approval systems, orchestrators>`
- What component actually performs the side effect?
  `<tool implementation, provider adapter, HTTP route, worker, service method>`
- What execution-gap risks are material in this system?
  `<parameter substitution, replay, audience misdirection, wrong tenant/subject, stale proof reuse>`
- Why is this problem consequential for this system?
  `<financial, security, customer, operational, or regulatory impact>`

## Why Execution-Edge Verification Matters

Document why the execution edge, not only the upstream control plane, must verify the request.

- Protected execution edge(s) covered by this decision:
  `<list protected tools, routes, or endpoints>`
- Why the execution edge is the final trust boundary in this architecture:
  `<explain where side effects actually happen>`
- Which checks must happen immediately before side effects:
  `<exact action binding, target, audience, tenant, subject, expiry, replay>`
- What would fail open if those checks remained upstream only:
  `<describe realistic failure path>`

## Why Upstream Auth Or Approval Alone Is Insufficient

Document why existing controls do not fully close the execution gap.

### Authentication

- What it proves in this system:
  `<caller identity / session / principal>`
- What it does not prove:
  `<exact action, exact target, exact audience, exact time window at execution>`

### Policy

- What it decides in this system:
  `<action class, policy allow/deny, approval-needed routing>`
- What it does not bind at execution:
  `<exact parameters, single use, replay, audience, tenant, subject>`

### Approval

- What approval means in this system:
  `<human or system approval semantics>`
- Why approval alone is insufficient:
  `<can be replayed, redirected, mutated, or used after context changes>`

## Options Considered

Document the main options that were actually evaluated.

### Option A: Keep current upstream-only controls

- Description:
  `<auth/policy/approval remain upstream; execution edge trusts inherited state>`
- Advantages:
  `<lower immediate change cost, no new execution-edge contract, etc.>`
- Risks or reasons not chosen:
  `<execution gap remains open>`

### Option B: Use internal or framework-specific execution checks only

- Description:
  `<custom middleware, framework-native guard, provider-specific logic>`
- Advantages:
  `<faster local fit, lower near-term implementation effort, etc.>`
- Risks or reasons not chosen:
  `<non-portable, hard to audit, no stable public compatibility target, weak cross-team reuse>`

### Option C: Adopt Actenon Kernel active v1 OSS surface

- Description:
  `<use Action Intent, PCCB, Protected Endpoint, Replay, Receipt, and Refusal on covered paths>`
- Advantages:
  `<portable contract surface, verifier-first model, public conformance target, structured outcomes>`
- Risks or tradeoffs:
  `<integration work, signer/trust-root handling, replay-store requirements, refusal-path handling>`

### Other options considered

- `<option name>`:
  `<summary and why not chosen>`

## Decision

State the decision plainly.

- Chosen option:
  `<Actenon Kernel active v1 OSS surface / alternative>`
- Decision statement:
  `<one clear paragraph>`
- Decision rationale in one sentence:
  `<why this option best addresses consequential execution risk in this architecture>`

## Why The Active v1 Kernel Surface Was Chosen

Document why the active public surface was the right fit.

- Active v1 surfaces adopted:
  - `Action Intent`
  - `PCCB`
  - `Protected Endpoint`
  - `Replay`
  - `Receipt`
  - `Refusal`
- Why these surfaces fit the problem:
  `<map them to the protected execution path>`
- Why reserved surfaces were not part of this decision:
  `<Reconciliation and Policy Bundle are not active v1 compatibility targets>`
- Why a public conformance surface matters:
  `<independent validation, architecture review, vendor neutrality, cross-team reuse>`

## Consequences And Adoption Obligations

Document what adopting this surface requires from the team.

### Engineering obligations

- The execution edge must verify proof before side effects.
- Replay must be enforced on paths that claim duplicate-execution defense.
- Protected endpoints must fail closed and emit structured `Receipt` or `Refusal` artifacts.
- Audience, tenant, subject, and expiry checks must be treated as mandatory security checks, not optional hints.
- Trust roots, signers, verifier configuration, and replay storage must be operated appropriately for the deployment.

### Delivery consequences

- Required code changes:
  `<protected endpoint integration, verifier SDK use, replay store, refusal handling, traceability changes>`
- Required operational changes:
  `<key management, trust-root distribution, observability, runbooks, incident handling>`
- Required testing changes:
  `<conformance run, endpoint tests, replay tests, failure-path tests>`

### Organizational consequences

- Teams must describe compatible scope precisely.
- Teams must not claim reserved-surface compatibility.
- Teams must not describe v1 `Receipt` or `Refusal` as portable cryptographic attestations of origin.

### Adoption obligations checklist

- [ ] every consequential execution path in scope has an identified Protected Endpoint
- [ ] each Protected Endpoint verifies Action Intent and PCCB locally before side effects
- [ ] audience, tenant, subject, expiry, and replay checks are exercised in tests
- [ ] Receipt and Refusal artifacts are retained or exported according to local review requirements
- [ ] compatibility claims are limited to the active v1 surface actually implemented
- [ ] reserved surfaces and paid-layer workflows are not implied by this ADR

## Audit And Compliance Considerations

Document how this decision helps internal review without overstating the control.

- Relevant review drivers:
  `<security architecture review, internal controls, AI governance review, auditability, customer assurance, etc.>`
- How structured artifacts help:
  `<Action Intent, PCCB, Receipt, Refusal, replay evidence, protected-endpoint behavior>`
- Which documents support review:
  - [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
  - [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
  - [THREAT_MODEL.md](THREAT_MODEL.md)
  - [CONFORMANCE.md](CONFORMANCE.md)
  - [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md)
- What this ADR does not claim:
  `<not a certification, not complete framework coverage, not provider-authenticated finality, not paid-layer adoption>`

## Compatibility And Conformance Considerations

Document how the team will make and validate compatibility claims.

- Target compatibility surface:
  `<active v1 only>`
- Planned conformance path:
  `<actenon conformance run / integration tests / release validation>`
- Public compatibility claim, if any:
  `<use safe scoped wording only>`
- Example safe wording:
  `<This service implements the Actenon Kernel active v1 protected-endpoint surface for [specific tool/endpoint/path] and validates that behavior against the public conformance suite.>`
- Explicit non-claims:
  - Reconciliation
  - Policy Bundle
  - hosted approvals or evidence workflows
  - provider-authenticated reconciliation or finality
  - paid-layer behavior outside the OSS specs

## Security And Trust Assumptions

- Issuer and signer trust assumptions:
  `<who can mint proof, how trust roots are configured>`
- Replay-store assumptions:
  `<durability, atomicity, failure handling>`
- Clock assumptions:
  `<expiry / not-before correctness>`
- Adapter trust assumptions:
  `<what happens after control passes beyond the protected endpoint>`

## Implementation Plan

- Initial protected paths:
  `<list services, tools, routes>`
- Rollout phases:
  `<pilot, limited production, broader rollout>`
- Success criteria:
  `<execution-edge verification in place, failure paths exercised, conformance passing, review completed>`
- Rollback or pause conditions:
  `<what would cause the team to stop rollout or revert>`

## Risks And Mitigations

| Risk | Impact | Mitigation | Owner |
| --- | --- | --- | --- |
| `<risk>` | `<impact>` | `<mitigation>` | `<owner>` |
| `<risk>` | `<impact>` | `<mitigation>` | `<owner>` |

## Alternatives Revisit Triggers

List the conditions that would cause this ADR to be revisited.

- `<major contract version change>`
- `<architecture shift>`
- `<new provider or framework boundary>`
- `<change in internal control requirements>`
- `<reserved surface activation that materially changes scope>`

## Approval Record

- Architecture approval:
  `<name / date>`
- Security approval:
  `<name / date>`
- Platform or service owner approval:
  `<name / date>`
- Compliance or governance review, if applicable:
  `<name / date>`

## Notes

- This template is for the Actenon Kernel active OSS surface.
- It should be filled with system-specific facts, not copied as generic language.
- Keep public claims scoped to active v1 compatibility unless a later repository version explicitly expands that scope.
