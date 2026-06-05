# For Security Leaders

**Control the blast radius of AI agents before actions become side effects.**

Actenon is built for a simple security problem: AI systems are no longer just producing text. They are calling tools, touching APIs, changing records, deploying code, exporting data, submitting forms, sending messages, and initiating actions that can affect real systems.

The risk is not only what the model says. The risk is what connected systems allow the model, agent, tool, or automation to do.

Actenon provides an execution-boundary control:

> **No valid proof, no execution.**

A protected endpoint refuses consequential actions unless it can verify proof bound to the exact action being attempted.

---

## The problem

Many agent systems inherit standing authority from the tools and APIs connected to them.

That means an agent may be able to trigger actions such as:

- deleting or modifying production data
- exporting sensitive records
- sending external communications
- changing access or permissions
- approving payments or refunds
- deploying or modifying infrastructure
- submitting forms through a browser or computer-use workflow
- executing MCP tool side effects

Most organisations already have identity, authentication, policy, approval, API gateways, service mesh, logging, and human workflow controls.

Those controls matter, but they do not always prove that the final execution edge performed the exact approved action, with the exact approved parameters, exactly once.

That missing control point is the execution gap.

---

## The control

Actenon adds proof-bound execution at the protected endpoint.

A consequential action is only allowed when the endpoint verifies proof bound to the exact:

- action
- parameters
- target
- tenant
- subject
- audience
- scope
- expiry
- replay identity
- policy boundary, where configured

If proof is missing, expired, replayed, audience-mismatched, action-mismatched, parameter-mismatched, tenant-mismatched, subject-mismatched, or policy-denied, the endpoint refuses before the side effect happens.

The agent can request the action. The protected endpoint decides whether the action executes.

---

## The evidence

Actenon emits structured artifacts:

- **Receipt** — evidence that a specific action executed under a defined proof and policy boundary.
- **Refusal** — evidence that a requested action was blocked before the side effect because proof verification failed or policy denied execution.

These artifacts are designed to support audit, compliance, incident review, and trust in agent-connected systems.

---

## The strongest deployment pattern

The strongest pattern removes standing production credentials from the agent path.

```text
agent
  ↓
protected endpoint
  ↓
proof verification
  ↓
policy / replay / escrow boundary
  ↓
credential broker
  ↓
single-use or scoped credential
  ↓
production system
  ↓
Receipt or Refusal
```

In this model, the agent does not hold raw production credentials that can bypass the protected endpoint.

If an agent still has a direct production credential that can reach the provider outside the protected endpoint, Actenon can still produce useful proof, receipts, and refusals for the protected route — but it cannot stop side-door execution on an unprotected path.

---

## What Actenon helps answer

For a security leader, Actenon helps answer:

- Where can AI agents trigger consequential actions?
- Which actions are routed through a protected endpoint?
- Which actions were refused before side effects?
- Which actions executed with valid proof?
- What evidence exists after an action or refusal?
- Are credentials brokered after verification rather than held directly by the agent?
- Can we distinguish consequence-class risk from proven vulnerability claims?

---

## What Actenon does not claim

Actenon does **not** claim to:

- prevent all prompt injection
- prevent all unsafe AI behavior
- stop a model from trying to act
- make a bad-but-authorized action good
- protect actions that bypass the protected endpoint
- replace IAM, OAuth, API gateways, service mesh, logging, or human approvals
- prove downstream provider finality
- prove every external provider behaved honestly after handoff
- certify that a repository is vulnerable
- prove real-world exploitability or production exposure from static scanner output
- claim regulator recognition, insurer endorsement, hosted transparency, or production KMS/HSM custody in the open-source kernel

Actenon’s claim is narrower and testable:

> If a consequential action is routed through an Actenon-protected endpoint, it cannot execute unless valid proof is verified for that exact action.

---

## Scanner posture

Actenon includes a local advisory scanner that maps candidate AI-controlled consequential action paths.

The scanner is a map, not a verdict.

It does not accuse a repository of being vulnerable. It does not prove runtime reachability, exploitability, production exposure, or business impact.

It asks:

> If an agent can reach this path, could it cause a consequential side effect without proof-bound execution?

Scanner findings should use consequence-class language:

```text
Critical-impact candidate action path, if reachable and ungated.
Not a vulnerability claim.
Runtime reachability not proven.
Exploitability not proven.
Suggested control: require proof before the side effect.
```

---

## How to evaluate Actenon

A practical security review should ask:

1. Are consequential actions routed through protected endpoints?
2. Does verification happen at the execution boundary, not only in client middleware?
3. Is proof bound to the exact action and parameters?
4. Are tenant, subject, audience, expiry, and replay checks enforced?
5. Are missing, expired, replayed, action-mismatched, and audience-mismatched proofs refused?
6. Are Receipt and Refusal artifacts emitted?
7. Are standing credentials removed from the agent path or brokered after verification?
8. Are limits and non-claims clearly documented?
9. Does CI pass?
10. Does the release gate pass from a clean public clone?

---

## Start here

- [README](../../README.md)
- [The Execution Gap](../../THE_EXECUTION_GAP.md)
- [Threat Model](../../THREAT_MODEL.md)
- [Kernel Guarantees](../../KERNEL_GUARANTEES.md)
- [Open Source Boundary](../../OPEN_SOURCE_BOUNDARY.md)
- [Execution Gap Scanner Methodology](../guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md)
- [Credential Broker Deployment](../guides/CREDENTIAL_BROKER_DEPLOYMENT.md)
- [Trust Boundaries](../architecture/TRUST_BOUNDARIES.md)
