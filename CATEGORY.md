# Proof-Bound Consequential Execution

## Category Definition

Proof-bound consequential execution is the category for systems that require the execution edge to verify portable proof before carrying out a consequential action.

A consequential action is any action where incorrect execution is materially unsafe or costly, including:

- money movement
- permission or entitlement changes
- account recovery or admin override
- destructive operations
- sensitive data export
- provider or infrastructure calls with irreversible effects

In this category, authorization is not complete when a caller is authenticated, when a policy engine says `allow`, or when an approval exists somewhere upstream. Authorization is complete only when the protected endpoint verifies proof bound to the exact action it is about to execute.

## Why This Category Exists

Agent systems are moving from advisory behavior into direct execution. They now call tools, initiate provider actions, modify state, and trigger irreversible operations.

Most current stacks still stop at some mix of:

- authentication
- policy evaluation
- approval workflow state
- audit logs
- idempotency keys
- orchestrator routing

Those controls are necessary, but they do not by themselves guarantee that the execution edge will perform the exact approved action exactly once.

Proof-bound consequential execution exists to close that gap.

## Category Primitives

This category needs a small public vocabulary that independent implementations can share:

- Action Intent: the public request for a consequential action
- PCCB: the proof artifact a protected endpoint verifies before side effects
- Receipt: the canonical structured outcome artifact
- Refusal: the canonical structured failure artifact
- Protected Endpoint: the execution edge that verifies proof before side effects
- Replay: the duplicate-execution defense model

In v1, Receipt and Refusal are canonical structured artifacts, not portable cryptographic attestations of origin.

## What Counts As A Category System

A system belongs in this category if it does all of the following:

- accepts a typed, attributable action request
- evaluates that request before execution
- mints or obtains proof only after a positive decision
- binds proof to the exact action, target, tenant, subject, audience, scope, expiry, and nonce
- routes consequential execution through a protected endpoint that verifies that proof before side effects
- defends the execution edge against replay or duplicate use
- emits structured receipts and refusals

If a system can still perform a consequential action safely only because an internal service said "yes" earlier, it is adjacent to this category, not inside it.

## What This Repository Defines

This repository is the open product for the category:

- the canonical kernel
- the public spec surface
- the reference verifier implementation
- the conformance base
- the protected endpoint pattern
- the canonical receipt/refusal artifact model

Its role is to be the default open standard and default developer entry point for proof-bound consequential execution.

## What This Repository Does Not Define

This repository does not define the hosted product layer around the kernel.

That separate layer may include:

- approvals and workflow routing
- evidence collection and review
- provider runtime services
- reconciliation operations
- long-term archive
- dashboards and audit operations
- billing and tenant administration
- enterprise multi-tenancy

That separation keeps the standard portable, credible, inspectable, and independently adoptable.
