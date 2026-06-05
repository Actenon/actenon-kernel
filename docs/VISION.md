# Actenon Vision

## Purpose

Actenon is a proof-required execution layer for consequential actions.

Its job is to sit between decision-making systems and protected endpoints so that the endpoint only executes when the request carries valid proof that the action was evaluated, allowed, and bound to the exact capability being used.

Core principle: No proof, no action.

## Problem

General-purpose agent systems can plan, reason, and request actions, but consequential actions need stronger guarantees than "the caller asked for it."

The kernel exists to enforce the missing guarantees:

- the action request is explicit, typed, and attributable
- policy is evaluated against hard rules, tenant rules, and dynamic context
- the resulting proof is bound to the exact action, tenant, actor, scope, and expiry
- the execution capability is single-purpose, time-bounded, and replay resistant
- refusal and success outcomes are both machine-verifiable and auditable

## Product Definition

The rebuild target is a generic protected execution kernel with the following mandatory capabilities:

- Action Intent admission and validation
- hard rules + tenant rules + dynamic context evaluation
- PCCB minting and verification
- Capability Escrow issuance, release, and consumption
- replay protection
- protected endpoint verification
- refusal envelopes
- receipts
- local proof mode
- one narrow finance wedge implemented end to end

## First Wedge

First wedge: refund execution.

Why this wedge:

- it is consequential and financially sensitive
- it forces exact binding of amount, currency, tenant, actor, and target resource
- it exercises approval, refusal, replay protection, single-use capability release, and receipt emission without requiring a broad payment platform

The first wedge is intentionally narrow:

- a previously recorded payment is the only eligible refund source
- the requested refund amount must not exceed the remaining refundable balance
- the refund currency must match the original payment currency
- the protected refund endpoint must refuse execution if proof, escrow state, replay checks, or policy checks do not line up

## Scope Of This Rebuild

This rebuild is complete when the repository contains a working kernel that can:

1. accept an Action Intent for a refund
2. evaluate hard rules, tenant rules, and dynamic context
3. mint a PCCB only for allowed intents
4. issue a capability through escrow
5. verify proof and escrow state at a protected refund endpoint
6. prevent replays and duplicate execution
7. produce either a refusal envelope or a receipt
8. run fully in local proof mode for deterministic testing and demos

## Non-Goals For The First Pass

- broad multi-action orchestration
- arbitrary tool execution
- general marketplace settlement flows
- multi-region deployment
- external key management or hardware signing
- more than one finance wedge

Those can come later, but they are not required for the kernel to count as complete.

## End State

The end state is a repository where `scripts/verify.sh` is the single rebuild acceptance gate and where passing that gate means the kernel can demonstrate the full proof-required loop for refund execution:

1. intake a valid Action Intent
2. compute policy against static and dynamic inputs
3. mint a PCCB for an allowed action
4. bind that proof to a single-use escrowed capability
5. verify the proof at the protected endpoint
6. execute once or refuse safely
7. emit a refusal envelope or receipt with enough linkage for replay defense and audit

## Quality Bar

The rebuild should optimize for:

- correctness over convenience
- deterministic local execution
- explicit auditability
- minimal trusted surface area
- observability and testability
- clean boundaries between policy, proof, escrow, verification, and execution
