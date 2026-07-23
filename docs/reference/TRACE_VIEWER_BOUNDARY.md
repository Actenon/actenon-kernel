# Trace Viewer Boundary

## Purpose

This document defines the product boundary for the OSS Trace Viewer.

The viewer is part of the open kernel repo because it helps developers inspect local kernel artifacts. It must not become the operational UI for the paid control plane.

## Why The Viewer Belongs In OSS

The viewer belongs in OSS because it operates on public, local, already-emitted kernel artifacts:

- Action Intent
- PCCB
- Receipt
- Refusal
- protected-endpoint state
- replay-related local state
- execution flow derived from artifact relationships

It is:

- local
- read-only
- artifact-based
- kernel-scoped
- inspectable
- portable
- useful for demos and adoption

Those are open-kernel qualities.

## What The OSS Viewer Does

The OSS viewer may:

- read local artifact roots
- render kernel artifacts
- summarize execution flow
- show why a protected action succeeded or failed
- show what the protected endpoint verified
- display replay and protected-endpoint state when those artifacts already exist

## What The OSS Viewer Must Not Do

The OSS viewer must not become:

- an approvals UI
- a policy editor
- an evidence review UI
- a reconciliation UI
- an audit operations dashboard
- a tenant or admin UI
- the operational product

It must also not add:

- operator actions
- mutable workflow state
- hosted search or archive
- reconciliation operations UI
- billing UI
- multi-tenant administration

## Why Read-Only Matters

Read-only is not a temporary product compromise. It is the boundary.

If the viewer could mutate workflow state, assign work, change policy, approve actions, or operate provider workflows, it would stop being a kernel artifact viewer and start becoming the paid control-plane UI.

Read-only keeps the OSS product aligned with what the kernel actually owns:

- verifier-edge behavior
- public artifacts
- protected-endpoint understanding
- local demo value

## Where The Paid UI Begins

The paid control plane UI begins where users need to:

- approve or reject actions
- review or collect evidence
- operate provider runtimes
- work reconciliation cases
- manage tenants or billing
- search long-term audit archives
- run operational queues and dashboards

That UI is outside this repository.

## Practical Rule

If a viewer feature only helps a developer understand local kernel artifacts, it likely belongs in OSS.

If a viewer feature requires an operator to change system state or manage live operational workflows, it belongs in the paid control plane.

If a viewer feature primarily turns the viewer into an approval, reconciliation, or audit operations console, it does not belong here even if it starts from the same artifacts.
