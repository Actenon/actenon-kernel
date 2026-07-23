# Trace Viewer Local Guide

Local, read-only, artifact-based trace viewer for Actenon Kernel artifacts.

This viewer is for inspecting artifacts already produced by the kernel's local proof paths.

It makes the kernel more tangible by showing:

- what happened
- what was verified
- which artifact was emitted
- why a protected action succeeded, failed, or stopped before execution
- replay and protected-endpoint state when present
- execution flow reconstructed from local artifacts

It does not add approvals, workflows, dashboards, policy editing, reconciliation operations, or any hosted control-plane behavior.

## What It Renders

- Action Intent
- PCCB
- Receipt
- Refusal
- execution flow derived from local proof artifacts
- replay and protected-endpoint state when those artifacts exist

## Why This Lives In OSS

The viewer belongs in the OSS kernel because it renders local artifacts that the repo already produces.

It is:

- read-only
- local-first
- based on public kernel artifacts
- kernel-scoped rather than operator-scoped
- useful for demos, onboarding, and adoption

It is not the operational product.

## Fastest Local Path

From the repo root:

```bash
make install
bash ./scripts/first_run.sh
python3 -m actenon.ui.trace_viewer.app
```

Then open:

```text
http://127.0.0.1:8421
```

Optional second artifact root:

```bash
python3 -m actenon.demo.portable_local_proof --artifacts-dir artifacts/portable_local_proof
```

## Inspect These First

Use this order on a first read:

1. Action Intent and PCCB for an executed scenario
2. the Receipt or Refusal emitted for that scenario
3. replay entries and protected-endpoint state where present
4. the execution-flow timeline

That gives a fast view of the kernel boundary:

- what was requested
- what proof was presented
- what the protected endpoint accepted or refused
- what artifact recorded the result

## Custom Artifact Roots

You can point the viewer at specific local artifact roots:

```bash
python3 -m actenon.ui.trace_viewer.app \
  --artifact-root artifacts/local_proof \
  --artifact-root artifacts/portable_local_proof
```

## Boundary

This viewer is strictly read-only:

- `GET` endpoints only
- local artifact loading only
- no approval or workflow actions
- no hosted services
- no reconciliation operations
- no tenant or billing features

The OSS Trace Viewer is not:

- an approvals UI
- a policy editor
- an evidence review UI
- a reconciliation UI
- an audit operations dashboard
- a tenant or admin UI
- the operational product

Where the paid UI begins:

- approvals
- evidence workflows
- provider runtime services
- reconciliation operations
- audit dashboards and archive
- billing and enterprise multi-tenancy

Related docs:

- [../../TRACE_VIEWER.md](../../TRACE_VIEWER.md)
- [../reference/TRACE_VIEWER_BOUNDARY.md](../reference/TRACE_VIEWER_BOUNDARY.md)
- [../../OPEN_SOURCE_BOUNDARY.md](../../OPEN_SOURCE_BOUNDARY.md)
