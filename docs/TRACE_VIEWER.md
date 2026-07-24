# Trace Viewer

The OSS Trace Viewer is the local, read-only, artifact-based viewer for the Actenon Kernel.

It exists to make proof-bound execution tangible without crossing into operational UI territory.

It is one of the fastest ways to see the execution gap as a concrete category problem rather than a whitepaper claim.

It renders:

- Intent Record
- Action Intent
- PCCB
- Receipt
- Refusal
- named incident-simulation explanation artifacts
- replay and protected-endpoint state when present
- execution flow derived from local kernel artifacts

It is a kernel-scoped demo and adoption surface, not the operational product.

## Why It Belongs In OSS

The viewer belongs in the OSS kernel because it renders public kernel artifacts that the repository already emits:

- Action Intent
- PCCB
- Receipt
- Refusal
- protected-endpoint state
- replay-related local state when present
- execution flow reconstructed from those local artifacts

That makes it a natural part of:

- the protected endpoint pattern
- local proof mode
- conformance-adjacent developer understanding
- public adoption and demo value

It does not require hosted services, operator workflow state, or paid-layer runtime infrastructure.

## Fastest Viewer Path

From the repo root:

```bash
make install
actenon-kernel up
actenon-kernel simulate --incident replit
```

Then open:

```text
http://127.0.0.1:8421
```

If you want the viewer to show the original seeded proof lab too, run:

```bash
bash ./scripts/first_run.sh
```

## What It Renders

The viewer renders local artifacts produced by the repo's existing proof paths, including:

- Intent Record
- Action Intent
- PCCB
- Receipt
- Refusal
- execution flow derived from scenario artifacts
- replay entries where local replay state exists
- protected-endpoint state snapshots where local endpoint state exists

## What To Inspect First

Use this order if you are seeing the viewer for the first time:

1. open the `Incident Simulator` run and inspect `weak_control_path`, `proof_bound_path`, `proof_only_gap`, and `bounded_intent_change`
2. open the incident `Intent Record` and compare it to the refusal or receipt emitted beside it
3. open an executed runtime scenario and compare the Action Intent to the PCCB
4. open a refused scenario and inspect the Refusal next to the same flow
5. inspect replay entries and protected-endpoint state for the scenario when present
6. read the execution-flow timeline to see where verification succeeded or where execution stopped

That sequence makes the kernel model visible quickly:

- what the weak-control path would have done
- what bounded machine intent was actually delegated
- what was requested
- what proof was bound
- what outcome artifact was emitted
- where the protected endpoint accepted or refused the request

## Why It Is Read-Only

The viewer is read-only because the OSS kernel publishes:

- contracts
- verifier behavior
- local artifact generation
- reference flows

It does not publish the operational UI.

Read-only behavior keeps the boundary clean:

- the viewer explains what happened
- it does not change what happened

That is the right open-kernel role.

## What It Does Not Do

The OSS Trace Viewer is not:

- an approvals UI
- a policy editor
- an evidence review UI
- a reconciliation UI
- an audit operations dashboard
- a tenant or admin UI
- the operational product

It also does not provide:

- reconciliation operations
- hosted archive or search
- billing
- multi-tenant admin features

## How It Makes The Kernel Tangible

Without a viewer, developers can inspect the JSON files directly.

With the viewer, they can understand the kernel faster:

- where the execution gap was
- how proof-bound execution changed the outcome
- which scenario ran
- what was verified
- which artifact was emitted
- where the protected endpoint acted
- why a refusal or approval-required result occurred

That makes the open kernel easier to try, easier to demo, and easier to adopt.

## Where The Paid UI Begins

The paid control plane UI begins where the product needs operational state and operator action, including:

- approvals
- evidence workflows
- provider runtime operations
- reconciliation operations
- audit operations
- dashboards
- long-term archive
- billing
- enterprise multi-tenancy

The OSS Trace Viewer stops well before that line. It is a local reader for kernel artifacts, not the paid control-plane UI and not a thin starter version of it.

## Related Docs

- [docs/reference/TRACE_VIEWER_BOUNDARY.md](docs/reference/TRACE_VIEWER_BOUNDARY.md)
- [docs/guides/TRACE_VIEWER_LOCAL.md](docs/guides/TRACE_VIEWER_LOCAL.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)
