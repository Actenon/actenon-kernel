# Open Source Boundary

This repository is the open kernel. It is not the paid control plane.

The paid layer can build on the kernel, but it must not collapse the public kernel into a hosted control plane.

The company story is now explicit:

- Actenon Kernel is the open standard and reference implementation for receipts for consequential agent actions.
- Actenon Cloud is the managed issuer and control plane for consequential action governance, beginning with governed invoice-payment execution.
- The accepted v2 keystone proves Cloud can issue proof and outcome artifacts that the open Kernel independently verifies for origin, integrity, and mutation failure.

The standard doctrine is:

```text
Neutralize the standard. Monetize the operation.
```

VAR, the Verifiable Action Receipt standard surface, must remain open and
independently implementable. Actenon may monetize operated services around VAR,
but not permission to issue, verify, or implement VAR.

## License Posture

The open kernel/spec/conformance repository is licensed under Apache-2.0.
Apache-2.0 supports neutral infrastructure adoption because it is permissive
and includes an explicit contributor patent grant and defensive patent
termination language. That makes the public standard surface easier for
frameworks, enterprises, competitors, and regulated adopters to evaluate.

This license migration applies to the open repository only. It does not change
the licensing, ownership, or commercial terms for Actenon Cloud, private
control-plane code, operated services, managed signing, hosted archive,
hosted trust-network services, enterprise workflows, or future paid products.

## Neutral/Open/Free

The neutral open surface includes:

- VAR specification
- reference verifier
- canonicalization profile
- wire contracts
- conformance suite
- conformance vectors
- compatibility policy
- local proof and verification primitives
- public schemas and behavior specs
- local protected-endpoint, replay, escrow, and credential-broker primitives

## Commercial/Operated

The commercial operated surface includes:

- Actenon Cloud / Control Plane
- managed KMS/HSM signing
- approvals and evidence workflows
- hosted archive
- hosted trust network
- anchoring/clearing
- Agent Trust Score
- insurer and compliance reporting
- enterprise support
- managed tenant operations and rollout services

Future commercial layers are not prerequisites for local verification or
VAR-compatible implementation.

## OSS Kernel Owns

- public specs
- schemas
- verifier SDKs
- local proof mode
- replay, refusal, and receipt primitives
- protected endpoint patterns, including local examples that can hold or broker credentials after proof verification
- local single-use capability and escrow primitives for brokered execution paths
- local issuer-side PCCB mint audit hooks and append-only local audit records
- conformance
- example integrations
- read-only local artifact viewers for kernel-emitted traces, execution flow, and replay or protected-endpoint state

## Paid Control Plane Owns

- approvals
- evidence workflows
- managed proof issuance and tenant operations
- managed credential-broker operations and customer-specific protected executor rollout
- provider runtime services
- reconciliation operations
- hosted transparency or network-scale audit services
- long-term archive
- dashboards
- audit operations
- billing and tenant administration
- enterprise multi-tenancy

## Practical Boundary Rule

If a feature requires any of the following, it belongs in the paid control plane rather than this repository:

- hosted mutable workflow state
- provider runtime operations
- long-lived operational services
- enterprise tenant administration
- billing or account management
- operator dashboards or archive systems

If a feature only renders local kernel artifacts in a read-only way, it can still fit the OSS boundary.

Proof binding happens at the protected endpoint in this repository's public model. Replay protection only helps where the protected endpoint actually enforces the replay path.

The strongest deployment removes standing production credentials from agents.
In that pattern, the protected endpoint holds or brokers the privileged
credential only after proof and policy verification succeed. The OSS kernel can
implement that credential-broker boundary locally; the paid Cloud layer adds
managed approvals, signing, audit/archive, tenant operations, reporting, and
operated trust-network services when those services exist.

Issuer-side mint audit logging also belongs in OSS when it is a local hook or local append-only artifact. Hosted transparency, audit operations, long-term retention, alerting, and enterprise search remain paid-layer concerns.

Outcome attestation verification belongs in OSS when it verifies copied Receipt
or Refusal artifacts against published issuer verification material. Managed
issuance, approval operations, hosted artifact retention, hosted transparency
logs, RFC-3161-style timestamping, hosted trust-network inclusion, and
cross-organization operating workflows remain Cloud or future paid-network
concerns.

That is why the OSS Trace Viewer belongs here:

- it reads local kernel artifacts
- it helps developers inspect Action Intent, PCCB, Receipt, Refusal, replay entries, protected-endpoint state, and execution flow
- it does not approve, edit, reconcile, administer, or operate anything

If a feature can be published as a portable contract, verifier-edge primitive, local reference flow, or conformance surface, it likely belongs here.

## Why The Boundary Is Product-Defining

This is not an accidental split.

The open repository must remain:

- portable
- inspectable
- independently adoptable
- credible as a public standard

The paid layer can build on the kernel, but it should not absorb the kernel or turn the public repository into a disguised control plane.

Local verification does not require Cloud. Cloud-issued artifacts can be copied
out and verified by the open Kernel when the verifier has the artifact, the
issuer well-known key material, and the asymmetric verification extra installed.

## What This Repository Does Not Solve

- it does not prove that an issuer, signer, or external control plane made the correct business decision before proof was minted
- local mint audit records improve retrospective detectability when configured; they do not prevent compromised issuance or provide hosted transparency
- it does not make downstream adapters truthful after control passes to them
- it does not stop side-door execution if agents still hold standing production
  credentials that bypass the protected endpoint
- v1 Receipt and Refusal artifacts are canonical structured artifacts; copied
  origin verification requires the opt-in outcome-attestation envelope
- provider-backed reconciliation or finality is not part of active v1
- reserved surfaces such as Reconciliation and Policy Bundle are named extension boundaries, not active v1 standards
- hosted trust-network anchoring, transparency logs, long-term archive, and
  managed compliance operations are not implemented in the OSS kernel
