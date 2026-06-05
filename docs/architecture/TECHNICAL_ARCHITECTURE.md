# Technical Architecture

Status: architecture doctrine for Actenon kernel deployments. This document describes the intended enforcement model. It does not add production KMS/HSM custody, hosted control-plane behavior, or Actenon Network behavior to the open kernel.

## One-Line Model

Actenon can prevent unproven consequential actions only when those actions are routed through a protected endpoint or equivalent enforcement boundary.

## Architecture At A Glance

```text
untrusted agent / model / tool loop
  -> SDK or middleware convenience layer
  -> Preflight advisory policy check
  -> issuer / control plane signs proof when allowed
  -> Protected Endpoint enforcement boundary
  -> verifier checks proof, binding, lifecycle, replay/escrow, and local policy
  -> Credential Broker releases scoped authority inside the boundary
  -> handler executes or refuses
  -> Receipt / Refusal and evidence records are emitted
  -> optional local external anchor is appended after signing
```

The SDK and Preflight stages can improve adoption and policy quality, but the execution edge is the trust boundary. The decisive question is whether the consequential side effect can happen without the Protected Endpoint or equivalent boundary verifying proof first.

## Runtime Enforcement Doctrine

- The agent is untrusted.
- SDKs and middleware inside the agent process are convenience integration points, not the trust boundary.
- Preflight is advisory unless its decision is connected to protected execution.
- The Protected Endpoint is the enforcement boundary.
- Production agents must not hold standing credentials for consequential production systems.
- The issuer or control plane is the proof root and must use production-grade signing custody in production deployments.
- Local or offline verification must fail closed if keys, proof, audience, action binding, expiry, replay, or escrow cannot be verified.

## Components

### 1. SDK / Middleware In Agent Process

Agent-side SDKs can help construct Action Intents, call Preflight, attach proof material, and route requests. They are not trusted enforcement. A compromised prompt, tool loop, browser controller, coding agent, or host process can ignore client-side checks.

### 2. Preflight Advisory Decision

Preflight classifies the action, evaluates policy, asks for evidence or approval where configured, and can return allow/refuse/advisory results. Preflight alone is not enforcement. It becomes enforceable only when the allowed decision is bound into proof and the Protected Endpoint verifies that proof before side effects.

### 3. Protected Endpoint Enforcement Boundary

The Protected Endpoint is the point where consequential execution is won or lost. It must verify the exact Action Intent and PCCB, enforce audience and expiry, consume replay or escrow state where used, broker credentials, execute or refuse, and emit Receipt/Refusal artifacts.

An equivalent enforcement boundary can be an MCP tool server, browser-action boundary, workflow runner, API adapter, or service endpoint, but only if it performs the same proof verification and refusal behavior immediately before the side effect. Passing proof through an agent or tool chain is not enough if the final executor can still act without checking it.

### 4. Credential Broker

The Credential Broker keeps raw production authority away from agents. In a strong deployment, credentials are short-lived, scoped, and acquired only inside the Protected Endpoint after proof and policy checks pass.

### 5. Issuer / Control Plane

The issuer or control plane evaluates issuance policy and signs proof. Its signing key is the root of proof issuance trust. In production, this must use production-grade signing custody and operational controls. Local proof signers and pilot-local keys are not production custody.

The issuer is a proof root, not an automatic business-correctness oracle. If the issuer or control plane is compromised and signs a bad-but-valid action, the execution edge can still verify cryptographic validity, binding, audience, expiry, and replay state, but it cannot infer that the upstream business decision was correct without additional mitigations.

### 6. Key Discovery Via Well-Known JWK

Verifiers resolve issuer public keys through the configured well-known key discovery origin. The verifier trusts the configured issuer origin, discovered public key material, key purpose, key status, and local verification policy. It does not trust the agent.

### 7. Evidence / Audit Store

Evidence, approvals, policy inputs, mint audit records, replay records, Receipts, and Refusals should be stored durably enough for the deployment's risk. The open kernel provides local primitives and interfaces, not a hosted evidence system.

### 8. External Anchor / Transparency Log

Local external anchors are a working local durability primitive for copied signed outcome artifacts. Hosted transparency logs or network-scale durability are future/deeper layers and are not implemented by the OSS kernel.

### 9. Actenon Network / Hosted Trust Layer

Actenon Network, hosted transparency, reputation layers, and Agent Trust Score are future or separately operated layers. They are not part of the OSS kernel enforcement boundary and must not be treated as a substitute for local Protected Endpoint verification. The Protected Endpoint still verifies proof and refuses locally before side effects; a future network layer can add durability or ecosystem coordination only if separately implemented and documented.

Do not place runtime trust in a future network signal. A future hosted layer may help with discovery, durability, audit operations, or ecosystem coordination, but the local verifier still trusts configured issuer keys and local verification policy at the execution boundary.

## Proof Envelope

The proof envelope must bind the action tightly enough that the Protected Endpoint can refuse substitution or replay. The signed proof path includes:

- action hash using JCS canonicalization
- issuer
- key id
- signature
- tenant
- subject or requester
- audience
- action
- target
- scope and capabilities
- validity window
- nonce or single-use identifier

The verifier must treat missing, malformed, unverifiable, wrong-audience, wrong-action, expired, or replayed proof as a refusal condition.

## Identity Model

Actenon is not an identity provider.

Deployments should bind tenant, subject, requester, audience, action target, and scope into proof. Where possible, deployments should integrate with existing identity systems such as SPIFFE, OAuth, OIDC, DPoP, SSO, or IAM rather than inventing new identity roots inside Actenon.

Actenon verifies consistency and binding at the execution boundary. It does not prove that upstream identity attribution was correct before proof issuance.

## Policy Model

Policy should be:

- deny by default
- consequence-classified
- evaluated at issuance
- re-checked at the edge where possible
- bound into signed proof and Receipt/Refusal evidence when approval or evidence is used

Approval and evidence are strongest when the exact approval/evidence identifiers or digests are bound into the proof and outcome artifact. Free-floating approval logs are useful, but they do not by themselves protect the execution edge.

## Minimum Strong Deployment Invariant

A strong Actenon deployment has all of the following:

- the agent cannot reach the consequential production system with standing credentials
- the side effect is reachable only through a Protected Endpoint or equivalent boundary
- the boundary verifies signed proof for the exact action, audience, tenant, subject/requester, target, scope, validity window, and nonce
- replay or escrow state is consumed where the route requires single-use execution
- production credentials are brokered only after proof and policy checks pass
- allowed and refused decisions emit durable Receipt/Refusal artifacts
- degraded verification, missing key material, missing proof, or missing brokered authority fails closed

If any of those are absent, the deployment may still be useful for migration, demos, or advisory visibility, but it should not be described as preventing unproven consequential actions.

## Protected Runtime Sequence

```text
agent request
  -> Action Intent
  -> Preflight / policy evaluation
  -> issuer signs PCCB when allowed
  -> Protected Endpoint receives request + proof
  -> verifier checks issuer key, signature, audience, tenant, subject, action hash, scope, and validity
  -> replay / escrow is consumed where used
  -> Credential Broker releases scoped authority inside the boundary
  -> handler executes or refuses
  -> Receipt / Refusal is emitted
  -> evidence / audit store records the outcome
  -> optional local external anchor is appended after signing
```

## Fail-Closed Rules

A protected deployment must refuse when any required enforcement input is absent or unverifiable:

- no proof = refuse
- no key = refuse
- key discovery cannot verify = refuse
- wrong issuer/key purpose/status = refuse
- no audience match = refuse
- no tenant/subject/requester match = refuse
- no action or target match = refuse
- expired or premature proof = refuse
- missing or invalid replay/escrow state where required = refuse
- credential broker cannot release scoped authority = refuse
- policy requires approval/evidence and it is missing or unbound = refuse

Degraded mode is not a reason to execute consequential actions. If the verifier cannot establish the proof boundary, execution must stop.

## What Actenon Adds

Actenon adds proof-bound execution at the consequential action boundary:

- exact action binding
- local verifier enforcement
- replay or escrow enforcement where deployed
- credential brokering inside the enforcement boundary
- structured Receipt/Refusal artifacts
- optional signed outcome attestations and local external anchors
- future hosted network or transparency integrations only when separately implemented and documented

## What Actenon Does Not Add By Itself

- Actenon cannot stop actions that bypass it through standing credentials.
- Actenon cannot make a bad-but-authorized action good.
- Actenon cannot stop a model from attempting a bad action.
- Actenon cannot protect production if the issuer key or control plane is compromised without additional mitigations.
- Preflight alone is not enforcement.
- SDK-only or client-side-only integration is not enforcement.
- The OSS kernel does not provide hosted transparency, Actenon Network, Agent Trust Score, or production KMS/HSM custody.
- A hosted network or transparency layer, if later deployed, does not replace local proof verification at the Protected Endpoint.

## Related Documents

- [TRUST_BOUNDARIES.md](TRUST_BOUNDARIES.md)
- [DEPLOYMENT_ARCHITECTURES.md](DEPLOYMENT_ARCHITECTURES.md)
- [BYPASS_RESISTANCE.md](BYPASS_RESISTANCE.md)
- [REPLAY_ESCROW_CONCURRENCY.md](REPLAY_ESCROW_CONCURRENCY.md)
- [PRODUCTION_SIGNING_CUSTODY.md](PRODUCTION_SIGNING_CUSTODY.md)
- [ISSUER_SECURITY_MODEL.md](ISSUER_SECURITY_MODEL.md)
- [../operations/KEY_LIFECYCLE_RUNBOOK.md](../operations/KEY_LIFECYCLE_RUNBOOK.md)
- [../../THREAT_MODEL.md](../../THREAT_MODEL.md)
- [../guides/CREDENTIAL_BROKER_DEPLOYMENT.md](../guides/CREDENTIAL_BROKER_DEPLOYMENT.md)
- [../reference/ecosystem/SIGNER_KMS_SPEC.md](../reference/ecosystem/SIGNER_KMS_SPEC.md)
- [../../spec/protected-endpoint/SPEC.md](../../spec/protected-endpoint/SPEC.md)
