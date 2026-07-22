# Trust Boundaries

Status: trust-boundary doctrine for Actenon deployments. This document describes where Actenon enforcement lives and what must not be trusted. It does not make a production-readiness claim for the OSS kernel.

## Boundary Summary

| Component | Trust posture | Enforcement role |
| --- | --- | --- |
| Agent / model / tool loop | Untrusted | May request action, but must not be able to execute consequential production actions directly. |
| SDK / middleware in agent process | Convenience only | Helps construct, route, or verify locally, but is not the security boundary. |
| Preflight | Advisory until bound | Evaluates policy and evidence. Enforcement requires signed proof plus protected execution. |
| Protected Endpoint | Enforcement boundary | Verifies proof, checks replay/escrow/policy, brokers credentials, executes or refuses. |
| Credential Broker | Authority boundary | Releases scoped credentials only after protected checks pass. |
| Issuer / control plane | Proof root | Decides whether proof may be minted and protects signing keys. |
| Well-known key discovery | Verification trust input | Publishes public verification keys and key lifecycle state. |
| Evidence / audit store | Audit boundary | Stores policy evidence, approvals, mint records, Receipts, Refusals, and replay records. |
| External anchor / transparency log | Durability layer | Local anchors exist; hosted transparency/network durability is future. |
| Actenon Network / reputation layer | Future hosted layer | Not an OSS kernel enforcement boundary; cannot replace local Protected Endpoint verification. |

## Boundary Map

```text
[untrusted agent process]
  model / planner / tool loop / browser controller / SDK helper
        |
        v
[advisory policy and issuance]
  Preflight + issuer/control plane + signed proof
        |
        v
[trusted execution boundary]
  Protected Endpoint or equivalent tool/action boundary
  verifier + replay/escrow + Credential Broker
        |
        v
[consequential side effect]
  provider, database, filesystem, browser portal, workflow, payment, access grant
        |
        v
[evidence and durability]
  Receipt / Refusal, audit store, optional local external anchor
```

The boundary that matters is the transition from an agent-selected action to a side effect. That transition must pass through proof verification and refusal behavior. Anything before that boundary is helpful only if the final executor cannot bypass it.

## Agent Is Untrusted

The agent can be useful, but it is not a trusted principal for consequential execution. Treat the following as untrusted:

- model outputs
- tool plans
- function-call arguments
- browser or computer-use actions
- coding-agent shell/file operations
- agent memory
- agent-hosted SDK checks
- agent-side Preflight results

The agent may ask for proof. It must not be able to bypass proof with raw production credentials.

## SDK Is Not The Trust Boundary

SDKs, middleware, and client libraries are developer ergonomics. They can:

- build Action Intents
- call Preflight
- attach PCCBs
- verify local artifacts for developer feedback
- route calls to a protected endpoint

They must not be treated as the final enforcement point if they run in the same process or account as the agent. Client-side checks can be skipped, patched, prompted around, or bypassed by direct credential use.

Do not make an enforcement claim for SDK-only deployment. The SDK can help build the correct request, but it does not stop an agent process that can call the provider directly.

## Preflight Is Advisory Unless Connected To Protected Execution

Preflight is valuable because it classifies consequences, gathers policy inputs, and can request approval or evidence. It is not sufficient by itself.

Preflight becomes enforceable when:

1. the issuer signs a PCCB for the exact allowed action,
2. approval/evidence identifiers or digests are bound into the proof or outcome records where used,
3. the Protected Endpoint verifies that proof before side effects.

Preflight without protected execution is an upstream advisory control.

## Protected Endpoint Is The Enforcement Boundary

The Protected Endpoint is trusted to refuse or execute. It must:

- verify the issuer signature and key lifecycle state
- verify audience, tenant, subject/requester, action, target, scope, action hash, expiry, and nonce
- re-check local policy where possible
- consume replay or escrow state where required
- call the Credential Broker only after verification succeeds
- execute the handler only inside the protected boundary
- emit Receipt or Refusal artifacts

If the Protected Endpoint cannot verify required proof or state, it must fail closed.

## Credential Broker Is Mandatory For Strong Production Deployment

Strong deployment requires no standing production credentials in the agent runtime.

The Credential Broker should:

- hold or access raw provider authority outside the agent process
- release only short-lived scoped authority
- release credentials only after proof and policy checks pass
- keep raw secret material out of Receipts, Refusals, logs, exceptions, and agent-visible responses
- prefer vault, KMS, IAM, OAuth, OIDC, DPoP, or provider-native short-lived credentials

If the agent still holds a raw credential that can reach production directly, Actenon cannot stop that bypass path.

This is a mandatory deployment requirement for strong enforcement claims, not merely a best practice. During migration, a protected path and a standing-credential side door can coexist, but receipts and refusals cover only the protected path.

## Issuer / Control Plane Is The Proof Root

The issuer or control plane decides whether proof may exist. Its signing key is the root of proof issuance trust.

Production deployments must treat the issuer/control plane as high-value infrastructure:

- protect signing keys with production-grade custody
- separate pilot/local signing from production signing
- rotate and revoke keys with documented lifecycle behavior
- publish key purpose and lifecycle state through well-known key discovery
- audit mint decisions and policy inputs
- minimize who or what can request proof issuance

The OSS kernel includes local and pilot signing paths for tests and demos. Those are not production signing custody.

Production signing custody is a deployment responsibility in this architecture pass. This document does not claim that the OSS kernel by itself provides KMS, HSM, managed custody, separation of duties, or hosted issuer operations.

## Verifier Trusts Keys And Policy, Not The Agent

The verifier trusts:

- configured issuer origins
- well-known public key material
- key id, purpose, algorithm, status, and lifecycle metadata
- local verification policy
- local replay/escrow state where used

The verifier does not trust:

- the agent's statement that approval happened
- the agent's selected audience
- the agent's raw tool parameters
- Preflight output unless it is bound into proof and checked at the edge

## Cloud / Control Plane Boundary

The open kernel does not require a hosted control plane. If a Cloud/control-plane deployment exists, it must be treated as high-value infrastructure because it can influence proof issuance.

Compromise of the issuer key or control plane can cause valid proof to be minted for the wrong action. Actenon cannot make that valid proof morally or operationally correct without additional mitigations such as stronger issuer custody, separation of duties, independent approval, mint audit, anomaly detection, revocation, and external anchoring.

## Evidence And Audit Boundary

Evidence and audit stores should be protected from agent write access except through explicit application interfaces. They should preserve:

- policy decision inputs
- approval and evidence references
- PCCB mint audit records
- replay and escrow state transitions
- Receipts and Refusals
- optional outcome attestations
- optional local external anchors

Evidence is strongest when identifiers or digests are bound into signed proof or outcome artifacts.

## Future Boundary: External Anchor / Transparency Log

The OSS kernel includes local external anchors as a local durability primitive. Hosted transparency logs, network-scale anchoring, reputation layers, and Agent Trust Score are future layers unless separately implemented and documented.

Do not describe future network or reputation layers as active kernel guarantees.

## Network Is Not The Enforcement Boundary

Actenon Network, hosted transparency, and reputation services are not active OSS kernel guarantees. Even if a future hosted layer publishes anchors, reputation signals, or ecosystem coordination, the verifier still trusts configured issuer keys and local verification policy, not the agent and not a remote grade. The Protected Endpoint remains the place where proof is checked and execution is refused before side effects.

Do not move enforcement claims from the Protected Endpoint to a future network layer.

The future network layer is therefore outside the runtime trust boundary unless a deployment separately implements and documents it. Even then, local proof verification remains required before consequential execution.

## Fail-Closed Boundary Rule

The verifier and Protected Endpoint must refuse if required material cannot be verified:

- no key
- no proof
- no audience match
- no action match
- no tenant/subject/requester match
- no valid expiry window
- no valid replay or escrow state where required
- no credential broker release where required

Fail-open degraded mode is not compatible with strong Actenon deployment.

## Claims To Avoid

- "The SDK prevents consequential actions" when the agent can bypass it.
- "Preflight blocked execution" unless the Preflight decision was bound into proof and checked at the Protected Endpoint.
- "The network protected the action" when local proof verification did not happen before execution.
- "Actenon protects production" while the agent still holds standing credentials to the production provider.
- "A valid proof means the business decision was correct" when it only proves signed authorization material matched local verification policy.

## Related Documents

- [TECHNICAL_ARCHITECTURE.md](TECHNICAL_ARCHITECTURE.md)
- [DEPLOYMENT_ARCHITECTURES.md](DEPLOYMENT_ARCHITECTURES.md)
- [BYPASS_RESISTANCE.md](BYPASS_RESISTANCE.md)
- [PRODUCTION_SIGNING_CUSTODY.md](PRODUCTION_SIGNING_CUSTODY.md)
- [ISSUER_SECURITY_MODEL.md](ISSUER_SECURITY_MODEL.md)
- [../operations/KEY_LIFECYCLE_RUNBOOK.md](../operations/KEY_LIFECYCLE_RUNBOOK.md)
