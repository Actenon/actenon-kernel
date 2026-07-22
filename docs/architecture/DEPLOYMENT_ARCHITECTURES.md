# Deployment Architectures

Status: deployment doctrine for Actenon architecture reviews. This document describes recommended and non-recommended deployment patterns. It does not claim the OSS kernel includes hosted production operations, production KMS/HSM custody, Actenon Network, or Agent Trust Score.

## Core Deployment Rule

Actenon can prevent unproven consequential actions only when those actions are routed through a protected endpoint or equivalent enforcement boundary.

If an agent can still call the production provider directly with standing credentials, Actenon can protect and receipt the protected path, but it cannot stop the bypass path.

## Minimum Strong Deployment

A deployment should make strong prevention claims only when all of these are true:

- agent runtimes do not hold standing production credentials
- consequential side effects are reachable only through a Protected Endpoint or equivalent boundary
- Preflight or policy decisions are bound into signed proof when they are relied on
- the boundary verifies tenant, subject/requester, audience, action, target, scope, expiry, nonce, issuer key, and action hash
- replay or escrow state is enforced where the route requires single-use execution
- credentials are brokered only after proof and policy verification
- Receipt/Refusal artifacts are emitted for allowed and blocked outcomes
- degraded verification, missing keys, missing proof, missing brokered authority, or unverifiable state refuses execution

Anything less can still be useful as a migration, local demo, scanner finding, or partial control, but it should be named as partial.

## Pattern 1: Unprotected Agent With Standing Credentials

```text
agent -> standing credential -> production system
```

Trust posture:

- agent is untrusted
- no protected execution boundary
- no proof verification before side effect
- no Credential Broker
- no Receipt/Refusal guarantee

This is outside strong Actenon deployment. The scanner may still identify candidate action paths, but enforcement is absent.

## Pattern 2: SDK-Only Or Client-Side Checks

```text
agent process
  -> SDK / middleware / local Preflight
  -> standing credential
  -> production system
```

Trust posture:

- SDK improves developer ergonomics
- client-side Preflight is advisory
- agent process remains able to bypass checks
- standing credential remains the side door

This is not an enforcement architecture. It may help adoption, logging, or developer feedback, but it should not be described as Actenon preventing consequential actions.

Preflight in this pattern is advisory. It can produce useful policy decisions, but those decisions do not stop execution unless the final side-effecting boundary refuses without matching proof.

## Pattern 3: Weak Protected Endpoint With Side Door

```text
agent -> protected endpoint -> production system
agent -> standing credential -> production system  [bypass remains]
```

Trust posture:

- protected endpoint can enforce proof for the routed path
- bypass path still exists
- receipts/refusals cover only the protected path

This is a partial deployment. It can be useful during migration, but the standing credential must be removed before making strong enforcement claims.

## Pattern 4: Strong Protected Endpoint With Credential Broker

```text
agent
  -> Action Intent
  -> Preflight / issuer
  -> PCCB
  -> protected endpoint
  -> verifier + replay/escrow + Credential Broker
  -> scoped credential
  -> production system
  -> Receipt / Refusal
```

Trust posture:

- agent remains untrusted
- protected endpoint is the enforcement boundary
- production credentials stay outside the agent runtime
- Credential Broker releases scoped authority only after proof and policy checks pass
- side effect happens only after local verification
- Receipt/Refusal artifacts record allowed or blocked outcomes

This is the recommended strong deployment pattern.

The agent may still initiate the request, but it cannot complete the side effect with its own standing authority. The Protected Endpoint, not the agent process, holds the final execution decision.

## Pattern 5: MCP Or Tool Server Boundary

```text
agent -> MCP/tool call -> protected tool boundary -> brokered authority -> side effect
```

For consequential tools, the MCP server or tool handler should behave like a Protected Endpoint:

- verify proof for the exact tool call
- bind audience to the tool boundary
- enforce action, target, tenant, subject/requester, scope, expiry, and nonce
- consume replay or escrow state where used
- broker credentials after verification
- emit Receipt or Refusal

Forwarding proof through a tool chain is not enough if the final tool can act without checking it.

## Pattern 6: Browser Or Computer-Use Agent Boundary

```text
agent -> browser/computer-use controller -> protected action boundary -> portal/provider
```

Authenticated browser clicks, form submits, file uploads/downloads, portal operations, and desktop actions can be consequential. Strong deployment should move high-impact browser/computer-use actions behind an enforcement boundary:

- classify consequence in Preflight
- bind the intended portal action into proof
- broker portal/session credentials outside the agent where practical
- verify proof before the final click/submit/action
- emit Receipt/Refusal

If the agent holds the authenticated browser session and can click directly, Actenon cannot stop that bypass path.

## Offline And Local Verification

Local/offline verification is useful for copied artifacts, conformance vectors, and disconnected review. It must fail closed when verification material is absent or unverifiable:

- no trusted issuer key = fail
- well-known key discovery fails = fail
- wrong key id, algorithm, purpose, status, or issuer = fail
- signature cannot verify = fail
- action hash or signed payload has changed = fail
- hard-revoked key recovery lacks valid required anchor = fail or return a documented non-success state

Offline verification proves origin/integrity of the artifact under the configured trust root. It does not prove business correctness, provider finality, or runtime reachability.

Do not use offline verification failure as an advisory warning while still executing. Local and offline verification are fail-closed paths: if the verifier cannot establish keys, proof, signature, action binding, lifecycle state, or required anchor recovery, the result is refusal or a documented non-success verification state.

## Issuer / Control Plane Deployment

The issuer/control plane is high-value infrastructure because it can cause proof to exist.

Production issuer deployments should include:

- production-grade signing custody
- key rotation, suspension, revocation, and hard-revocation procedures
- well-known public JWK publication
- purpose-separated keys for proof issuance and outcome attestation where possible
- mint audit logging
- separation of duties for high-impact issuance
- short proof validity windows
- integration with enterprise identity and approval systems

This pass does not implement production KMS/HSM custody. Do not describe local proof signing or pilot-local keys as production custody.

## Identity Deployment

Actenon is not an identity provider.

Recommended deployments should integrate with existing identity infrastructure:

- SPIFFE for workload identity where available
- OAuth/OIDC for user or service identity
- DPoP or equivalent proof-of-possession where useful
- IAM, SSO, or provider-native authorization for downstream authority

Actenon then binds tenant, subject, requester, audience, target, action, and scope into proof. It enforces consistency at the execution edge.

## Policy Deployment

Policy should be consequence-classified and deny by default.

Recommended flow:

1. classify action consequence
2. gather evidence
3. require approval where configured
4. mint proof only when allowed
5. bind approval/evidence references or digests into proof and outcome records where used
6. re-check local policy at the Protected Endpoint where practical
7. refuse if required policy, evidence, or approval is missing

Preflight alone is not enforcement. It must connect to proof-bound protected execution.

## Future Layers

The following are future or deeper layers unless a deployment explicitly implements and documents them:

- hosted transparency log
- Actenon Network
- Agent Trust Score
- network-scale reputation
- insurer or regulator recognition
- production KMS/HSM custody in the OSS kernel
- provider-authenticated reconciliation or settlement finality

These may be important enterprise capabilities, but they are not current OSS kernel guarantees.

Future hosted network or transparency layers must not be described as the execution boundary. They can add durability, discovery, or ecosystem coordination only if implemented. Consequential actions still need local proof verification, replay/escrow handling where required, credential brokering, and Receipt/Refusal emission at the Protected Endpoint or equivalent boundary.

Do not present a future network, hosted transparency service, Agent Trust Score, or commercial control plane as active OSS kernel enforcement. Those layers can complement the boundary only after they exist and are explicitly documented.

## Deployment Checklist

- Agent has no standing production credential.
- Protected Endpoint verifies proof before side effects.
- Preflight result is bound into signed proof where relied on.
- Tenant, subject/requester, audience, action, target, scope, expiry, and nonce are verified.
- Replay or escrow state is consumed atomically where required, using storage shared by every worker that can execute the same protected route.
- Credential Broker releases scoped authority inside the boundary.
- Receipt/Refusal is emitted for allowed or blocked execution.
- Local/offline verification fails closed when keys or proof cannot be verified.
- Issuer/control-plane signing keys use production-grade custody in production.
- Future layers are not described as active unless actually deployed.

## Related Documents

- [TECHNICAL_ARCHITECTURE.md](TECHNICAL_ARCHITECTURE.md)
- [TRUST_BOUNDARIES.md](TRUST_BOUNDARIES.md)
- [BYPASS_RESISTANCE.md](BYPASS_RESISTANCE.md)
- [REPLAY_ESCROW_CONCURRENCY.md](REPLAY_ESCROW_CONCURRENCY.md)
- [PRODUCTION_SIGNING_CUSTODY.md](PRODUCTION_SIGNING_CUSTODY.md)
- [ISSUER_SECURITY_MODEL.md](ISSUER_SECURITY_MODEL.md)
- [../operations/KEY_LIFECYCLE_RUNBOOK.md](../operations/KEY_LIFECYCLE_RUNBOOK.md)
