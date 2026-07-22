# Issuance And Approval

## Where Proof Comes From

An agent should not mint its own production authorization proof.

In production, a trusted issuer creates a PCCB only after the intended action
has passed the organization's authorization process. The issuer may be an
approval service, policy decision point, workflow engine, or tightly controlled
service using asymmetric KMS/HSM-backed signing custody.

The protected endpoint is a separate trust boundary. It does not trust the
agent's statement that approval happened. It verifies the issued proof against
the exact Action Intent, audience, tenant, subject, target, parameters, expiry,
and replay state before executing.

```text
agent proposes exact Action Intent
              |
              v
approval / policy / evidence evaluation
              |
        allow | refuse
              v
trusted issuer signs proof for that exact intent
              |
              v
agent or runtime carries intent + proof to protected endpoint
              |
              v
endpoint verifies, executes once, or emits a Refusal
```

## Approval Comes Before Issuance

The issuer should run Preflight or an equivalent authorization workflow before
minting. A high-risk action must not receive proof merely because an agent
requested one.

For the packaged policy path:

1. Build the exact `ActionIntent`, including final parameters and target.
2. Evaluate the configured `PreflightEngine` with the required evidence.
3. If the decision has unmet requirements, collect the documented approvals or
   evidence and evaluate again.
4. Mint only after the decision allows the exact action.
5. Send the unchanged intent and proof to the intended protected endpoint.

The exact evidence keys, types, and examples are documented in
[PREFLIGHT_EVIDENCE.md](PREFLIGHT_EVIDENCE.md).

## Using `ActenonGate.mint_proof`

`ActenonGate.mint_proof(action)` is the high-level wrapper around `PCCBMinter`.
It is appropriate inside an authorized issuer process and in local
development. It does not turn the calling agent into an approver and does not
replace the policy or human-approval step.

```python
from actenon import ActenonGate

issuer_gate = ActenonGate(
    signer=kms_or_hsm_signer,
    verifier=trusted_public_key_verifier,
    audience="service:payments",
    issuer="service:authorization-issuer",
)

# Call only after policy and approval allow this exact Action Intent.
proof = issuer_gate.mint_proof(action)
```

A protected endpoint that should never issue proof can construct
`ActenonGate` without a signer. It can verify and protect actions, but
`mint_proof()` fails because the process is verifier-only.

The `ActenonGate.local_dev(...)` helper uses a documented local HMAC signer. It
exists for examples and tests, not as a production trust root.

## Autonomous-Agent Patterns

### Per-Intended-Action Issuance

The strongest general pattern is one issuance decision per consequential
action:

- the agent proposes the final intended action
- policy and approval evaluate that exact intent
- the issuer signs proof for that exact intent and audience
- the protected endpoint independently verifies it
- replay protection permits execution once

Changing the destination, amount, target, tenant, or other bound field requires
a new authorization decision and a new proof.

### Risk-Tiered Automatic Issuance

Organizations may automatically issue proofs for narrowly scoped, low-risk
actions when explicit policy allows them. This is standing policy, not standing
proof: each action still receives a short-lived proof bound to its exact
parameters and endpoint.

Higher-risk actions should require stronger evidence, separation of duties, or
human approval before issuance. Examples include production deletion, money
movement, privilege escalation, sensitive export, and external bulk send.

Do not give an agent an unrestricted signing key or a reusable proof. That
collapses the separation between requesting an action and authorizing it.

## Multi-Agent Systems

An orchestrator may request issuance for downstream work, but each
consequential execution edge needs proof for its own exact action and audience.
A proof for one tool is not a general delegation token for another tool.

See [MULTI_AGENT_EXECUTION_MODEL.md](../../MULTI_AGENT_EXECUTION_MODEL.md) for
audience binding, proof-laundering risks, and shared replay-store guidance.

## What This Does Not Claim

This guide does not prescribe one approval vendor or workflow. Actenon does not
decide who your organization trusts to approve an action, and the open-source
kernel does not claim production KMS/HSM custody.

Actenon provides the exact-action proof format and protected execution
behavior. Operators remain responsible for issuer custody, policy design,
approval identity, evidence integrity, protected routing, and durable shared
replay state.
