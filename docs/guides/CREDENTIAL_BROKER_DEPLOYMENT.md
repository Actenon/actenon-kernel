# Credential Broker Deployment

## Purpose

Actenon works best when the protected endpoint is the execution boundary for a
consequential action, not a voluntary wrapper that an agent can bypass.

The deployment rule is simple:

```text
no standing agent credential for consequential production systems
```

The agent should request an action. The protected endpoint verifies proof and
policy, consumes a single-use capability, uses or brokers the privileged
credential, executes or refuses, and emits a Receipt or Refusal.

## The Bypass Risk

Standing production credentials are the side door.

If an agent can call a production provider directly with a raw credential,
Actenon cannot stop that direct path. It can still verify and record actions
that pass through the protected endpoint, but it cannot control actions that
never reach the boundary.

Without Actenon:

```text
agent -> standing credential -> production system
```

Weak Actenon deployment:

```text
agent -> protected endpoint -> production system
agent -> standing credential -> production system  [bypass remains]
```

Strong Actenon deployment:

```text
agent -> ActionIntent/PCCB -> Protected Endpoint -> Credential Broker -> target system
no standing agent credential for consequential systems
```

## How Protected Endpoints Close The Side Door

A protected endpoint should sit between the agent and the system that can create
the side effect.

The endpoint is responsible for:

- receiving the Action Intent and PCCB
- verifying exact action, audience, tenant, subject, target, scope, expiry, and signature
- enforcing replay protection when duplicate execution is a risk
- consuming an escrowed or single-use capability when configured
- using or brokering the privileged credential only after verification succeeds
- refusing without calling the broker on proof failure, policy refusal, replay failure, or escrow failure
- emitting a Receipt or Refusal

The agent receives no standing production credential. The agent can request a
consequential action, but the endpoint remains the execution authority.

## Broker Requirements

A credential broker used for consequential systems must:

- issue short-lived scoped credentials
- keep raw secret material out of Receipt and Refusal artifacts
- ensure credential references do not leak sensitive vault/provider details
- run only after proof verification succeeds
- run only after replay/escrow consumption where those controls are configured
- avoid running on refusal paths
- release or revoke brokered authority after execution
- release or revoke brokered authority after protected handler exceptions
- fail closed when acquisition or release cannot be completed safely
- sanitize provider SDK errors and response bodies before anything reaches public artifacts

The brokered value visible to the handler should be a scoped execution reference,
not reusable provider authority for the agent. `secret_reference` should be safe
for receipts and refusals: use an opaque broker grant id or public-safe
credential reference, not a raw vault path, provider token id, account secret,
database URL, cookie value, or private-key reference.

## PCCB, Escrow, And Capability Brokering

The PCCB binds proof to the exact action attempt. Escrow and capability
primitives let a deployment map that proof to a narrow, single-use execution
authority.

A typical brokered path is:

1. The agent submits an Action Intent.
2. An issuer evaluates policy and mints a PCCB only when the action is eligible.
3. The protected endpoint verifies the Action Intent and PCCB.
4. The endpoint claims replay/capability state.
5. The endpoint consumes escrow/capability state where configured.
6. The endpoint obtains or uses the privileged credential.
7. The endpoint executes or refuses.
8. The endpoint releases brokered authority.
9. The endpoint emits a Receipt or Refusal.

The credential is not handed to the agent. It is held by the protected executor
or brokered just-in-time under the endpoint's control.

## Escrow Setup Contract

An escrow-enabled execution edge requires two linked records:

- a PCCB containing `escrow_reference.escrow_id`
- an escrow record issued for that PCCB ID and exact capability

The high-level `ActenonGate` creates both when `mint_proof()` is called on a
gate configured with escrow. This is the recommended setup because proof
minting and escrow issuance cannot drift apart:

```python
from actenon-kernel import ActenonGate
from actenon.escrow import InMemoryCapabilityEscrow

gate = ActenonGate.local_dev(
    audience="service:protected-endpoint",
    escrow=InMemoryCapabilityEscrow(),
)
proof = gate.mint_proof(action_intent)
outcome = gate.protect(action_intent, proof, side_effect)
```

Supplying a legacy PCCB without `pccb.escrow_reference.escrow_id` to this gate
raises `EscrowConfigurationError` before protected execution begins. The error
points to `ActenonGate.mint_proof(...)`; it is intentionally distinguishable
from policy, binding, and replay refusals.

Low-level `PCCBMinter` users must pass an `escrow_id` while minting and issue
the matching escrow record themselves. See
[High-Level Gate API](HIGH_LEVEL_GATE_API.md#escrow-setup-contract) for the
correct-on-enable path.

## Local Kernel Code Path

The OSS kernel exposes a local `ProtectedExecutor` helper for this pattern:

```python
from datetime import timedelta

from actenon.credentials import InMemoryCredentialBroker
from actenon.execution import ProtectedExecutor
from actenon.proof import PCCBVerifier, build_local_proof_signer
from actenon.receipts import InMemoryOutcomeWriter

signer = build_local_proof_signer()
executor = ProtectedExecutor(
    proof_verifier=PCCBVerifier(signer),
    credential_broker=InMemoryCredentialBroker(ttl=timedelta(seconds=60)),
    outcome_writer=InMemoryOutcomeWriter(),
)


def delete_volume(request, brokered_credential):
    # The handler receives a brokered credential reference after verification.
    # The agent never receives the raw provider credential.
    return {
        "external_reference": f"delete:{request.intent.target.resource_id}",
        "credential_reference": brokered_credential.secret_reference,
    }


result = executor.execute(
    protected_execution_request,
    delete_volume,
    policy_decision=endpoint_policy_decision,
)
```

The flow is:

```text
agent -> ActionIntent/PCCB -> protected endpoint -> brokered credential -> side effect
```

For a runnable example, see
`examples/credential_broker_infra_delete/`.

## Kernel Guarantees And Broker Implementer Duties

The kernel's reference broker never places raw secrets in Receipt or Refusal
artifacts. `BrokeredCredential` carries a `secret_reference`, not raw secret
material, and the protected executor redacts generic handler exception text
before writing public artifacts. On unexpected handler failure, the artifact may
include safe structured diagnostics such as `exception_type`, `phase`,
`request_id`, and `safe_error_code`; it must not include the raw exception
message, traceback, provider response body, token, credential value, private
key, or raw secret.

Third-party `CredentialBroker` implementations must preserve the same boundary.
They are responsible for ensuring raw secrets are not logged, serialized,
returned to agents, raised in exception messages, or written to Receipt or
Refusal artifacts. Actenon cannot cryptographically guarantee arbitrary
third-party broker hygiene unless the broker implementation follows the
contract and is audited.

Implementation guidance:

- use vault or KMS references instead of embedding provider credentials
- issue short-lived, scoped credentials only after proof verification
- consume replay/escrow state before broker acquisition where single-use execution is required
- use atomic replay/escrow stores shared by every worker that can execute the protected route
- avoid embedding credential values or provider response bodies in exception messages
- sanitize provider SDK errors before returning, raising, logging, or persisting them
- never expose raw credential material to agents
- never store raw credentials in receipts or refusals

If broker acquisition fails after replay or escrow has been consumed, the
protected executor emits a safe refusal and leaves the single-use state
consumed. Treat this as an ambiguity boundary and reconcile from artifacts and
deployment logs instead of retrying the same proof.

## Scanner Signals For Bypass Review

`actenon-kernel scan repo` and `actenon-kernel scan mcp` report candidate standing-authority
signals when agent/tool paths appear to load or construct direct credentials.
Review findings for:

- environment secrets loaded in agent or tool modules
- API client construction inside an agent executor
- browser session/cookies loaded directly by the agent
- cloud credentials in agent paths
- database URLs or connection strings in agent tool paths
- MCP tools with direct credentials and no visible proof gate
- consequential action paths where "credential broker not visible" is reported

Scanner output is static advisory analysis. It does not prove runtime
reachability or exploitability, and it does not prove a project is unsafe. It
marks places where maintainers should confirm that the protected endpoint is
the only route to consequential authority.

## OSS-Only Deployment

OSS-only users can run this pattern locally or inside their own infrastructure:

- use the kernel's public contracts and verifier
- protect the endpoint that performs the side effect
- configure replay protection for duplicate-sensitive actions
- use local escrow or single-use capability state where useful
- keep raw provider credentials out of agent runtime environments
- emit local Receipt and Refusal artifacts

Trust grade:

- OSS local Receipt: local/self-audit evidence unless asymmetric signing and
  published verification material are configured.
- OSS asymmetric attestation: stronger copied-artifact origin and integrity when
  the verifier can resolve the issuer key.
- Cloud-issued attested Receipt: externally verifiable origin and integrity for
  copied Cloud artifacts.

## What The Paid Layer Adds

The managed Cloud/control-plane layer can add operational capabilities around
the same boundary:

- managed approvals and evidence workflows
- managed signing and key lifecycle
- tenant operations and access controls
- reporting and audit/archive workflows
- operated credential-broker rollout support
- hosted transparency, trust-network inclusion, or long-term anchoring when
  those paid services exist

The paid layer should not replace the kernel's verifier boundary. Cloud issues;
the Kernel verifies.

## What Actenon Still Does Not Prove

Actenon does not prove:

- that the business decision was inherently correct
- that a downstream provider reached finality
- that an adapter or provider behaved honestly after handoff
- that replay protection is active unless it is deployed at the protected endpoint
- that side-door execution is blocked if agents still hold standing credentials
- that hosted trust-network anchoring exists in OSS

The deployment protects the path it controls. The strongest deployment removes
the uncontrolled path.

## Related Architecture

- [../architecture/BYPASS_RESISTANCE.md](../architecture/BYPASS_RESISTANCE.md)
- [../architecture/REPLAY_ESCROW_CONCURRENCY.md](../architecture/REPLAY_ESCROW_CONCURRENCY.md)
- [../architecture/TRUST_BOUNDARIES.md](../architecture/TRUST_BOUNDARIES.md)
- [../architecture/DEPLOYMENT_ARCHITECTURES.md](../architecture/DEPLOYMENT_ARCHITECTURES.md)
