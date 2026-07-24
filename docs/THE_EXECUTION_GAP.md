# The Execution Gap

Canonical public problem statement for proof-bound consequential execution.

This document is written to stand on its own at a public URL, not only inside this repository.

It names the category and the mechanism:

- the category is the execution gap
- the mechanism is proof-bound execution

## Canonical Definition

The execution gap is the gap between upstream authorization and the execution edge that actually performs a consequential side effect.

The gap remains open unless the execution edge independently verifies proof bound to the exact action it is about to perform.

Consequential actions include actions that move money, change permissions, export sensitive data, call provider APIs, or trigger other irreversible external effects.

Here, "export sensitive data" means an explicit export or transmit action at an
execution edge. Proof-bound execution does not inspect prompts, model output,
or data returned in-band by an unprotected tool. See
[Scope And Guarantees](docs/SCOPE_AND_GUARANTEES.md).

Short citation form:

> The execution gap is the gap between upstream authorization and the execution edge that actually performs a consequential side effect.

Proof-bound execution is the requirement that the execution edge independently verifies proof bound to the exact action it is about to perform before side effects.

## The Question Most Systems Still Leave Open

Many systems answer this question upstream:

`Should this requester be allowed to do this kind of thing?`

What many systems still do not answer at the execution edge is:

`Is the exact action about to execute still the exact action that was authorized for this endpoint, this tenant, this subject, this target, and this time window?`

That unanswered question is the execution gap.

## Why Upstream Authorization Is Not Enough

Upstream controls matter. They are just not the missing boundary.

**Authentication** proves caller identity. It does not prove that the exact action about to execute still matches the action that was authorized.

**Policy** decides whether a principal may perform an action class. It does not bind one execution attempt to exact parameters, exact target, exact audience, expiry, and replay state at the moment of side effect.

**Approval** records that a human or process said yes to an action description. It does not stop a different action from arriving at the execution edge later, and it does not prevent the same approval material from being presented twice.

**Audit logs** explain what happened after the fact. They do not stop it.

**Idempotency keys** help with accidental duplicate retries. They are not proof-bound replay protection against deliberate or structural re-presentation of valid-looking authorization material.

The missing question is always the same:

did the execution edge independently verify the exact action it is about to perform?

## Why The Execution Edge Is The Missing Trust Boundary

Modern agent and service stacks separate decision-making from execution.

- a planner or agent proposes an action
- an orchestrator approves or routes it
- a framework serializes it into a tool or request
- a provider adapter, tool implementation, or protected endpoint finally performs the side effect

Those are different components. They are often in different processes, sometimes in different services, and sometimes in different trust domains.

That separation creates room for:

- parameter mutation between approval and execution
- replay of valid-looking proof or approval material
- presentation to the wrong endpoint
- tenant or subject rebinding mistakes
- execution after the intended validity window has closed

The execution edge is the only component that can see the final action immediately before side effects. That makes it the only trustworthy place to enforce exact proof binding.

## Failure Classes When The Gap Is Open

### 1. Parameter substitution

The request that reaches execution no longer exactly matches the action that was approved.

Examples:

- a payment amount changes
- a payee or destination account changes
- a refund target changes
- a permission scope expands

If the execution edge only trusts upstream approval, it cannot detect the substitution before side effects.

### 2. Replay

The same valid-looking approval or proof is presented more than once, and the action fires more than once.

Examples:

- the same refund executes twice
- the same transfer is retried after the first attempt crossed an ambiguity boundary
- the same tool call is replayed into a second external side effect

Without execution-edge replay enforcement, the system is depending on timing, luck, or downstream provider behavior.

### 3. Audience misdirection

Authorization material intended for one execution edge is presented to another.

Examples:

- proof minted for one tool is sent to a different tool
- proof intended for one payment route is presented to another route
- one service accepts proof that was approved for a different protected endpoint

Without audience binding, an endpoint cannot distinguish "approved somewhere" from "approved for me."

### 4. Wrong tenant or wrong subject

The action remains plausible, but it is no longer bound to the right tenant or requester identity at execution time.

Examples:

- a request authorized for one tenant executes under another
- a delegated workflow reuses proof minted for a different requester
- a multi-agent or multi-service handoff loses subject fidelity

Without execution-edge tenant and subject checks, the system can enforce the wrong business boundary perfectly consistently.

### 5. Stale proof reuse

An action that was valid within one time window is presented later, after context has changed.

Examples:

- old approval material is replayed after account state changed
- proof is presented after a freeze, maintenance window, or policy change
- a time-bounded authorization is executed after its safe window

Without expiry enforcement at the execution edge, old proof remains dangerous.

## What Closes The Gap

Closing the execution gap requires execution-edge properties, not stronger prose around upstream controls.

Before any consequential side effect, the execution edge must be able to:

- verify exact action binding
- verify exact target binding
- verify exact audience binding
- verify exact tenant and subject binding
- enforce validity windows such as `not_before` and `expires_at`
- enforce replay or single-use protections where the path claims them
- emit structured success or failure artifacts when execution proceeds or is blocked

If any of those checks fail, execution must be refused before side effects.

## The Mechanism: Proof-Bound Execution

Proof-bound execution is the narrow mechanism that closes the execution gap.

It means:

- the action is represented in a portable artifact
- proof is minted for that exact action
- the execution edge independently verifies that proof for itself
- the execution edge refuses before side effects if the action, audience, tenant, subject, target, expiry window, or replay identity no longer match

That is different from:

- upstream auth without execution-edge verification
- workflow approval without execution-edge verification
- framework routing without execution-edge verification
- audit logging after the side effect already happened

The core idea is simple:

upstream systems may decide, but the execution edge must still verify.

## Why Actenon Exists

Actenon exists to make that boundary explicit, portable, and inspectable.

The kernel publishes a public surface for proof-bound consequential execution:

- `Action Intent`: the exact requested action in portable form
- `PCCB`: the proof artifact bound to that exact action
- `Protected Endpoint`: the execution-edge behavior that verifies proof before side effects
- `Replay`: the duplicate-execution defense surface
- `Receipt` and `Refusal`: the canonical structured outcome artifacts

Actenon is not a replacement for authentication, policy, or approvals.

It exists so the execution edge independently verifies what it is about to do instead of trusting that upstream systems already got everything right.

## Why This Matters For Tool And Agent Frameworks

Tool frameworks make the execution gap easier to see, not less important.

In many modern stacks, the real execution edge is the tool implementation itself:

- the planner decides
- the framework routes
- the tool performs the side effect

If the tool does not verify bound proof inside its own execution path, then auth, policy, and approval remain upstream hints. The side effect still depends on trust in the route between decision and execution.

That is why protected tools, protected endpoints, and verifier-first integrations matter. The pattern is the same whether the execution edge is an HTTP route, an MCP tool, or a framework-specific function boundary.

## What This Concept Does And Does Not Claim

The claim is narrow and strong:

if the execution edge enforces proof binding, audience, tenant, subject, expiry, and replay rules before side effects, then the action that fires must match the action that was bound for that edge, or execution is refused before side effects.

This concept does not claim:

- that prompts, model output, or in-band response content are inspected or filtered
- that data disclosed through ordinary output is stopped unless the disclosure is modeled and routed as a protected action
- that the upstream issuer or signer made the correct business decision
- that replay protection exists where the execution edge does not actually enforce it
- that a malicious or buggy adapter cannot lie after control passes to it
- that copied v1 `Receipt` or `Refusal` artifacts are portable cryptographic attestations of origin
- that provider-backed reconciliation or settlement finality is part of active v1
- that reserved surfaces such as Reconciliation or Policy Bundle are active v1 standards

## Open Reference Implementation

For readers who want to inspect the open reference implementation after understanding the concept:

```bash
make install
actenon-kernel up
actenon-kernel doctor
actenon-kernel simulate --incident replit
python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime
```

Then:

- open `http://127.0.0.1:8421` when the local trace viewer is available
- inspect `artifacts/local_runtime/simulations/replit/`
- inspect `artifacts/local_runtime/artifacts/`

That flow makes the model visible through artifacts rather than slogans:

- `Action Intent`
- `Intent Record`
- `PCCB`
- `Receipt`
- `Refusal`
- replay state
- protected-endpoint state

Further reading:

- [QUICKSTART.md](QUICKSTART.md)
- [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [EXECUTION_GAP_SCANNER.md](EXECUTION_GAP_SCANNER.md)
