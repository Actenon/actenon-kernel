# Multi-Agent Execution Model

## Purpose

This document explains how the existing Actenon kernel model applies in multi-agent systems.

It does not define a new protocol or activate a new public surface. Active v1 still centers on:

- Action Intent
- PCCB
- Protected Endpoint
- Replay
- Receipt
- Refusal

The rule stays the same:

- each protected execution edge verifies its own proof before side effects

For the normative execution-edge behavior, see [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md). For the neutral tool pattern, see [MCP_HERO_PATH.md](MCP_HERO_PATH.md). For the current framework and platform example order, see [INTEGRATIONS.md](INTEGRATIONS.md).

## Why Multi-Agent Systems Increase Risk

Multi-agent systems add more hops between decision and execution:

- one agent plans
- another agent delegates
- a third agent calls a tool
- a tool or route finally causes the side effect

Every additional hop creates more room for proof laundering and delegation mistakes.

In this context, proof laundering means a system treats proof, approval state, or "allowed" context gathered upstream as if that were sufficient authorization for a different downstream execution edge.

Typical failure modes include:

- an orchestrator agent receives proof for one tool and forwards it to another tool
- a coordinating agent accumulates permissions from several steps and passes them to sub-agents as if they were a general execution grant
- a sub-agent executes with parameters, tenant, subject, or audience that differ from what the proof actually bound
- the same proof is replayed across multiple tool boundaries because no single execution edge is taking full local responsibility for verification

These are not new category problems. They are the execution gap expressed through multi-agent delegation.

## Core Rule

Each protected tool or endpoint verifies its own proof.

That rule does not weaken because:

- an upstream agent is trusted
- an orchestrator already checked approval
- another tool already verified something similar
- a framework makes the call chain look like one workflow

If a component can cause a consequential side effect, that component is the protected endpoint for that action and must verify the proof locally before acting.

In practice, that means:

1. the tool, route, or action handler that can actually perform the side effect receives the Action Intent and PCCB
2. that same execution boundary builds its local verification context
3. that same execution boundary verifies proof, audience, expiry, and replay requirements
4. only then does it execute

If proof verification happens elsewhere but the execution edge can still act without re-checking it, the system has reintroduced the execution gap.

## Proof Must Not Be Casually Shared Across Agent Boundaries

Proof is not a general-purpose capability token for arbitrary downstream agents.

A PCCB is bound to a specific execution context, including:

- audience
- subject
- tenant
- action
- target
- scope
- expiry

That means forwarding proof across agent boundaries is not, by itself, a safe delegation mechanism.

Safe guidance:

- agents may pass proof artifacts as data when the downstream protected tool is the intended audience and will verify them for itself
- agents must not treat upstream proof possession as blanket authority for unrelated tools, endpoints, or sub-agents
- operators should assume that any proof copied across boundaries without a fresh local verification step is a proof-laundering risk

This is especially important in systems where one agent can inspect, summarize, or relay another agent's tool payloads. Observing proof is not the same as being authorized to execute with it.

## Chained Consequential Actions Need Separate Proof

Separate execution edges require separate proof.

If a workflow includes multiple consequential actions, each action boundary needs its own proof for its own audience and execution context.

Examples:

- "read customer balance" and "issue refund" are separate execution edges
- "generate export" and "send export to vendor" are separate execution edges
- "draft change" and "apply change to provider" are separate execution edges

One proof should not be stretched across the whole chain unless the chain is, in fact, one protected execution edge with one bound action. In most real multi-agent systems, that is not true.

The safe default is simple:

- one consequential edge, one proof

If an orchestrator wants Tool A and Tool B to perform different consequential steps, it should obtain proof for Tool A and separate proof for Tool B. Relaying the PCCB for one edge into another edge is exactly the failure this model is designed to stop.

In practical modeling terms:

- each consequential step should have its own Action Intent
- each consequential step should have its own PCCB bound to the audience for that exact Protected Endpoint
- each Protected Endpoint should emit its own Receipt or Refusal for the step it actually executed or blocked

That keeps the chain inspectable without pretending that one upstream authorization decision safely covers every downstream side effect.

## Orchestrator Permission Accumulation Is A Real Failure Mode

A common design mistake is to let an orchestrator agent accumulate permissions or approvals from several steps and then forward them to sub-agents as if they authorize any later execution.

That weakens the model in several ways:

- the orchestrator becomes an informal super-audience
- downstream tools stop verifying their own local audience
- tenant and subject boundaries become easier to blur during delegation
- replay enforcement becomes ambiguous because no single execution edge owns it cleanly
- failures become harder to reason about because "allowed somewhere upstream" replaces explicit execution-edge verification

In other words, the orchestrator starts behaving like a permission warehouse instead of a planner.

That is not what the kernel standardizes.

An orchestrator may coordinate work, but it should not replace protected-endpoint verification at each consequential edge.

## What Orchestrator Agents Must Not Implicitly Inherit Or Forward

An orchestrator agent must not treat any of the following as a general downstream execution grant:

- an upstream Action Intent for a different consequential step
- a PCCB whose audience is another tool, route, or managed runtime surface
- a prior "allowed" or "approved" state that was not re-bound to the current execution edge
- a Receipt from one step as if it authorizes a different step
- subject, tenant, or capability context copied from one agent boundary into another without fresh local verification

Safe orchestrator behavior is narrower:

- gather context
- request the next Action Intent
- obtain proof for the next exact edge
- let that exact edge verify locally
- handle the resulting Receipt or Refusal as an outcome artifact, not as a reusable cross-edge permit

## How Existing Kernel Concepts Already Mitigate This

Multi-agent guidance does not require new active surfaces because the current kernel vocabulary already provides the right defenses when used correctly.

### Audience Binding

Audience binding prevents proof minted for one execution edge from being valid at a different edge.

This is the first defense against delegated proof laundering:

- a proof for Tool A should not verify at Tool B
- a proof for one managed tool surface should not verify at another unrelated tool surface

Relevant specs and examples:

- [spec/pccb/SPEC.md](spec/pccb/SPEC.md)
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [spec/refusal/examples/audience-mismatch.json](spec/refusal/examples/audience-mismatch.json)

### Subject And Tenant Binding

Subject and tenant binding reduce the chance that a coordinating agent can reuse proof across users, services, or tenants during delegation.

They do not stop a compromised issuer from minting bad proof, but they do give the protected endpoint concrete fields to verify before execution.

Relevant examples:

- [spec/pccb/examples/wrong-subject.json](spec/pccb/examples/wrong-subject.json)
- [spec/pccb/examples/wrong-tenant.json](spec/pccb/examples/wrong-tenant.json)

### Protected Endpoint Verification

Protected endpoint verification is the central behavioral rule.

The tool or endpoint that can cause the side effect verifies proof for itself. That is the control that stops a multi-agent system from treating upstream orchestration state as sufficient execution authority.

Relevant docs:

- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)

### Replay Behavior

Replay behavior matters even more in delegated systems because the same proof can be forwarded or retried across multiple boundaries.

Replay protection only helps where the replay path is actually enforced. If a multi-agent host bypasses replay enforcement at the protected edge, the kernel cannot prevent duplicate execution for that edge.

Relevant docs and examples:

- [spec/replay/SPEC.md](spec/replay/SPEC.md)
- [spec/refusal/examples/replay-refused.json](spec/refusal/examples/replay-refused.json)
- [THREAT_MODEL.md](THREAT_MODEL.md)

## Framework Guidance

The same rule maps cleanly into the current public examples.

### MCP

MCP is the neutral hero path because the tool boundary is explicit and ecosystem-wide.

The important property is not "MCP" by itself. It is that the MCP tool implementation is the protected execution edge.

Start here:

- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [examples/mcp_server_protected_tool/README.md](examples/mcp_server_protected_tool/README.md)

### CrewAI

CrewAI matters because it makes multi-agent delegation visible.

The lesson is not that CrewAI needs a special Actenon protocol. The lesson is that delegation does not remove the need for each protected tool to verify proof locally.

See:

- [examples/crewai_protected_tool/README.md](examples/crewai_protected_tool/README.md)

### Claude Managed Agents

Claude Managed Agents matters because it is a managed agent surface where orchestration and execution can look deceptively unified.

The same rule still applies: the custom tool implementation is the protected execution edge, and verification belongs there rather than in upstream planning or orchestration.

See:

- [examples/claude_managed_agents_protected_tool/README.md](examples/claude_managed_agents_protected_tool/README.md)

## What This Does Not Add

This document does not add:

- a new delegation protocol
- a new active proof type
- a general-purpose agent-to-agent grant surface
- orchestration semantics as part of active v1
- hosted control-plane behavior

Reserved surfaces remain reserved. This document is deployment guidance for using the existing kernel model correctly in multi-agent systems.

## Practical Review Questions

When reviewing a multi-agent integration, ask:

1. Which component can actually cause the side effect?
2. Does that exact component verify the Action Intent and PCCB locally?
3. Is the local audience identity specific to that execution edge?
4. Could an orchestrator or sub-agent forward proof to a different tool and still get execution?
5. Is replay enforcement actually active at the edge that executes?
6. If the workflow chains multiple consequential actions, does each edge require its own proof?

If the answer to those questions is unclear, the system probably still has an execution gap.
