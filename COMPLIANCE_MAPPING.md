# Compliance Mapping

## Purpose

This document maps the Actenon Kernel to common security and governance frameworks that enterprise teams already use when reviewing AI and agent systems.

It is not a certification statement, a legal opinion, or a claim of complete framework coverage.

It is a scoped technical mapping for one part of the problem:

- consequential execution at the protected endpoint

It is intentionally limited to the kernel's execution-edge control surface rather than organizational governance, provider operations, or the paid control plane.

Use it with:

- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [CONFORMANCE.md](CONFORMANCE.md)

## How To Read This Mapping

The kernel helps most where a framework asks:

- whether execution is bound to an explicit request contract
- whether a consequential tool or endpoint verifies authorization material locally before side effects
- whether replay, audience, tenant, subject, and expiry are enforced at the execution edge
- whether blocked execution and successful execution produce structured artifacts that reviewers can inspect

The kernel helps much less where a framework asks about:

- enterprise governance programs
- human approvals
- model training governance
- privacy programs
- provider oversight
- legal compliance workflows
- complete audit operations

This is therefore a partial mapping to selected framework categories, not a full control framework.

## What The Kernel Supports

The kernel materially supports:

- exact proof binding at the protected endpoint
- refusal of mutated, expired, mis-addressed, wrong-tenant, wrong-subject, or replayed execution attempts before side effects when the relevant checks are actually enforced
- explicit public contracts for Action Intent, PCCB, Receipt, Refusal, Protected Endpoint, and Replay
- structured execution artifacts that are stable, machine-readable, and correlation-friendly
- local evidence-query support for asking whether a proof and outcome chain exists for a specific execution anchor
- optional execution-anchor publication as an additive transparency surface when a deployment wants public or semi-public digest-based anchoring
- a public conformance target for active v1 compatibility

## What The Kernel Does Not Support

The kernel does not by itself provide:

- certification against any framework
- complete coverage of OWASP or NIST guidance
- model governance, model evaluation, or training-data governance
- hosted approval workflows, evidence review, or compliance operations
- provider-authenticated reconciliation or settlement finality
- portable cryptographic attestation of origin for copied Receipt or Refusal artifacts in v1
- protection against a compromised issuer, signer, or external control plane that can mint bad proof
- protection against a malicious adapter that lies after control passes to it
- continuous monitoring, SIEM integration, or enterprise evidence-retention workflows

## OWASP Top 10 For LLM Applications Mapping

This section maps the kernel to the most relevant entries in the OWASP Top 10 for LLM Applications.

It is not a full crosswalk.

| OWASP category | Where the kernel helps | What it does not claim |
| --- | --- | --- |
| `LLM01 Prompt Injection` | The kernel can reduce the chance that a prompt-manipulated planner or tool call causes an unauthorized side effect by requiring proof verification at the protected endpoint before execution. | It does not prevent prompt injection into the model, planner, or orchestrator itself. |
| `LLM05 Improper Output Handling` | The kernel helps when improper handling would otherwise let model output directly trigger a consequential action. The protected endpoint verifies Action Intent, PCCB, audience, tenant, subject, expiry, and replay context before side effects. | It does not sanitize arbitrary model output or validate every non-consequential downstream use of model text. |
| `LLM06 Excessive Agency` | The kernel narrows execution authority by binding proof to an exact action, target, audience, tenant, subject, scope, and time window. This is directly relevant when agent or tool autonomy would otherwise be broader than intended. | It does not design the agent's autonomy model or choose appropriate human approval policy. |
| `LLM09 Misinformation` | The kernel can limit misinformation from turning into a consequential side effect by refusing unbound or mismatched execution attempts at the endpoint. | It does not make model content true, accurate, or safe to rely on outside protected execution. |
| `LLM10 Unbounded Consumption` | Replay enforcement and refusal behavior can help block repeated consequential execution attempts at the protected edge. | It is not a general resource-abuse, quota, or cost-governance system. |

## OWASP Top 10 For Agentic Applications Mapping

This section maps the kernel to the most relevant entries in the OWASP Top 10 for Agentic Applications.

Again, this is a partial mapping, not a full crosswalk.

| OWASP category | Where the kernel helps | What it does not claim |
| --- | --- | --- |
| `ASI01 Agent Goal Hijack` | The kernel can reduce downstream damage when a hijacked orchestrator or planner attempts to cause side effects without valid proof for the exact execution edge. | It does not prevent the agent's goals, planning, or reasoning from being hijacked upstream. |
| `ASI02 Tool Misuse and Exploitation` | This is one of the kernel's strongest fits. The protected tool or endpoint verifies proof locally before acting, rather than trusting orchestration state. | It does not secure every framework runtime or tool implementation detail outside the protected execution path. |
| `ASI03 Identity and Privilege Abuse` | Audience, tenant, and subject binding help prevent proof minted for one principal, tenant, or endpoint from being reused elsewhere. | It does not repair upstream identity compromise or privilege assignment mistakes before proof issuance. |
| `ASI07 Insecure Inter-Agent Communication` | The kernel helps by making proof forwarding insufficient on its own. Each protected edge verifies its own proof, which reduces proof laundering across agent boundaries. See [MULTI_AGENT_EXECUTION_MODEL.md](MULTI_AGENT_EXECUTION_MODEL.md). | It does not define a complete secure inter-agent protocol or communication framework. |
| `ASI08 Cascading Failures` | Refusal behavior, replay checks, and structured outcome artifacts can help prevent or contain duplicate or mismatched consequential execution at a local edge. | It is not a full resilience, rollback, or distributed recovery system for agent swarms. |
| `ASI10 Rogue Agents` | A rogue or unexpected agent still has to satisfy protected-endpoint proof checks before it can cause a protected side effect on a compliant path. | The kernel cannot stop a rogue agent that already has valid proof from a compromised issuer or that acts outside the protected path entirely. |

## NIST AI RMF Mapping

The NIST AI RMF is broader than this repository. The kernel mostly helps with execution-edge control implementation inside the `GOVERN`, `MAP`, `MEASURE`, and `MANAGE` functions.

This section focuses on selected functions and categories from NIST AI RMF 1.0 that are directly relevant to protected execution.

| NIST AI RMF area | Where the kernel helps | What it does not claim |
| --- | --- | --- |
| `GOVERN 1` | The kernel publishes explicit specs, guarantees, threat boundaries, open-source scope, and conformance behavior. That gives teams a concrete technical control surface they can reference in internal AI governance processes. | It is not a full organizational governance program, legal inventory, or policy management system. |
| `MAP 1` | [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md) and [THREAT_MODEL.md](THREAT_MODEL.md) help teams define the specific consequential execution context, risk assumptions, failure classes, and trust boundaries for protected tools and endpoints. | It does not replace enterprise-wide risk identification across every model, workflow, and business process. |
| `MEASURE 1` | [CONFORMANCE.md](CONFORMANCE.md), active specs, and example artifacts give teams a way to test whether protected-endpoint behavior matches the published v1 surface. | It is not a complete measurement program for all AI trustworthiness characteristics. |
| `MEASURE 2.4`, `2.7`, `2.8`, `2.9` | Structured Action Intent, PCCB, Receipt, Refusal, replay state, protected-endpoint behavior, local evidence-query results, and optional execution anchors help teams evaluate security, resilience, transparency, accountability, and documented output context for consequential execution paths. | The kernel does not provide full model evaluation, fairness assessment, privacy assurance, or enterprise monitoring coverage. |
| `MANAGE 1` | The kernel gives teams concrete execution-edge response options: refuse invalid execution, enforce replay constraints, and generate structured outcome artifacts that can feed risk treatment and review. | It is not an enterprise risk register, policy workflow, or remediation management system. |

## How Structured Artifacts Help Audit And Compliance Review

The kernel's structured artifacts can help audit and compliance review because they make consequential execution legible in a stable public shape.

- `Action Intent` captures the requested consequential action in an explicit contract.
- `PCCB` captures the proof material the protected endpoint verifies for that execution attempt.
- `Receipt` captures structured success outcomes.
- `Refusal` captures structured blocked-execution outcomes.
- replay and protected-endpoint artifacts can show whether duplicate-execution or execution-edge checks were part of the path being reviewed.
- `EvidenceQuery` can answer whether a local proof and outcome chain exists for a specific receipt, PCCB, intent, or action hash.
- optional `ExecutionAnchor` publication can expose a digest-based public anchor for a terminal execution outcome without disclosing the full artifacts.

That can help reviewers answer questions such as:

- what action was requested
- what execution edge it was bound to
- whether the request was refused or executed
- whether replay or mismatch conditions were surfaced explicitly

Those benefits are useful for internal control review, security architecture review, and implementation auditability.

They can also make security questionnaires and internal control narratives more concrete because they give reviewers stable artifact shapes instead of hand-waved descriptions of "agent approval" or "tool authorization."

For enterprise review, the strongest use is usually:

1. verify that consequential execution is forced through a protected endpoint
2. verify that the protected endpoint enforces proof, audience, subject/tenant, expiry, and replay checks locally
3. verify that execution emits stable Receipt / Refusal artifacts
4. optionally use evidence query or execution anchors to strengthen implementation review and post-hoc traceability

They are not, by themselves:

- evidence of regulatory sufficiency
- proof that every production route uses the protected path
- proof that the issuer or external control plane made the right decision
- provider-authenticated proof of final external state
- portable cryptographic proof of origin for copied Receipt or Refusal artifacts in v1

## Practical Enterprise Use

Enterprise teams can use this repository to support:

- architecture reviews for agentic or tool-calling systems
- execution-edge control design reviews
- secure framework integration reviews
- internal control narratives for consequential tool and endpoint behavior
- compatibility testing for teams implementing the active public v1 surface

They should not use this repository alone as a substitute for:

- enterprise governance
- legal interpretation
- control-plane operations
- provider risk management
- complete compliance evidence programs

## Related Documents

- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [MULTI_AGENT_EXECUTION_MODEL.md](MULTI_AGENT_EXECUTION_MODEL.md)
- [spec/evidence-api/SPEC.md](spec/evidence-api/SPEC.md)
- [spec/execution-graph/SPEC.md](spec/execution-graph/SPEC.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)
