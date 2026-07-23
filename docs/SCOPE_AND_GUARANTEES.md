# Scope And Guarantees

Actenon provides deterministic action authorization and verifiable
Receipt/Refusal artifacts at a protected execution boundary.

## Scope Boundary

**Actenon gates explicit execution-edge actions; it does not inspect or filter
prompts, model output, or in-band response content.**

**It can require proof for an explicit export or transmit action, but it does
not stop data disclosed inside ordinary output unless that disclosure is itself
modeled and routed as a protected action.**

This distinction is fundamental:

| Path | Inside Actenon's boundary? |
| --- | --- |
| `customer_data.export(destination="external")` routed through a protected endpoint | Yes. The endpoint can require exact-action proof and refuse before the export side effect. |
| `email.send(attachment=...)` routed through a protected tool | Yes. The send action and attachment metadata can be bound into proof. |
| A model includes sensitive text in its ordinary response | No. Actenon is not a model-output filter or data-loss-prevention system. |
| A tool returns sensitive data inside an unprotected response | No. There is no protected execution-edge action for Actenon to authorize. |
| An agent calls a provider directly with a standing credential | No. That is a bypass path outside the protected boundary. |

Actenon can gate a disclosure only when the disclosure is represented as an
explicit consequential action, bound into proof, and forced through the
protected execution path.

## What The Kernel Guarantees

For an action that reaches a correctly deployed protected boundary, Actenon
deterministically:

- verifies proof for the exact action, parameters, target, audience, tenant,
  subject, scope, and validity window
- enforces replay or single-use state according to the configured deployment
- refuses before the side effect when required proof, policy, or state does not
  verify
- emits a Receipt or Refusal artifact for the protected outcome

These are action-authorization and artifact guarantees. They are not claims
about model intent, generated content, business correctness, or downstream
provider truth.

## Condition Of The Edge Guarantee

**The edge guarantee applies only when the protected edge is the only path to
the resource, the backend accepts only brokered credentials issued after
verification, and the agent has no standing credential or alternate route.**

This is a condition of the guarantee, not a deployment preference. Every
alias, direct SDK path, browser session, queue consumer, admin endpoint, and
legacy integration that can cause the same side effect must be removed from the
agent path or protected by an equivalent boundary.

For multi-worker or multi-region execution, every edge that can perform the
same action must also share the required replay state. A protected route beside
an unprotected route provides evidence for the protected route only; it does
not protect the bypass.

## What Actenon Does Not Protect

Actenon does not:

- inspect, classify, redact, or filter prompts or generated output
- prevent prompt injection, jailbreaks, hallucination, or model misbehavior
- stop in-band disclosure through ordinary model or tool responses
- discover every action path or prove that every path is routed through the
  boundary
- make an authorized business decision correct
- protect actions performed through standing credentials or alternate routes
- prove provider settlement, delivery, storage, deletion, or other downstream
  finality
- guarantee that a compromised trusted issuer will not authorize a bad action
- replace IAM, DLP, output filtering, sandboxing, API gateways, service mesh,
  human approval, or provider-native controls

## Safe Product Description

Use:

> Actenon provides deterministic exact-action authorization at protected
> execution boundaries and emits verifiable Receipt or Refusal artifacts.

Avoid broad descriptions such as "AI security," "stops data leaks," "prevents
prompt injection," or "makes agents safe." Those phrases collapse model,
content, routing, authorization, and provider behavior into claims the kernel
does not make.

## Related Documents

- [Threat Model](../THREAT_MODEL.md)
- [Kernel Guarantees](../KERNEL_GUARANTEES.md)
- [Protected Edge Deployment](guides/EDGE_DEPLOYMENT.md)
- [Framework Adapters](guides/FRAMEWORK_ADAPTERS.md)
- [Deployment Architectures](architecture/DEPLOYMENT_ARCHITECTURES.md)
- [Trust Boundaries](architecture/TRUST_BOUNDARIES.md)
