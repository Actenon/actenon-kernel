# Protected Endpoint Spec

Status: Active behavioral spec

## Purpose

The protected endpoint is the execution edge. Its job is to ensure that a consequential action executes only when the request carries valid proof for that exact execution attempt.

This spec defines behavior, not a required transport or framework.

A protected endpoint is the last component before side effects. If proof verification happens elsewhere but the execution edge can still act without re-checking it, that edge is not conforming to this spec.

## Terminology

- Protected endpoint: the component that can trigger a consequential side effect.
- Verification context: the locally known context a verifier uses to evaluate a PCCB, including audience identity, time, and permitted capabilities.
- Consequential action: an action whose incorrect execution is materially unsafe or costly.
- Ambiguity boundary: the point after which a duplicate retry would be unsafe because the downstream side effect may already have occurred.

## Required Inputs

A conforming protected endpoint must receive:

- an Action Intent
- a PCCB
- endpoint-specific verification context, including the intended audience and permitted capability set

## Expected Behavior

Before any protected side effect, a conforming protected endpoint MUST:

1. parse or validate the Action Intent and PCCB
2. verify PCCB signature integrity and trust
3. enforce `not_before` and `expires_at`, with any explicitly configured bounded clock skew tolerance treated as part of the verifier's local context
4. enforce exact audience match
5. enforce exact action, target, tenant, and subject match
6. enforce scope capability match
7. enforce action-hash match
8. enforce replay and single-use protections required for the execution path

If any check fails, the endpoint must refuse execution.

## Non-Conforming Shortcuts

The following patterns break the protected-endpoint model and MUST NOT be treated as conforming behavior:

- executing the side effect before proof verification completes
- relying on upstream approval, policy, or workflow state as a substitute for endpoint verification
- verifying one request shape and executing another transformed or expanded shape
- injecting hidden side-effect parameters that are not represented in the verified Action Intent and local verifier constraints
- sharing one audience identity across unrelated protected endpoints without an equivalent security boundary
- skipping replay or single-use checks on a path that claims replay-safe execution

## Execution Semantics

- no protected side effect may occur before verification succeeds
- replay claim must happen before entering the side-effecting handler
- if pre-execution guards fail after replay claim, the claim may be released
- once execution crosses the ambiguity boundary where duplicate retries are unsafe, replay state must be treated as consumed
- the endpoint SHOULD emit a structured refusal when execution is blocked
- the endpoint SHOULD emit a structured receipt when execution completes through a receipt-producing integration path

## Security Considerations

- protected endpoints SHOULD fail closed when proof, replay, or execution-state checks are unavailable or inconclusive
- audience and capability checks are mandatory security controls, not advisory hints
- clock skew tolerance, if used, SHOULD be small, explicit, and justified by deployment clock drift rather than operational queueing delay
- execution logic should not deserialize untrusted extension data into hidden authorization behavior
- duplicate delivery after the ambiguity boundary must be treated as unsafe unless a stronger external guarantee exists

## Out Of Scope

This spec does not standardize:

- HTTP wire format
- framework middleware shape
- approval workflow APIs
- provider adapter interfaces
- hosted operational state

## Compatibility And Versioning

- This behavioral spec is part of the public kernel surface.
- Adding new mandatory verifier checks or changing the meaning of existing checks is a compatibility-significant change and may require a new major version of the relevant contract surface.
- Explanatory implementation examples do not change conformance requirements.

## Reference Material

- [`../../docs/reference/EXECUTION_SEMANTICS.md`](../../docs/reference/EXECUTION_SEMANTICS.md)
- [`../../CONFORMANCE.md`](../../CONFORMANCE.md)
- [`../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits`](../../THREAT_MODEL.md#threats-kernel-response-and-residual-limits)
- [`../../docs/guides/INTEGRATION_QUICKSTART.md`](../../docs/guides/INTEGRATION_QUICKSTART.md)
- [`../../docs/reference/verifier/VERIFIER_SDK_REFERENCE.md`](../../docs/reference/verifier/VERIFIER_SDK_REFERENCE.md)
- [`../../docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md`](../../docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md)
- [`../pccb/examples/wrong-audience.json`](../pccb/examples/wrong-audience.json)
- [`../pccb/examples/expired.json`](../pccb/examples/expired.json)
- [`../pccb/examples/wrong-tenant.json`](../pccb/examples/wrong-tenant.json)
- [`../pccb/examples/wrong-subject.json`](../pccb/examples/wrong-subject.json)
- [`../pccb/examples/mutated-action.json`](../pccb/examples/mutated-action.json)
- [`../refusal/examples/audience-mismatch.json`](../refusal/examples/audience-mismatch.json)
- [`../refusal/examples/expired-proof.json`](../refusal/examples/expired-proof.json)
- [`../refusal/examples/wrong-tenant.json`](../refusal/examples/wrong-tenant.json)
- [`../refusal/examples/wrong-subject.json`](../refusal/examples/wrong-subject.json)
- [`../refusal/examples/action-mismatch.json`](../refusal/examples/action-mismatch.json)
- [`../refusal/examples/action-hash-mismatch.json`](../refusal/examples/action-hash-mismatch.json)
- [`../refusal/examples/replay-refused.json`](../refusal/examples/replay-refused.json)
