# Incident Analysis Template

Use this template to analyze a real incident in Actenon Kernel vocabulary.

The goal is not sensationalism or retrospective product marketing. The goal is to explain, as precisely as possible:

- what consequential action was involved
- where the execution gap existed
- which upstream controls existed
- which protected-endpoint checks would have mattered
- what the kernel would and would not honestly have changed

This template is suitable for Actenon-authored or third-party public writeups.

## Writing Rules

- State only facts that are known, sourced, or explicitly marked as assumptions.
- Distinguish observed incident facts from counterfactual kernel analysis.
- Do not claim the kernel would have blocked the incident unless the relevant protected-endpoint checks would actually have been in path.
- Do not claim provider-authenticated finality, post-side-effect truth, or control-plane correctness from the OSS kernel.
- Do not describe v1 `Receipt` or `Refusal` artifacts as portable cryptographic attestations of origin.

---

# Incident Analysis: `<incident title>`

## Metadata

- Incident date: `<date or time window>`
- Analysis date: `<date>`
- Analyst or organization: `<name>`
- Public sources reviewed: `<links, advisories, postmortems, filings, internal references if appropriate>`
- Confidence level: `<high | medium | low>`
- Disclosure note:
  `<what is known, what is inferred, what remains unverified>`

## 1. Incident Summary

Summarize the incident in neutral, technically precise language.

- Affected system or workflow:
  `<service, tool, endpoint, provider path, multi-agent workflow, etc.>`
- Outcome:
  `<what side effect occurred, what changed, what was exposed, what was executed>`
- Consequence class:
  `<money movement, permission change, data export, provider action, other irreversible side effect>`
- Short summary:
  `<one concise paragraph>`

## 2. Consequential Action Involved

Describe the action in kernel-style terms.

- Likely `Action Intent` equivalent:
  - action name: `<name>`
  - target: `<resource or endpoint>`
  - tenant: `<tenant or account boundary if applicable>`
  - subject: `<requester, actor, service, or delegated principal>`
  - audience: `<protected endpoint / tool / service identity>`
- Was the side effect executed, attempted, replayed, redirected, or ambiguously completed?
  `<describe>`
- Was the incident about one action or a chain of actions?
  `<single execution edge or multiple edges>`

If the public facts do not support one of these fields, say so explicitly rather than guessing.

## 3. Where The Execution Gap Existed

Identify the point where upstream authorization and the real execution edge diverged.

- Actual execution edge:
  `<the component that actually performed or triggered the side effect>`
- Upstream decision point(s):
  `<auth service, policy engine, approval system, orchestrator, workflow engine, model/tool planner>`
- Why this was an execution-gap issue:
  `<explain the missing execution-edge verification step>`
- Failure class:
  `<parameter substitution | replay | audience misdirection | wrong tenant | wrong subject | stale proof reuse | other>`

## 4. What Upstream Controls Existed And Why They Were Insufficient

Describe the controls that were present before execution and why they did not close the gap.

### Authentication

- What existed:
  `<session, token, identity, service authentication, etc.>`
- Why it was insufficient:
  `<did not bind exact action, target, audience, time window, or replay state at execution>`

### Policy

- What existed:
  `<policy engine, entitlement logic, role checks, rule evaluation, etc.>`
- Why it was insufficient:
  `<did not bind a single execution attempt at the side-effect boundary>`

### Approval

- What existed:
  `<human approval, system approval, ticketed workflow, checkpoint, etc.>`
- Why it was insufficient:
  `<could be replayed, redirected, mutated, or used after context changed>`

### Other controls

- Other controls present:
  `<audit logs, idempotency keys, provider checks, segregation of duties, review gates, etc.>`
- Why they were insufficient:
  `<explain precisely>`

## 5. Which Kernel Checks Would Have Mattered

Assess which Actenon protected-endpoint checks were relevant.

For each line, mark one:

- `would likely have blocked`
- `might have blocked`
- `not applicable`
- `would not have blocked`
- `unknown from public facts`

### Proof binding

- Exact action binding:
  `<rating + explanation>`
- Exact target binding:
  `<rating + explanation>`
- Exact audience binding:
  `<rating + explanation>`
- Exact tenant binding:
  `<rating + explanation>`
- Exact subject binding:
  `<rating + explanation>`

### Time and reuse controls

- `not_before` / `expires_at` enforcement:
  `<rating + explanation>`
- Replay enforcement:
  `<rating + explanation>`
- Escrow-aware execution checks, if relevant:
  `<rating + explanation>`

### Summary judgment

- Most important kernel check in this incident:
  `<one line>`
- Why:
  `<one short explanation>`

## 6. What Refusal Or Receipt Artifacts Would Likely Have Been Emitted

Describe the likely kernel outcome artifacts under a compliant protected-endpoint path.

### If the kernel would likely have blocked before side effects

- Likely `Refusal` category:
  `<proof | replay | escrow | execution | schema | policy | unknown>`
- Likely refusal code:
  `<current-code analogue if known; otherwise describe the nearest refusal class without inventing a new public code>`
- Likely refusal message:
  `<short, plain-language description>`
- Would a refused `Receipt` also likely exist on this path?
  `<yes | no | depends>`
- Likely useful correlation fields:
  `<pccb_id, request_id, refusal_id, action_hash, etc.>`

### If the kernel would not have blocked before side effects

- Likely `Receipt` outcome:
  `<executed | refused | ambiguous execution note if appropriate>`
- Why the kernel would still permit execution:
  `<for example: proof could still have been valid, or the failure occurred after control passed to the adapter>`
- What the receipt would and would not prove:
  `<structured kernel outcome versus provider finality or post-side-effect truth>`

### If the answer is genuinely uncertain

- What facts are missing:
  `<state them clearly>`
- Why that uncertainty matters:
  `<explain>`

## 7. What Remains Outside The Kernel's Scope

State plainly what the kernel would not have solved, even in a correct integration.

Consider:

- compromised issuer or signer
- compromised external control plane
- malicious or buggy adapter after control passes beyond the protected endpoint
- provider-authenticated reconciliation or settlement finality
- approval routing or evidence workflow operations
- long-term archive, dashboard, or audit operations
- portable cryptographic proof of origin for copied v1 artifacts

List only what is relevant to this incident.

## 8. Lessons For Adopters

Write lessons as concrete adoption guidance, not vague recommendations.

- Protected-endpoint lesson:
  `<what execution-edge change matters>`
- Replay lesson:
  `<what duplicate-execution or ambiguity lesson matters>`
- Integration lesson:
  `<tool, framework, or provider-boundary lesson>`
- Artifact lesson:
  `<how Receipt / Refusal / correlation artifacts help>`
- Boundary lesson:
  `<what should remain outside the OSS kernel claim>`

## Counterfactual Conclusion

Use one of these conclusions and then justify it in one paragraph:

- `A compliant Actenon protected-endpoint path would likely have blocked this incident before side effects.`
- `A compliant Actenon protected-endpoint path might have reduced or narrowed this incident, but the public facts are not sufficient to say it would definitely have blocked it.`
- `A compliant Actenon protected-endpoint path would probably not have blocked this incident because the failure was outside the kernel's defended boundary.`

## Related Kernel References

- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [spec/pccb/SPEC.md](spec/pccb/SPEC.md)
- [spec/replay/SPEC.md](spec/replay/SPEC.md)
- [spec/receipt/SPEC.md](spec/receipt/SPEC.md)
- [spec/refusal/SPEC.md](spec/refusal/SPEC.md)
