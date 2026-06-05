# Scanner Output Summary

Actenon Scanner maps agent authority. It does not accuse your repo of being vulnerable.

Use this summary when sharing scanner output in a README, deck, or issue:

```text
Runtime-source candidate paths: 2
Additional test/example/context findings: 3, downgraded
Consequence Class: High-impact candidate, if reachable and ungated
Gating Status: Not verified
Runtime Reachability: Not proven
Vulnerability Claim: No
Manual Review Required: Yes
```

This is not a vulnerability severity rating. It is a consequence-class map of candidate action surfaces found by static analysis.

Runtime reachability, exploitability, production exposure and business impact are not proven by this scan.

Buyer-friendly summary:

> Actenon found candidate AI-controlled action paths. Static analysis could not verify that high-impact actions are proof-bound before execution. These findings are advisory and require maintainer review.

Developer-friendly question:

> Can a model, agent, workflow, MCP tool, browser controller, or computer-use path reach a side effect before a proof/authorization gate, approval/evidence policy, credential boundary, replay control, or audit receipt?

Public-safe badge wording:

- Actenon Scan: Review required
- Gating: Not verified
- Action Surface: Review required
- Consequence Map: High-impact candidates

Avoid using bare vulnerability-style labels such as `Critical`, `High Risk`, or `Critical Risk` for static advisory scanner output.
