# Protected policy preflight refund example

This example demonstrates the correct split between issuer policy and execution-boundary verification.

Actenon core is domain-neutral. It should not hard-code business rules such as "refund amounts must be positive" or "bulk deletes must be below 50 records".

Instead:

1. The issuer/control-plane runs domain policy before proof issuance.
2. Proof is minted only if policy allows the exact action.
3. The protected boundary verifies the proof immediately before the side effect.

This example proves:

- positive refund -> proof minted -> side effect executes
- negative refund -> proof not minted -> no side effect
- excessive refund -> proof not minted -> no side effect
- proof for a small refund cannot be reused for a larger refund
