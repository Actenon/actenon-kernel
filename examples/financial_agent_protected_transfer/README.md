# Financial Agent Protected Transfer

This example shows Actenon protecting the clearest high-consequence boundary: money movement.

The agent can reason about a transfer. It can ask to transfer funds. It can even be prompt-injected into trying the wrong transfer.

But the ledger does not move unless the protected financial boundary receives valid proof bound to the exact amount, destination, tenant, subject, audience, expiry, and replay identity.

The trust boundary is not the agent. The trust boundary is the protected execution edge.

## Run it

From the repo root:

```bash
python3 -m pytest examples/financial_agent_protected_transfer -q
```

Expected result:

```text
5 passed
```

## What the tests prove

The tests assert resource state, not just status strings:

| Test | Expected boundary behaviour | Ledger result |
| --- | --- | --- |
| `test_missing_proof_does_not_move_money` | Refused before side effect | Balances unchanged |
| `test_wrong_amount_proof_does_not_move_money` | Refused before side effect | Balances unchanged |
| `test_wrong_destination_proof_does_not_move_money` | Refused before side effect | Balances unchanged |
| `test_replayed_proof_does_not_move_money_twice` | First execution allowed, replay refused | One transfer only |
| `test_valid_exact_proof_moves_money_once` | Valid exact proof executes | One transfer and receipt evidence |

## Why this matters

Most AI-agent safety examples focus on what the agent should or should not decide.

Actenon focuses on the moment that matters more:

> Does the side effect actually happen?

In this example, a financial agent may attempt a transfer, but the ledger mutation is behind an Actenon-protected boundary. If proof is missing, mismatched, replayed, or bound to a different action, Actenon refuses before the ledger mutates and emits refusal evidence.

If proof is valid and exact, the transfer executes once and emits receipt evidence.

## Local development only

This example uses `ActenonGate.local_dev(...)`, which uses the local development proof signer.

That is intentionally not production signing custody. Production deployments should use asymmetric/KMS/HSM-backed signing and verifier configuration, plus production replay state and operational key management.
