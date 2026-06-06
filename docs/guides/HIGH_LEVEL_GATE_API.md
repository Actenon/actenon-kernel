# High-Level Gate API

`ActenonGate` is the package front door for proof-bound execution. It wires
exact-action verification, replay protection, optional Preflight policy,
optional capability escrow, credential brokering, and Receipt/Refusal emission
behind one call.

## Local development

```python
from actenon import ActenonGate

gate = ActenonGate.local_dev(audience="service:protected-endpoint")
proof = gate.mint_proof(action_intent)
outcome = gate.protect(action_intent, proof, side_effect)
```

`local_dev()` uses the repository's public HMAC development key. It is for
local tests and demos only. It is not a production trust root.

The complete valid, mismatch, and replay sequence is in
[`../../examples/quickstart_min.py`](../../examples/quickstart_min.py).

## Asymmetric or managed signing

A production protected endpoint needs a trusted `SignatureVerifier`; it does
not need proof-minting authority:

```python
from actenon import ActenonGate

gate = ActenonGate(
    verifier=well_known_or_managed_verifier,
    audience="service:payments-protected-endpoint",
    issuer="service:payments-proof-issuer",
)
outcome = gate.protect(action_intent, supplied_proof, execute_payment)
```

If the same process is authorized to issue proofs, pass a separate
`Signer`-compatible KMS/HSM signer with `signer=...`. `mint_proof()` is
unavailable on verifier-only gates.

## Secure defaults

- Replay and single-use protection are on by default.
- `replay_protection="disabled"` is an explicit unsafe opt-out and emits a
  warning.
- A custom durable `ReplayProtector` can be supplied for shared execution
  edges.
- Escrow remains optional. When configured, `mint_proof()` issues the escrow
  reference and `protect()` consumes it before credential brokering.
- A configured `PolicyPack` runs through Preflight and is enforced before the
  side effect.

## Outcomes

`protect()` always returns a `GateOutcome` for a valid Action Intent:

```python
if outcome.ok:
    print(outcome.receipt)
else:
    print(outcome.reason_code, outcome.refusal)
```

The outcome exposes `ok`, `outcome`, `reason_code`, `unmet_requirements`,
`receipt`, `refusal`, `payload`, and `to_dict()`. Missing proof is a
`PCCB_REQUIRED` refusal. Exact-action mismatch and replay are refused before
the side effect.

The common side-effect form takes no arguments. Advanced endpoint handlers may
accept `(request, brokered_credential)` when they need the verified request or
the brokered credential reference.

## Decorator

```python
@gate.protect_action(action_intent, proof)
def change_production_state():
    return {"status": "changed"}

outcome = change_production_state()
```

The decorated function body runs only after proof, policy, replay, escrow, and
credential-broker checks succeed.
