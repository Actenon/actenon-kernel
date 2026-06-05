# Actenon Hero Demo Transcript

Run:

```bash
bash scripts/demo_hero.sh
```

Expected terminal output:

```text
Actenon hero demo
No valid proof, no execution. Every consequential AI action leaves a verifiable receipt.
Local-only demo signer: development HMAC, not production custody.

Runtime: artifacts/hero_demo_runtime

Phase 1/3: Without execution-edge proof binding
Agent request: run a production database action
Outcome: WOULD_EXECUTE
Side effect executed: simulated only
Artifact: artifacts/hero_demo_runtime/simulations/replit/counterfactual_unprotected_execution.json
Summary: Counterfactual weak control path: a broadly trusted development agent turns an intended schema migration into a destructive database action and the execution edge never rechecks the exact action.

Phase 2/3: With Actenon, but no matching proof
Outcome: REFUSED
Reason code: ACTION_HASH_MISMATCH
Side effect executed: false
Refusal artifact: artifacts/hero_demo_runtime/simulations/replit/refusal.json
Refusal digest: sha256:9408f4573e097f38d38a483280ec70b3737df74d4119e09af4615b19840ff121

Phase 3/3: With valid proof
Agent request: execute one approved refund action
Outcome: EXECUTED
Side effect executed: simulated only
Receipt artifact: artifacts/hero_demo_runtime/simulations/replay-refused/execution_receipt.json
Receipt digest: sha256:353c73da14c3a6884c5308cf7d3826d8faeda8413a80ada9a1e2aab879fbfc71
Verifier: bound proof accepted; replay/escrow consumed once

Refusal snippet:
{
  "outcome": "refused",
  "reason_code": "ACTION_HASH_MISMATCH",
  "side_effect_executed": false,
  "pccb_id": "pccb_incident_replit",
  "action_hash": "badc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffe",
  "artifact_digest": "sha256:9408f4573e097f38d38a483280ec70b3737df74d4119e09af4615b19840ff121"
}

Receipt snippet:
{
  "outcome": "executed",
  "side_effect_executed": true,
  "receipt_id": "rcpt_sim_replay_0002",
  "pccb_id": "pccb_sim_replay_001",
  "action_hash": "a2df0ff9a688450b00509762f2624e027b3956f65a8fdf2a97987db2b2c5e186",
  "artifact_digest": "sha256:353c73da14c3a6884c5308cf7d3826d8faeda8413a80ada9a1e2aab879fbfc71"
}

Done: unproven action refused, valid proof executed once, artifacts written locally.
```

