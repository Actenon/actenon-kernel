# Actenon Hero Demo Transcript

Run:

```bash
bash scripts/demo_hero.sh
```

Expected terminal output:

```text
ACTENON
No valid proof, no execution.

Agent attempts:
  database.delete_table production_customers

WITHOUT proof gate:
  WOULD EXECUTE
  side_effect_executed: true
  consequence: destructive action reaches side effect path

WITH ACTENON:
  REFUSED
  reason_code: ACTION_HASH_MISMATCH
  side_effect_executed: false
  refusal artifact: artifacts/hero_demo_runtime/live/simulations/replit/refusal.json

VALID PROOF:
  EXECUTED ONCE
  side_effect_executed: true
  receipt artifact: artifacts/hero_demo_runtime/live/simulations/replay-refused/execution_receipt.json

SNAPSHOT:
{
  "refusal": {
    "reason_code": "ACTION_HASH_MISMATCH",
    "side_effect_executed": false,
    "artifact": "artifacts/hero_demo_runtime/live/simulations/replit/refusal.json",
    "pccb_id": "pccb_incident_replit",
    "artifact_digest": "sha256:854848e9c4404ff9f6fcae0bffd32543c56a0aa1746571bfa7687f63fbafaed6"
  },
  "receipt": {
    "outcome": "executed",
    "side_effect_executed": true,
    "artifact": "artifacts/hero_demo_runtime/live/simulations/replay-refused/execution_receipt.json",
    "receipt_id": "rcpt_sim_replay_0002",
    "pccb_id": "pccb_sim_replay_001",
    "artifact_digest": "sha256:80896edb20bac4da429b3c8a25f2383ef088f6130e9ca5e1441d1ed7fc86abb6"
  }
}

Done: unproven action refused; valid proof executed once.
```
