# replay-refused

Simulation id: `replay-refused`

Status: `refused`

Duplicate execution was refused by the replay layer.

Lesson: Replay protection is a runtime property. Proof alone verifies intent, but only the protected endpoint with replay state prevents duplicate execution.

Refusal code: `DUPLICATE_REPLAY`

Receipt id: `rcpt_sim_replay_0003`

Intent Record: `/Users/ross/actenon-github-launch/artifacts/hero_demo_runtime/simulations/replay-refused/intent_record.json`

Perspectives:

- `without_execution_edge` [counterfactual] -> `would_execute_twice`
  Counterfactual: without execution-edge replay enforcement, the same proof-bearing request could drive two side effects.

- `proof_verifier_only` [observed] -> `would_verify_twice`
  Observed: proof verification alone accepted the same PCCB twice. Replay defense is not a signature property.

- `protected_endpoint_runtime` [observed] -> `first_execution_then_refused`
  Observed: the protected endpoint executed once and refused the duplicate with DUPLICATE_REPLAY.

- `action_intent_record` [observed] -> `recorded_refusal`
  Observed: the Action Intent, first execution Receipt, and replay Refusal show exactly which attempt succeeded and which duplicate was blocked.
