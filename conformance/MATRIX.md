# Conformance Matrix

This matrix is intentionally scoped to the active public compatibility target. It is not a general product checklist.

The central behavioral surface is the Protected Endpoint: the rows below validate that proof-bound execution is accepted or refused at the execution edge, and that the canonical Receipt and Refusal artifacts preserve the public shape around that behavior.

Outcome Attestation is additive and opt-in. It verifies signed envelopes around v1 Receipt and Refusal artifacts without changing those v1 payload semantics.

| Area | Active surface | Behavior | Test location |
| --- | --- | --- | --- |
| Proof verification | PCCB, Protected Endpoint | valid proof is accepted | `tests/conformance/test_verifier_sdk_conformance.py` |
| Proof verification | PCCB, Protected Endpoint | audience mismatch is refused | `tests/conformance/test_verifier_sdk_conformance.py` |
| Proof verification | PCCB, Protected Endpoint | action mutation is refused | `tests/conformance/test_verifier_sdk_conformance.py` |
| Proof verification | PCCB, Protected Endpoint | expired proof is refused | `tests/conformance/test_verifier_sdk_conformance.py` |
| Replay behavior | Replay, Protected Endpoint | duplicate execution is replay-refused | `tests/conformance/test_replay_conformance.py` |
| Refusal shape | Refusal, Replay | replay refusal parses and preserves public fields | `tests/conformance/test_replay_conformance.py` |
| Receipt shape | Receipt | execution and refusal receipts parse and preserve public fields | `tests/conformance/test_artifact_shape_conformance.py` |
| Refusal shape | Refusal | policy refusal parses and preserves public fields | `tests/conformance/test_artifact_shape_conformance.py` |
| Outcome attestation | Outcome Attestation | attested Receipt and Refusal envelopes are created, verified, and fail on tampering or wrong keys | `tests/conformance/test_outcome_attestation_conformance.py` |
| Execution semantics | Protected Endpoint | valid state paths are accepted | `tests/conformance/test_execution_state_conformance.py` |
| Execution semantics | Protected Endpoint | invalid state paths are rejected | `tests/conformance/test_execution_state_conformance.py` |

Reserved surfaces such as Reconciliation and Policy Bundle are intentionally absent from this matrix because they are not active v1 compatibility targets.
