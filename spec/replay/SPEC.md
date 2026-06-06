# Replay Spec

Status: Active behavioral spec

## Purpose

Replay protection prevents the same proof-bound action from being executed more than once at the execution edge.

Replay is a kernel responsibility. It is not optional host-app glue.

## Terminology

- Replay key: the durable identity used to detect duplicate execution attempts.
- Claim: the first successful reservation of a replay key for an execution attempt.
- Consume: the terminal state that prevents later duplicate use.
- Release: explicit abandonment of a claim before crossing the ambiguity boundary.
- Expire: aging out a stale unconsumed claim so a fresh attempt may proceed.
- Ambiguity boundary: the point after which duplicate retries are unsafe because side effects may already have happened.

## Expected Behavior

Replay identity MUST be derived from proof and execution bindings that make duplicate execution unsafe to accept.

In the current open kernel, the replay key is derived from proof identity and exact execution attributes including:

- `pccb_id`
- `nonce`
- `action_hash`
- `audience`
- capability
- target
- tenant
- subject

## State Model

A conforming replay implementation MUST support these states:

- `claimed`
- `consumed`
- `released`
- `expired`

## State Semantics

- claim must be atomic
- duplicate active claims must fail
- released claims may be reclaimed
- expired stale claims may be reclaimed
- once execution succeeds, the claim must be marked `consumed`
- once execution has crossed a boundary where duplicate retries are unsafe, the claim must also be treated as `consumed` even if the downstream handler reports failure
- replay state MUST be durable enough for the deployment's execution model

## Failure Surface

The current open kernel uses these stable replay failure codes:

- `DUPLICATE_REPLAY`
- `REPLAY_STATE_INVALID`
- `REPLAY_CLAIM_MISSING`
- `REPLAY_STORE_UNAVAILABLE`
- `REPLAY_STORE_ROLLBACK_DETECTED`

Replay failures surface as structured refusals in the `replay` category.

## Security Considerations

- replay protection is effective only if claim and transition operations are atomic for the chosen backend
- replay-store failures must refuse before side effects unless a host explicitly selects and logs an unsafe fail-open mode
- weak or partial replay keys can permit dangerous duplicate execution
- claims should not be released after the ambiguity boundary unless the operator has a stronger external guarantee that no side effect occurred
- replay protection complements, but does not replace, proof verification and capability-state enforcement

## Boundary

Replay is distinct from proof verification and distinct from escrow:

- proof verifies authorization and binding
- replay blocks duplicate delivery at execution time
- escrow governs single-use capability state

All three may be required for a complete protected execution path.

## Compatibility And Versioning

- Replay behavior is part of the public kernel surface even though no standalone replay JSON schema is published today.
- Changes to required replay states, transition meaning, or duplicate-handling semantics are compatibility-significant.
- Backend implementation details may vary as long as the public replay semantics remain intact.

## Related Documents

- [`../../docs/reference/EXECUTION_SEMANTICS.md`](../../docs/reference/EXECUTION_SEMANTICS.md)
- [`../../CONFORMANCE.md`](../../CONFORMANCE.md)
- [`../../docs/guides/CONFORMANCE_TESTS_GUIDE.md`](../../docs/guides/CONFORMANCE_TESTS_GUIDE.md)
- [`../refusal/examples/replay-refused.json`](../refusal/examples/replay-refused.json)
