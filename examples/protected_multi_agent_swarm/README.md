# Evidence: a protected multi-agent swarm on a shared resource boundary

A runnable, self-verifying demonstration for multi-agent swarm architectures.

An orchestrator delegates to specialist sub-agents and a scaled-out worker pool. Every agent acts through its own Actenon gate, but all gates share one replay store.

The key swarm question is:

> When multiple independent agents can all act, does the protected boundary still enforce exactly one correct action?

This example attacks swarm-native failure modes that a single-agent test cannot fully cover:

- delegation amplification
- cross-agent proof laundering
- confused-deputy / audience confusion
- cross-agent replay
- rogue swarm member with no proof
- real concurrency: 32 workers racing the same proof at once

The concurrency test is the critical evidence. Thirty-two independent worker gates race the same valid proof against a shared replay store. Exactly one worker must execute, and every other worker must be refused.

## Run it

    pip install -e ".[asymmetric]"
    python examples/protected_multi_agent_swarm/protected_multi_agent_swarm.py
    echo "exit: $?"

## What it proves

The test verifies that the boundary enforces one correct action across multiple independent agents when they share a replay store. It also proves that an approved proof cannot be amplified, laundered into another tool, used by the wrong audience, replayed by a scaled-out worker, or raced successfully by multiple workers at the same time.

## Scope

This is a development evidence example. It is not a production deployment, third-party security audit, or proof of production key custody. The local HMAC signer is development-only; production should use asymmetric signing under managed custody.

> No valid proof, no execution.
