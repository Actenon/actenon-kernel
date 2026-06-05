# Protected Execution Kernel Test Plan

## Test Objective

Prove that the kernel enforces "No proof, no action" for the refund execution wedge and that all required support mechanisms behave correctly under both allow and refusal conditions.

`scripts/verify.sh` is the acceptance entry point. As implementation arrives, that script should expand to invoke the checks below instead of creating a second gate.

## Test Layers

### Unit

Unit tests should cover pure logic and deterministic component behavior.

Required unit coverage:

- Action Intent schema validation
- hard rules evaluation
- tenant rules evaluation
- dynamic context normalization
- PCCB minting
- PCCB verification
- Capability Escrow state transitions
- replay key generation and replay detection
- refusal envelope construction
- receipt construction

### Integration

Integration tests should cover component interaction without requiring external infrastructure.

Required integration coverage:

- Action Intent -> policy evaluation -> PCCB minting
- PCCB verification -> escrow validation -> protected refund execution
- refusal generation for policy deny, proof failure, escrow failure, and replay detection
- receipt persistence and lookup
- local proof mode end-to-end signing and verification

### End-To-End

End-to-end tests should exercise the full protected execution loop from inbound request to durable outcome.

Required end-to-end coverage:

- allowed refund request executes exactly once and emits a receipt
- over-limit refund request is refused before execution
- expired proof is refused
- mismatched tenant or amount in proof is refused
- replay of previously consumed proof is refused
- direct call to protected endpoint without proof is refused

## Mandatory Scenarios

### Positive Path

1. Submit a valid refund Action Intent.
2. Evaluate hard rules, tenant rules, and dynamic context.
3. Mint a PCCB for the approved refund.
4. Store and release the capability through escrow.
5. Verify proof at the protected refund endpoint.
6. Execute the refund once.
7. Emit and persist a receipt.

### Negative Paths

The following scenarios must each produce a refusal envelope and zero unauthorized side effects:

- malformed Action Intent
- policy deny from hard rules
- policy deny from tenant rules
- policy deny from dynamic context
- expired PCCB
- tampered PCCB
- amount mismatch between intent and proof
- currency mismatch between payment and refund request
- revoked escrow capability
- already-consumed capability
- replay attempt with previously used proof
- protected endpoint call without proof

## Test Data Requirements

The test harness should provide:

- at least one recorded payment fixture eligible for refund
- at least one tenant rule set that allows a refund
- at least one tenant rule set that denies a refund
- dynamic context fixtures for allow and refuse decisions
- deterministic local proof keys or equivalent local proof materials

## Evidence Required For Completion

The kernel is not complete until the test harness can show:

- all unit tests pass
- all integration tests pass
- all end-to-end tests pass
- the happy-path refund executes exactly once
- refusal cases do not trigger unauthorized refund side effects
- receipts and refusal envelopes are queryable for assertions

## Acceptance Mapping

- AC-001: unit + integration
- AC-002: unit + integration
- AC-003: unit + integration
- AC-004: unit + integration + end-to-end
- AC-005: unit + integration
- AC-006: unit + integration + end-to-end
- AC-007: integration + end-to-end
- AC-008: unit + integration + end-to-end
- AC-009: unit + integration + end-to-end
- AC-010: integration + end-to-end
- AC-011: end-to-end
- AC-012: integration + end-to-end
- AC-013: repository gate validation
