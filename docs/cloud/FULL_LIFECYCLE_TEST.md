# Full Lifecycle Test

Status: local/in-process lifecycle coverage for the open kernel. This document
does not claim hosted Cloud production readiness, production KMS/HSM custody, or
Postgres tenant isolation.

## Scope

The lifecycle test is implemented in
`tests/integration/test_cloud_full_lifecycle.py`. It uses:

- an in-process control-plane harness
- kernel `ActionIntent` parsing
- kernel policy evaluation
- kernel-compatible PCCB issuance
- SQLite replay and capability escrow stores
- a protected endpoint middleware handler
- in-memory outcome writing
- local outcome attestation signing and verification

This is intentionally a deterministic local test. It is suitable for proving
the wire and lifecycle contract in CI. It is not a substitute for a hosted Cloud
operational audit.

## Lifecycle Covered

The positive path drives:

1. Tenant creation.
2. Policy creation.
3. ActionIntent submission.
4. Approval/evidence-aware policy allow decision.
5. Kernel-compatible PCCB issuance.
6. Single-use escrow creation.
7. Protected endpoint execution.
8. SQLite replay claim and consume.
9. SQLite escrow consume.
10. Receipt emission.
11. Receipt attestation.
12. Kernel verification of the PCCB and Receipt attestation.

The signed Receipt binds back to the proof through:

- `correlation.pccb_id`
- `correlation.escrow_id`
- `correlation.action_hash`
- the attestation `proof_binding`

## Negative Paths

The test also proves fail-closed behavior for:

- tampered action parameters
- wrong audience
- replay after a successful execution
- expired proof
- missing escrow reference
- malformed, structurally non-executable ActionIntent
- policy denial when approval/evidence requirements are not met

Each refused path emits a Refusal or refusal-shaped admission result and does
not increment the local billable-action meter.

## Evidence, Approval, Usage, And Audit

The in-process harness records:

- `tenant_created`
- `policy_created`
- `action_intent_accepted` or `action_intent_rejected`
- `policy_evaluated`
- `proof_issued`
- `escrow_created`
- `protected_execution_requested`
- `escrow_consumed`
- `receipt_emitted`
- `refusal_emitted`

Where available, the audit trace captures the approver identity and evidence
references used for the allow decision. The local usage meter counts only
proved-and-executed actions. Decision receipts, policy denials, proof failures,
replays, escrow failures, and malformed intents are not counted as billable in
this harness.

## Package Data Check

The installed-package integration test also verifies that the top-level
`schemas` package is present after `pip install .` and that
`pccb.v1.json` is available through `importlib.resources`.

## Out Of Scope

This test does not prove:

- production KMS/HSM custody
- non-exportable production signing keys
- hosted Actenon Cloud isolation
- Postgres tenant isolation
- multi-node escrow coordination
- downstream provider finality
- commercial billing behavior beyond the local harness policy
- business correctness of the allowed action

Use this test as a lifecycle contract check. Use separate operational tests for
hosted Cloud deployment, KMS/HSM custody, IAM, Postgres isolation, billing
systems, and production observability.
