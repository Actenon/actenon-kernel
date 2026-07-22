# Consequential Action Coverage Matrix

The Consequential Action Coverage Matrix is a deterministic local simulation suite. It exercises representative consequential action surfaces and verifies Actenon's proof-bound refusal and execution behavior. It does not claim live provider integration, real exploitability, production exposure, downstream finality, or that every possible consequential action has been covered.

## What It Is

The matrix demonstrates Actenon's execution-boundary behavior across many classes of consequential AI-agent actions. It is designed to be fast enough for local development and CI while staying public-safe:

- runs locally
- requires no cloud calls
- requires no external secrets
- performs no real destructive action
- uses representative synthetic scenarios only
- emits machine-readable evidence under `artifacts/coverage/`

## Domains Covered

The default matrix covers 9 domains with 6 representative actions per domain:

- DevOps
- Fintech
- IAM / Access Control
- Database
- Browser / Computer Use
- MCP Tools
- Data Export
- Email / Communications
- Code Agent Operations

Each representative action is synthetic. The purpose is to exercise consequence classes such as deployment, payment mutation, access changes, data mutation, browser submission, MCP side effects, data export, outbound communication, and code-agent operations.

## Failure Modes Checked

For each representative action, the matrix checks:

- missing proof is refused
- action hash mismatch is refused
- parameter mismatch is refused
- audience mismatch is refused
- tenant or subject mismatch is refused
- expired proof is refused
- replay attempt is refused
- policy-denied action is refused
- valid proof-bound action executes once
- a Receipt or Refusal artifact is emitted for the outcome

The default suite runs 540 checks: 9 domains x 6 representative actions x 10 checks.

## Evidence Artifact

Run output is written to:

```text
artifacts/coverage/consequential_action_coverage_matrix.json
```

The JSON includes:

- `generated_at`
- `total_scenarios`
- `domains`
- `per_domain_counts`
- `check_counts`
- `artifact_counts`
- `result`
- `limitations`
- `representative_actions`
- `refusal_reason_codes_observed`
- Receipt and Refusal artifact sample references

Per-outcome Receipt and Refusal artifacts are written beside the evidence file under:

```text
artifacts/coverage/consequential_action_coverage_matrix_artifacts/
```

These files are local runtime evidence and are not intended to be committed.

## How To Run

From a fresh clone:

```bash
python3 -m pip install -e ".[asymmetric]"
python3 -m actenon.cli coverage run
```

Expected shape:

```text
ACTENON CONSEQUENTIAL ACTION COVERAGE MATRIX

Total scenarios: 540
Domains covered: 9

Domain evidence:
- DevOps:                   60 checks
- Fintech:                  60 checks
- IAM / Access Control:     60 checks
- Database:                 60 checks
- Browser / Computer Use:   60 checks
- MCP Tools:                60 checks
- Data Export:              60 checks
- Email / Communications:   60 checks
- Code Agent Operations:    60 checks

Result: PASS

No valid proof, no execution.
```

## What It Proves

The matrix proves that the local Actenon kernel can deterministically exercise representative consequential action surfaces and verify proof-bound refusal and execution behavior:

- invalid or missing proof is refused before the synthetic side-effect path
- proof mismatches are rejected at the protected endpoint
- replay attempts are rejected
- policy-denied actions are refused
- valid proof-bound actions execute once
- Receipt and Refusal artifacts are emitted

## What It Does Not Prove

The matrix does not prove:

- live provider integration
- provider-side finality
- real exploitability
- production exposure
- vulnerability severity
- coverage of every possible consequential action
- prevention of every unsafe AI action
- prevention of all prompt injection

It provides consequence-class evidence for proof-bound execution behavior in a deterministic local simulation.
