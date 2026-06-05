# Data Export Exfiltration Pattern

This is a generic pattern simulation, not a named factual incident report.

## Pattern Summary

An agent with standing data access exports a broad or sensitive dataset to an external destination. Read access becomes export authority because the execution edge does not verify legal basis, scope, destination, approval, or evidence.

## Consequential Action

```json
{
  "capability": "data.export",
  "target": "customer_prod_profiles",
  "row_count": 25000,
  "destination": "external"
}
```

## Execution Gap

The gap appears when data read credentials can be used as bulk export credentials without an execution-specific boundary.

## What Actenon Would Require

- Preflight classification as sensitive export.
- Approval for broad, sensitive, or external export.
- Destination and legal-basis evidence where policy requires it.
- Protected endpoint that brokers export authority instead of giving the agent standing warehouse credentials.
- Receipt/Refusal artifact for the export attempt.

## Sample Decision

```json
{
  "outcome": "approval_required",
  "reason_code": "PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED"
}
```

## What Actenon Does Not Claim

Actenon does not prove the export is lawful, that downstream storage is secure, or that a destination accepted or deleted data. It can verify and record the protected execution decision before the side effect.

## Simulate

```bash
actenon simulate --scenario data-export
```

