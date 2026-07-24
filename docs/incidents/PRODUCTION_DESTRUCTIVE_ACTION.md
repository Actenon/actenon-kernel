# Production Destructive Action

This is a generic pattern simulation, not a named factual incident report.

## Pattern Summary

An agent starts from a maintenance or cleanup task and reaches a production destructive operation while holding standing production credentials. Without an execution boundary, the side effect can occur before a human or system verifies the exact target, environment, approval, and backup evidence.

## Consequential Action

```json
{
  "capability": "database.delete",
  "target": "prod-db-primary",
  "environment": "production"
}
```

## Execution Gap

The gap appears when the agent can call the production system directly:

```text
agent -> standing credential -> production database
```

Actenon is strongest when the path becomes:

```text
agent -> ActionIntent/PCCB -> protected endpoint -> brokered credential -> production database
```

## What Actenon Would Require

- Preflight decision for the exact production delete.
- Evidence such as backup status and change ticket.
- Required approval for production destructive action.
- No standing production credential on the agent.
- Receipt or Refusal emitted before any side effect.

## Sample ActionIntent

```json
{
  "contract": {"name": "action_intent", "version": "v1"},
  "intent_id": "intent_pattern_prod_delete_001",
  "action": {
    "name": "database.delete",
    "capability": "database.delete",
    "parameters": {
      "environment": "production",
      "change_ticket": "CHG-9001",
      "backup_verified": true
    }
  },
  "target": {"resource_type": "database", "resource_id": "prod-db-primary"}
}
```

## Sample Decision

```json
{
  "outcome": "approval_required",
  "reason_code": "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
  "summary": "Production destructive action requires explicit approval before execution."
}
```

## What Actenon Does Not Claim

Actenon does not claim the business decision is correct, that downstream provider finality occurred, that the adapter is honest, or that replay protection exists unless the protected endpoint enforces replay state.

## Simulate

```bash
actenon-kernel simulate --incident prod-delete
```

