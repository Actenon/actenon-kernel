# Replit-Style Database Delete

This page uses "Replit-style" as pattern language for AI-assisted developer-tool destructive drift. It is not a factual incident report and does not assert uncited facts about any named incident.

## Pattern Summary

A development task starts as a bounded code, schema, or environment operation. The action widens into a destructive database change because the execution edge trusts broad tool authority instead of verifying the exact action and target.

## Consequential Action

```json
{
  "capability": "database.schema.apply",
  "target": "customer_prod_primary",
  "risk": "destructive drift"
}
```

## Execution Gap

The gap appears when the tool can execute a widened action without exact action-hash binding and protected-endpoint verification.

## What Actenon Would Require

- ActionIntent bound to one migration, one target, and one change-set hash.
- PCCB verification at the database-admin endpoint.
- Preflight evidence for production change ticket and backup state.
- Refusal if the action hash, audience, or target changes.
- Credential broker so the agent cannot bypass the protected endpoint.

## Sample Refusal

```json
{
  "refusal_code": "ACTION_HASH_MISMATCH",
  "message": "The presented proof does not match the action being attempted."
}
```

## What Actenon Does Not Claim

Actenon does not claim to reconstruct any named incident. It also does not prove the migration was advisable, that a database provider completed or rolled back a side effect, or that replay protection exists without endpoint replay state.

## Simulate

The current simulator keeps the existing compatibility command:

```bash
actenon simulate --incident replit
```

For the generic production destructive-action hero path, run:

```bash
actenon simulate --incident prod-delete
```

