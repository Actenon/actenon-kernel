# Preflight Evidence

Actenon Preflight evaluates every matching rule in one pass. A refused decision
includes `unmet_requirements`, so callers can see all missing evidence and
approvals before retrying.

This guide documents the exact `evidence_context` keys accepted by the default
`destructive_data_v1` policy pack. Evidence is local policy input. It does not
replace proof verification at the protected endpoint, and production
deployments should bind verified evidence references or digests to their
authorization process.

## Evidence Shape

Raw dictionaries remain supported:

```python
evidence = {
    "change_ticket": "CHG-2026-0042",
    "approval_present": True,
    "approver_types": ["security_admin"],
}
```

The typed builder emits the same shape:

```python
from actenon.preflight import PreflightEvidence

evidence = PreflightEvidence(
    change_ticket="CHG-2026-0042",
    approval_present=True,
    approver_types=("security_admin",),
)
```

Pass either form to `PreflightEngine.check(..., evidence_context=evidence)` or
`ActenonGate.protect(..., evidence=evidence)`.

## Default Rules

| Rule | Trigger | Exact `evidence_context` shape | Satisfying example |
|---|---|---|---|
| Capability classification | Capability is outside the default pack | `capability_classification: string` | `{"capability_classification": "non_consequential"}` after local review. Consequential capabilities need a custom policy rule. |
| Production change ticket | A covered consequential action targets `production` | `change_ticket: string` | `{"change_ticket": "CHG-2026-0042"}` |
| Backup evidence | A production delete, schema, infrastructure, volume, or migration action requires backup evidence | `backup_verified: boolean` | `{"backup_verified": true}` |
| Production destructive approval | A production destructive action is not the unconditional backup-delete denial | `approval_present: boolean`; `approver_types: array[string]` | `{"approval_present": true, "approver_types": ["infrastructure_owner", "security_admin"]}` |
| Production backup delete denied | `backup.delete` targets `production` | No evidence key overrides this default deny | Use a reviewed custom policy pack if the deployment intentionally permits this action. |
| Broad data export approval | `data.export` is sensitive, external, or has at least 10,000 rows | `approval_present: boolean`; `approver_types: array[string]` | `{"approval_present": true, "approver_types": ["data_owner", "privacy_reviewer"]}` |
| Admin permission approval | `iam.permission.grant` grants admin, owner, root, superuser, or wildcard authority | `approval_present: boolean`; `approver_types: array[string]` | `{"approval_present": true, "approver_types": ["security_admin"]}` |
| Sandbox low-risk allow | Environment is `sandbox`, `dev`, `development`, `test`, or `staging` | No additional evidence | `{"environment": "sandbox"}` when the intent does not already classify its environment. |
| Environment context | No intent, target, or evidence value classifies the environment | `environment: string` | `{"environment": "production"}` |
| Requirements satisfied | Environment is known and no blocking rule remains | No additional evidence | Returned automatically after every applicable requirement is satisfied. |

`backup_snapshot` remains accepted as a legacy alias for backup evidence.
`approval_present: true` without `approver_types` remains accepted for backward
compatibility. New integrations should always supply the documented roles so
the approval shape is explicit.

## IAM Admin Grant

Without evidence, a production admin grant reports both the change-ticket and
admin-approval requirements:

```json
{
  "unmet_requirements": [
    {
      "reason_code": "PREFLIGHT_CHANGE_TICKET_REQUIRED",
      "evidence_keys": [
        {"key": "change_ticket", "type": "string", "example": "CHG-2026-0042"}
      ]
    },
    {
      "reason_code": "PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED",
      "evidence_keys": [
        {"key": "approval_present", "type": "boolean", "example": true},
        {
          "key": "approver_types",
          "type": "array[string]",
          "example": ["security_admin"]
        }
      ]
    }
  ]
}
```

Supply both in one pass:

```json
{
  "change_ticket": "CHG-2026-0042",
  "approval_present": true,
  "approver_types": ["security_admin"]
}
```

## Sensitive Export

A production broad or sensitive export requires:

```json
{
  "change_ticket": "CHG-2026-0043",
  "approval_present": true,
  "approver_types": ["data_owner", "privacy_reviewer"]
}
```

The rule triggers when `row_count` is at least `10000`, `sensitive_data` is
true, or `destination` is an external URL, `s3://`, `gs://`, `external`,
`third_party`, or `vendor`. Those classification values may come from the
Action Intent parameters or local evidence context.

## Decision Precedence

All blockers are returned. The backward-compatible top-level `outcome`,
`reason_code`, and `summary` select the highest-risk blocker; equally risky
results prefer `deny`, then `approval_required`, then `needs_evidence`.
Original policy-pack order breaks any remaining tie.

The protected endpoint still verifies exact-action proof, replay state, and
configured escrow before brokering credentials and reaching the side effect.
