# IAM Privilege Escalation Pattern

This is a generic pattern simulation, not a named factual incident report.

## Pattern Summary

An agent with standing IAM authority can grant admin or wildcard permissions to itself or another principal. The business task may be legitimate, but raw credential access lets the side effect happen without proof, approval, or an audit-grade refusal path.

## Consequential Action

```json
{
  "capability": "iam.permission.grant",
  "principal": "agent-runtime-service-account",
  "role": "admin",
  "scope": "*"
}
```

## Execution Gap

The gap appears when standing credentials let the agent bypass a protected privilege-grant boundary.

## What Actenon Would Require

- Preflight classification as privileged access.
- Approval for admin or wildcard grants.
- Protected endpoint as the broker of IAM authority.
- Receipt/Refusal artifact for the attempted grant.

## Sample Decision

```json
{
  "outcome": "approval_required",
  "reason_code": "PREFLIGHT_ADMIN_PERMISSION_APPROVAL_REQUIRED"
}
```

## What Actenon Does Not Claim

Actenon does not prove the requested role is appropriate, that downstream IAM propagation completed, or that every cloud account path is protected. It only protects actions routed through the protected execution boundary.

## Simulate

```bash
actenon simulate --scenario iam-escalation
```

