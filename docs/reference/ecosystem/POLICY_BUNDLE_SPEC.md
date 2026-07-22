# Policy Bundle Spec

## Purpose

This document defines a portable policy-bundle shape that a paid control plane or other external policy system can hand to the open kernel ecosystem.

The goal is to let external systems move policy constraints, reason codes, and workflow requirements into kernel-adjacent environments without embedding hosted policy management into this repository.

## Scope

This document defines:

- a portable policy-bundle envelope
- a portable policy-rule descriptor
- how bundles constrain capabilities and audiences

This document does not define:

- a hosted policy authoring product
- a policy UI
- a full policy-evaluation engine
- proprietary workflow storage

## Normative Interface

The reference model lives at:

- `actenon/models/policy_bundle.py`

Related reserved public spec surface:

- `spec/policy-bundle/SPEC.md`

## Bundle Structure

A policy bundle contains:

- `contract` with `name=policy_bundle` and `version=v1`
- `bundle_id`
- `issued_at`
- `issuer`
- `rules`

Optional envelope fields:

- `tenant_id`
- `not_before`
- `expires_at`
- `audiences`
- `capabilities`
- `metadata`

## Rule Structure

Each `PolicyBundleRule` contains:

- `rule_id`
- `effect`
- `summary`
- `reason_code`
- `capabilities`

Optional rule fields:

- `audiences`
- `parameter_constraints`
- `resource_selectors`
- `required_evidence_types`
- `approver_types`
- `metadata`

The rule structure is intentionally declarative. It is a transport shape, not a full hosted workflow runtime.

## Example

```json
{
  "contract": {
    "name": "policy_bundle",
    "version": "v1"
  },
  "bundle_id": "pb_20260406_demo_001",
  "issued_at": "2026-04-06T10:00:00Z",
  "issuer": "control-plane.example",
  "tenant_id": "tenant_demo",
  "audiences": ["service:protected-endpoint"],
  "capabilities": ["refund.execute"],
  "rules": [
    {
      "rule_id": "tenant_demo.refund.amount_threshold",
      "effect": "approval-required",
      "summary": "Large refunds require approval.",
      "reason_code": "APPROVAL_REQUIRED",
      "capabilities": ["refund.execute"],
      "parameter_constraints": {
        "max_without_approval_minor": 2000
      },
      "approver_types": ["finance-operator"]
    }
  ]
}
```

## Security Considerations

- A policy bundle is portable input, not proof that the issuer was correct.
- Consumers SHOULD validate issuer trust, freshness, tenant scope, and capability scope before relying on a bundle.
- Bundles SHOULD fail closed when required scope, rule identity, or timing constraints are missing.
- The open kernel does not claim that a bundle was authored or approved correctly by an external control plane.

## Boundary

This repository publishes the bundle structure so broader ecosystem components can interoperate around policy inputs.

It does not publish:

- hosted policy bundle distribution
- approval workflow orchestration
- multi-tenant policy storage
- control-plane enforcement services
