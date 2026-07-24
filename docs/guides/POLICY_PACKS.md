# Policy Packs

Policy packs are local, inspectable Preflight rule sets for representative
consequential-action domains. They decide whether an exact `ActionIntent` may
proceed to proof issuance or needs evidence, approval, or denial.

They do not replace proof verification at the protected endpoint.

## Choose A Pack Explicitly

`ActenonGate` does not guess an application's policy domain. Pass the selected
pack explicitly:

```python
from actenon-kernel import ActenonGate
from actenon.preflight import build_data_privacy_policy_pack

gate = ActenonGate.local_dev(
    audience="service:protected-export",
    policy_pack=build_data_privacy_policy_pack(
        broad_export_row_threshold=10_000,
        allowed_external_destinations=("s3://reviewed-export-bucket",),
        allowed_residency_pairs=(("gb", "eu"),),
    ),
)
```

For production, use the same `policy_pack=...` selection with an asymmetric
verifier and an authorized proof issuer. See
[ISSUANCE_AND_APPROVAL.md](ISSUANCE_AND_APPROVAL.md).

## Shipped Packs

| Builder | Scope | Governing approval |
|---|---|---|
| `build_destructive_actions_policy_pack()` | Destructive infrastructure and mixed legacy data actions | Production destructive approval |
| `build_data_privacy_policy_pack()` | Export, download, sharing, external sync, and external reports | Broad/sensitive/external export approval |
| `build_access_governance_policy_pack()` | Role grants, memberships, API keys, credentials, and workspace sharing | Privileged/wildcard/standing-access approval |
| `build_payments_policy_pack()` | Payments, transfers, refunds, invoices, payouts, and bank-detail changes | High-notional/new-destination approval |
| `build_clinical_policy_pack_template()` / `build_clinical_policy_pack()` | Illustrative notes, records, medication, and treatment-plan actions | Licensed-clinician review |

The clinical pack is a **template only**. It is not certified clinical
guidance, medical advice, or a substitute for local clinical governance.

## Data Privacy

The privacy pack uses:

- `row_count`
- `sensitivity_classification`
- `destination` and `destination_classification`
- `destination_allowlisted` or `external_egress_approved`
- `source_residency`, `destination_residency`, and `residency_allowed`
- `approval_present` and `approver_types`

A small internal export may allow immediately:

```python
decision = engine.check(
    small_export,
    evidence_context={
        "row_count": 250,
        "sensitivity_classification": "internal",
        "destination_classification": "internal",
        "source_residency": "gb",
        "destination_residency": "gb",
    },
)
```

A broad, sensitive, or external export is governed by
`PREFLIGHT_BROAD_DATA_EXPORT_APPROVAL_REQUIRED`. The privacy pack deliberately
does not apply the generic production change-ticket rule, so that rule cannot
shadow the domain-specific approval.

For a cross-residency external export, a satisfying evidence shape is:

```python
evidence = {
    "approval_present": True,
    "approver_types": ["data_owner", "privacy_reviewer"],
    "destination_allowlisted": True,
    "residency_allowed": True,
}
```

Preflight aggregation returns the broad-export approval together with any
missing egress or residency evidence in one decision. The broad-export approval
remains the top-level governing reason.

## Access Governance

The access pack understands role tiers, admin/wildcard grants, just-in-time
versus standing access, and separation of duties.

Relevant evidence:

- `role` and `role_tier`
- `access_mode`: `jit` or `standing`
- `approval_present`
- `approver_types`: `security_admin` and `resource_owner`
- `approver_ids`
- `requester_is_approver`

An approval whose verified approver identity is the requesting subject is
denied with `PREFLIGHT_SEPARATION_OF_DUTIES_VIOLATION`.

## Payments

Configure the notional threshold in minor currency units:

```python
pack = build_payments_policy_pack(approval_threshold_minor=100_000)
```

High-notional actions, new payees, and changed destinations require
`finance_approver` approval. New or changed destinations also report the exact
`payee_verified` and `destination_verified` evidence requirements.

Threshold comparison assumes the action and configured threshold use the same
minor currency unit. Currency conversion is outside this starter pack and
should be performed by a reviewed upstream policy input.

## Rule Authoring

A rule has this signature:

```python
from actenon.models import ActionIntent
from actenon.preflight import EvidenceContext

def rule(
    intent: ActionIntent,
    evidence: EvidenceContext,
) -> dict[str, object] | None:
    ...
```

Return `None` when the rule does not match. Return one result when it does:

```python
from actenon.preflight import (
    PolicyPack,
    build_evidence_key,
    build_preflight_rule_result,
)

def require_owner_approval(intent, evidence):
    if intent.action.capability != "repository.delete":
        return None
    if evidence.get("approval_present"):
        return None
    return build_preflight_rule_result(
        outcome="approval_required",
        reason_code="REPOSITORY_OWNER_APPROVAL_REQUIRED",
        summary="Repository deletion requires owner approval.",
        risk_level="high",
        matched_rule="repository.owner_approval",
        required_approvals=("repository_owner",),
        evidence_keys=(
            build_evidence_key(
                "approval_present",
                "boolean",
                True,
                "True after approval for this exact repository deletion.",
            ),
        ),
    )

pack = PolicyPack(
    pack_id="repository_v1",
    display_name="Repository controls",
    capabilities=("repository.delete",),
    rules=(require_owner_approval,),
)
```

Every matching rule is evaluated. All blockers appear in
`unmet_requirements`; the highest-risk blocker becomes the backward-compatible
top-level `reason_code`. Avoid generic rules at equal or higher priority when a
domain-specific requirement should govern.

The exact evidence-key contract and aggregation behavior are described in
[PREFLIGHT_EVIDENCE.md](PREFLIGHT_EVIDENCE.md).

## Limits

Starter packs are examples to inspect and adapt. They do not prove that a
policy is legally sufficient, clinically safe, complete for a domain, or
correct for a particular organization. Operators remain responsible for
thresholds, classifications, approval identity, evidence integrity, residency
rules, currency semantics, and protected routing.
