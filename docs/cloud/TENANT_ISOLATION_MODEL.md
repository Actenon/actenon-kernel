# Cloud Tenant Isolation Model

Status: current Cloud/control-plane isolation doctrine and test evidence. This
document does not claim SOC2 readiness or completed production Postgres/RLS
validation.

## Core Principle

A trust control plane cannot have cross-tenant data bleed. Tenant isolation is a
trust-critical feature for proof issuance, approvals, evidence, receipts,
refusals, audit trails, and usage records.

## Tenant-Scoped Surfaces

The Cloud/control-plane model treats the following as tenant-scoped:

- tenants
- users/operators through tenant membership and tenant role grants
- tenant-scoped service principals
- policies
- Action Intent records
- approvals
- evidence
- signing key references
- issued proofs
- escrow records
- receipts/refusals and reconciliation records
- audit logs and trace exports
- usage/metering summaries

## Enforcement Layers

The current local harness proves app-layer isolation:

- bearer authentication resolves a principal and tenant permission set
- list/search endpoints require or infer an authorized tenant scope
- direct object endpoints authorize against the object's stored `tenant_id`
- mutations authorize against the target tenant before state changes
- cross-tenant object references fail closed in service validation
- missing tenant context for non-platform callers fails closed

The Cloud tree also contains a PostgreSQL RLS foundation migration
(`20260409_0007_postgres_rls_foundation.py`) and unit coverage for applying RLS
context to PostgreSQL sessions. The current pass did not run a live Postgres
instance, so live RLS behavior remains a production-readiness validation item.

## Tests Added

Cloud integration coverage:

```text
AI Agent Execution Control Layer/tests/integration/test_tenant_isolation.py
```

The test creates two tenants and proves:

- tenant A cannot read tenant B actions
- tenant A cannot read tenant B evidence
- tenant A cannot read tenant B receipts
- tenant A cannot mutate tenant B policies
- tenant A cannot approve tenant B actions
- tenant A cannot query tenant B audit entries or traces
- tenant A cannot query tenant B usage summaries
- forged tenant IDs are rejected
- missing tenant context is rejected
- cross-tenant object references are rejected

## Production-Only Follow-Up

Before production tenant-isolation claims, run the same matrix against
PostgreSQL with RLS enabled and verify:

- no tenant context yields no tenant rows and no writes
- forged `app.current_tenant_scope` cannot be set by application callers
- RLS `USING` and `WITH CHECK` policies cover every tenant-scoped table
- platform-admin bypass is deliberate, audited, and limited
- migrations cannot create tenant-scoped tables without RLS policy coverage
- export/report jobs preserve the same tenant boundary

## Safe Public Claim

Safe:

> The Cloud/control-plane test harness includes two-tenant app-layer isolation
> tests for actions, policies, approvals, evidence, receipts, audit, and usage.

Not safe until live Postgres/RLS evidence exists:

> Production PostgreSQL/RLS tenant isolation has been fully validated.
