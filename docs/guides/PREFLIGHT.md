# Actenon Preflight

Actenon Preflight is the simplest local adoption surface:

```text
before a consequential action executes, ask Actenon
```

Preflight evaluates an Action Intent and returns a structured local decision:

- `allow`
- `deny`
- `approval_required`
- `needs_evidence`

It does not require Actenon Cloud. It does not require a hosted trust network.
It is a local OSS policy check that helps teams put a proof-bound execution
gateway in front of consequential actions.

## CLI

Run a preflight check against an Action Intent:

```bash
actenon preflight check --intent intent.json
```

Emit JSON:

```bash
actenon preflight check --intent intent.json --json
```

Pass local evidence context:

```bash
actenon preflight check \
  --intent intent.json \
  --evidence-json '{"change_ticket":"CHG-123","backup_verified":true}' \
  --json
```

Explain a saved decision:

```bash
actenon preflight explain --decision decision.json
```

Run the built-in destructive infrastructure simulation:

```bash
actenon preflight simulate --wedge infra_delete --json
```

## Local Endpoint

When the local runtime is running, Preflight is available at:

```text
POST /v1/preflight
```

Example:

```bash
curl -s http://127.0.0.1:8787/v1/preflight \
  -H 'Content-Type: application/json' \
  -d @request.json
```

The request may be a raw Action Intent JSON object or a wrapper:

```json
{
  "action_intent": {
    "contract": {"name": "action_intent", "version": "v1"},
    "intent_id": "intent_123",
    "issued_at": "2026-01-01T12:00:00Z",
    "expires_at": "2026-01-01T12:10:00Z",
    "tenant": {"tenant_id": "tenant_alpha"},
    "requester": {"type": "agent", "id": "infra-agent"},
    "action": {
      "name": "database.delete",
      "capability": "database.delete",
      "parameters": {"environment": "production"}
    },
    "target": {
      "resource_type": "database",
      "resource_id": "prod-db-primary",
      "selectors": {"environment": "production"}
    }
  },
  "evidence_context": {
    "change_ticket": "CHG-123",
    "backup_verified": true
  }
}
```

## Default Policy Pack

The first local pack covers destructive infrastructure and data actions:

- `database.delete`
- `database.schema.apply`
- `infrastructure.delete`
- `backup.delete`
- `volume.delete`
- `migration.apply`
- `deployment.execute`
- `iam.permission.grant`
- `data.export`
- `payment.release`

Default rules:

- production destructive action without approval returns `approval_required` or
  `deny`
- missing backup evidence returns `needs_evidence`
- missing change ticket returns `needs_evidence`
- broad data export returns `approval_required`
- admin permission grant returns `approval_required`
- sandbox low-risk action returns `allow`

## Example Decision

```json
{
  "contract": {"name": "preflight_decision", "version": "v1"},
  "decision_id": "pfl_...",
  "outcome": "approval_required",
  "reason_code": "PREFLIGHT_PRODUCTION_DESTRUCTIVE_APPROVAL_REQUIRED",
  "summary": "Production destructive action requires explicit approval before execution.",
  "required_evidence": [],
  "required_approvals": ["infrastructure_owner", "security_admin"],
  "risk_level": "critical",
  "matched_rules": ["destructive_data.production_destructive_approval_required"],
  "metadata": {}
}
```

## How This Maps To Protected Execution

Preflight is an early local ask:

```text
agent -> ActionIntent -> Actenon Preflight -> decision
```

Protected execution is the enforcement boundary:

```text
agent -> ActionIntent/PCCB -> protected endpoint -> brokered credential -> side effect
```

Preflight helps decide whether proof should be minted or what evidence/approval
is missing. It does not replace protected endpoint verification. The endpoint
still needs to verify proof, enforce replay where needed, consume escrow where
configured, and emit Receipt or Refusal artifacts.

## What Preflight Does Not Prove

Preflight does not prove:

- the business decision was inherently correct
- downstream provider finality occurred
- an adapter behaved honestly after execution
- replay protection is active at the protected endpoint
- side-door execution is blocked if agents still hold standing credentials
- hosted trust-network anchoring or Actenon Cloud operation exists

It is a local OSS adoption surface, not a paid-service dependency.
