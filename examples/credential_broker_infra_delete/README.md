# Credential Broker Infrastructure Delete

This local example shows the strong Actenon deployment pattern:

```text
agent -> ActionIntent/PCCB -> protected endpoint -> brokered credential -> side effect
```

The agent has no standing production database credential. The protected
endpoint owns the execution boundary, verifies the PCCB, enforces endpoint
policy, consumes escrow when execution is allowed, brokers a short-lived
credential reference, and emits a Receipt or Refusal.

Run it:

```bash
python -m examples.credential_broker_infra_delete.demo
```

The demo has three paths:

- direct agent production delete: blocked because the agent has no credential
- protected production delete: refused before credential brokering
- protected sandbox delete: executed with a brokered credential reference

The Receipt records the brokered `secret_reference`. It never records raw
provider secrets.
