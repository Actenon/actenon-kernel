from datetime import datetime, timedelta, timezone
from actenon import ActenonGate
now = datetime.now(timezone.utc)
gate = ActenonGate.local_dev(audience="service:quickstart", clock=lambda: now)
action = {"contract": {"name": "action_intent", "version": "v1"}, "intent_id": "intent_quickstart_001", "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=5)).isoformat(), "tenant": {"tenant_id": "tenant_local"}, "requester": {"type": "agent", "id": "quickstart-agent"}, "action": {"name": "database.delete_table", "capability": "database.delete", "parameters": {"table": "synthetic_customers"}}, "target": {"resource_type": "database_table", "resource_id": "synthetic_customers"}}
proof = gate.mint_proof(action)
effects = []
valid = gate.protect(action, proof, lambda: effects.append("executed"))
mismatch = gate.protect({**action, "intent_id": "intent_quickstart_other"}, proof, lambda: effects.append("mismatch"))
replay = gate.protect(action, proof, lambda: effects.append("replay"))
print(f"""ACTENON QUICKSTART
valid: {valid.outcome.upper()}
mismatch: {mismatch.outcome.upper()} ({mismatch.reason_code})
replay: {replay.outcome.upper()} ({replay.reason_code})
side_effects: {len(effects)}
No valid proof, no execution.""")
