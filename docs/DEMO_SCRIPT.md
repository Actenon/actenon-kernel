# Actenon Demo Script

This document explains what the 60-second Actenon demo proves.

The demo is intentionally small: a fake refund ledger protected by an Actenon proof gate.

The domain is not the point.

The invariant is the point:

> No valid proof, no execution.

---

## Run the demo

```bash
python examples/interactive_execution_demo.py
```

Expected shape:

```text
✅ approved refund: ord-123 £25.00 -> executed
🛑 hallucinated refund: ord-456 £2,500.00 -> refused / INTENT_MISMATCH
🛑 replay approved refund -> refused / DUPLICATE_REPLAY
🛑 refund with no proof -> refused / PCCB_REQUIRED

Final ledger events: [{'order_id': 'ord-123', 'amount_cents': 2500}]

No valid proof, no execution.
```

---

## What the demo proves

### 1. Valid proof executes once

The approved refund has a proof bound to the action name, capability, order ID, exact refund amount, target audience and expiry window.

Because the proof matches the exact action, the protected side effect executes.

### 2. Parameter tampering is refused

The demo then attempts a different refund using the original proof.

The order and amount no longer match the proof-bound action.

Actenon refuses before the side effect.

### 3. Replay is refused

The demo attempts to reuse the valid proof.

Actenon refuses the replay before the side effect.

A valid proof is not a reusable permission slip.

### 4. Missing proof is refused

The demo attempts to execute a consequential action without proof.

Actenon refuses before the side effect.

### 5. The ledger contains only the approved action

The final ledger proves that only the approved proof-bound action executed.

No tampered, replayed or no-proof action reached the side effect.

---

## What the demo does not claim

The demo does not claim to make an LLM truthful, prevent all bad model output, replace IAM/DLP/SIEM/EDR/application security, protect resources reachable through unprotected paths, certify production deployment, or prove production latency/scale.

The demo proves one narrow and important property:

> When the side effect is routed through an Actenon-protected boundary, execution only occurs for the proof-bound action.

---

## Why this matters

AI-agent failures often become dangerous at the execution boundary.

The model may hallucinate, be prompt-injected, misunderstand instructions, retry incorrectly, delegate badly, or operate in a multi-agent swarm.

Actenon does not try to make the model safe.

Actenon makes the boundary deterministic.

> The agent may ask. The protected boundary decides.
