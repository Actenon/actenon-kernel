# Local Proof Runbook

## Purpose

This runbook explains the zero-credential local proof mode path for the Actenon kernel.

It is also the shortest complete local-runtime runbook for the category:

- start the local trust machine
- verify it is healthy
- run the incident simulator
- protect a consequential endpoint
- export a portable bundle

It runs entirely on local files:

- no external accounts
- no API keys
- no network integrations

## Local HMAC Is Dev-Only

Default local proof mode uses an `HS256` HMAC signer with deterministic public
test material. That is intentional for reproducible demos and local tests, but
it is not production signing custody. Anyone with the public repository can
derive the default local proof secret and forge local-mode proofs.

Production deployments must use an asymmetric verification path, such as
well-known JWK discovery backed by production-grade signing custody. Do not
publish local symmetric HMAC material through key discovery, do not treat it as
public verification material, and do not use it for production protected
endpoints. Production flags are non-bypassable. Run local/demo flows in an
explicitly local or test process, or use asymmetric well-known/KMS/HSM signing
custody.

The shipped local proof runtime now persists both replay state and capability escrow in SQLite, so a real single-node run survives process restart instead of depending on in-memory-only execution authority.

For embedded local deployments, the same durable escrow default is available programmatically through `actenon.escrow.build_default_capability_escrow()`.

## Commands

Start the complete local single-node runtime:

```bash
actenon up
```

That command starts the local issuer/verifier HTTP surface on `http://127.0.0.1:8787` by default, exposes `POST /v1/intents`, serves `GET /healthz`, and starts the read-only trace viewer on `http://127.0.0.1:8421` when available.

The startup banner prints the issuer URL, health URL, key-discovery URLs, key-publication file path, artifact directory, replay DB path, escrow DB path, and one first `curl` so you can prove the runtime is alive immediately.

The local runtime also exposes the well-known key-discovery URLs, but default local `HS256` mode does not publish public verification material. Those routes return an explicit unavailable response unless you place a real `key_discovery v1` document at `artifacts/local_runtime/keys/actenon-keys.json`. Do not place local symmetric HMAC key material there.

If you only want the labs and runtime files without starting the HTTP services:

```bash
actenon up --bootstrap-only
```

Check the local runtime health:

```bash
actenon doctor
```

That command is local-runtime aware. In default mode it stays fast and checks the signer, replay store, escrow store, artifact writability, runtime-server health, key-discovery response, and trace-viewer reachability. Use `actenon doctor --deep` when you also want slower receipt/refusal writer, evidence lookup, portable verifier, and scanner-harness checks. If you only ran `actenon up --bootstrap-only`, doctor should report that the runtime is prepared but not actively serving yet.

Run the built-in local incident simulator:

```bash
actenon simulate --incident replit
```

That simulator is meant to be explanatory, not just demonstrative. Named incident runs are educational simulations inspired by public incidents, not exact forensic reconstructions. Each incident or scenario writes an `INCIDENT_SUMMARY.md` file under `artifacts/local_runtime/simulations/<name>/` that compares:

- the counterfactual outcome without execution-edge verification
- what proof verification catches directly
- what the protected endpoint and replay state add beyond proof
- what the persisted Action Intent plus Receipt or Refusal makes provable afterward

Named incidents also write four top-level explanation artifacts:

- `weak_control_path.json`
- `proof_bound_path.json`
- `proof_only_gap.json`
- `bounded_intent_change.json`

They also write `intent_record.json`, which is the additive bounded-delegation artifact for the simulated action.

Run `actenon simulate --incident all` if you want the full named set: `replit`, `openai-eggs`, and `amazon-kiro`. Run `actenon simulate --scenario all` if you want the lower-level technical cases instead.

If `actenon up` is already serving the local trace viewer, refresh it after a simulation run and open the `Incident Simulator` run to inspect the incident artifacts interactively.

Protect a real consequential endpoint:

```bash
python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime
```

Export the runtime as a portable bundle:

```bash
actenon bundle export --runtime-dir artifacts/local_runtime
```

Verify the exported bundle:

```bash
actenon bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon
```

The `.actenon` bundle is the kernel's portable execution evidence class for local single-node mode. It carries manifest-linked file hashes, canonical artifact digests, and proof-chain metadata where available. In v1 it is tamper-evident relative to the manifest, not a cryptographic attestation of origin.

## Local Issuer API

The foreground runtime started by `actenon up` is also a local issuer.

Current supported capabilities:

- `refund.execute`
- `invoice_payment.execute`

It evaluates local policy, returns the decision outcome, mints a PCCB when the decision is `allow`, issues escrow for that PCCB, and writes canonical artifacts for the request under `artifacts/local_runtime/artifacts/`. `deny` responses include a structured refusal. `approval-required` and `needs-evidence` responses stop before proof minting and return the decision receipt without a PCCB.

Each request directory now also includes `intent_record.json`, which makes the bounded-delegation layer explicit before or alongside proof:

- authorization says who may ask
- Intent Record says what bounded machine action is actually delegated
- proof says which exact action was minted for the protected endpoint
- receipts and refusals say what actually happened

Allow request example:

```bash
curl -s http://127.0.0.1:8787/v1/intents \
  -H 'Content-Type: application/json' \
  -d @- <<'JSON'
{
  "action_intent": {
    "contract": {"name": "action_intent", "version": "v1"},
    "intent_id": "intent_local_runtime_allow",
    "issued_at": "2026-01-01T12:00:00Z",
    "expires_at": "2026-01-01T12:05:00Z",
    "tenant": {"tenant_id": "tenant_demo"},
    "requester": {"type": "service", "id": "demo_actor"},
    "action": {
      "name": "refund.create",
      "capability": "refund.execute",
      "parameters": {"amount_minor": 1500, "currency": "USD"},
      "constraints": {"exact_amount_minor": 1500, "exact_currency": "USD"},
      "scope": {"single_use": true, "target_resource_type": "payment"}
    },
    "target": {"resource_type": "payment", "resource_id": "payment_demo_001"}
  },
  "context": {
    "audience": "service:local-refund-endpoint",
    "now": "2026-01-01T12:00:00Z"
  }
}
JSON
```

Allow response shape:

- `decision.outcome` is `allow`
- `pccb` is present
- `escrow_id` is present
- `receipt` is present
- `refusal` is `null`

Approval-required example using a shipped lab intent:

```bash
python3 - <<'PY' | curl -s http://127.0.0.1:8787/v1/intents -H 'Content-Type: application/json' -d @-
import json
from pathlib import Path

payload = json.loads(
    Path("artifacts/local_runtime/labs/local_proof/scenarios/approval_required/action_intent.json").read_text(encoding="utf-8")
)
print(json.dumps({"action_intent": payload, "context": {"now": payload["issued_at"]}}))
PY
```

Approval-required response shape:

- `decision.outcome` is `approval-required`
- `pccb` is `null`
- `escrow_id` is `null`
- canonical decision `receipt` is present
- `refusal` is `null`

If you replay shipped lab intents directly, supply an in-window `context.now` or use a fresh intent. Those fixtures carry fixed timestamps and will otherwise fail chronology checks once they are outside their validity window.

Run the demo:

```bash
bash ./scripts/run_local_proof.sh
```

Reset local state only:

```bash
bash ./scripts/reset_demo_state.sh
```

Run the quick-start path:

```bash
bash ./scripts/first_run.sh
```

Export the current local runtime as a portable bundle:

```bash
actenon bundle export
```

## Refund Scenarios

### `allow`

- workflow risk level: `normal`
- result: proof minted, escrow issued, replay claimed, protected endpoint executes
- artifacts include PCCB, decision receipt, execution receipt, and endpoint payload

### `deny`

- workflow risk level: `blocked`
- result: tenant workflow denies before proof minting
- artifacts include decision receipt and refusal envelope

### `approval_required`

- workflow risk level: `approval`
- result: workflow requires a finance operator approval before proof minting
- artifacts include decision receipt with approver guidance

### `needs_evidence`

- workflow risk level: `review`
- result: workflow requires evidence before proof minting
- artifacts include decision receipt with follow-up requirements

## Invoice Payment Scenarios

### `invoice_payment.allow`

- result: proof minted, escrow issued, replay claimed, protected invoice payment endpoint executes
- artifacts include PCCB, decision receipt, execution receipt, execution payload, and reconciliation state

### `invoice_payment.duplicate_invoice_payment`

- result: denied before proof minting with duplicate invoice or payment refusal

### `invoice_payment.wrong_entity`

- result: denied before proof minting with wrong entity refusal

### `invoice_payment.bank_mismatch`

- result: denied before proof minting with bank mismatch refusal

### `invoice_payment.approval_missing`

- result: approval-required receipt with approval-chain guidance

### `invoice_payment.evidence_missing`

- result: needs-evidence receipt with required evidence types

### `invoice_payment.batch_hash_mismatch`

- result: denied before proof minting with batch hash mismatch refusal

## Artifact Layout

All output is written under:

- `artifacts/local_proof/`

Important paths:

- `artifacts/local_proof/manifest.json`
- `artifacts/local_proof/SUMMARY.txt`
- `artifacts/local_proof/scenarios/allow/`
- `artifacts/local_proof/scenarios/deny/`
- `artifacts/local_proof/scenarios/approval_required/`
- `artifacts/local_proof/scenarios/needs_evidence/`
- `artifacts/local_proof/outcomes/receipts/`
- `artifacts/local_proof/outcomes/refusals/`
- `artifacts/local_proof/state/replay.sqlite3`
- `artifacts/local_proof/state/escrow.sqlite3`
- `artifacts/local_proof/state/protected_endpoint_state.json`
- `artifacts/local_proof/invoice_payment/manifest.json`
- `artifacts/local_proof/invoice_payment/SUMMARY.txt`
- `artifacts/local_proof/invoice_payment/scenarios/allow/`
- `artifacts/local_proof/invoice_payment/scenarios/duplicate_invoice_payment/`
- `artifacts/local_proof/invoice_payment/scenarios/wrong_entity/`
- `artifacts/local_proof/invoice_payment/scenarios/bank_mismatch/`
- `artifacts/local_proof/invoice_payment/scenarios/approval_missing/`
- `artifacts/local_proof/invoice_payment/scenarios/evidence_missing/`
- `artifacts/local_proof/invoice_payment/scenarios/batch_hash_mismatch/`
- `artifacts/local_proof/invoice_payment/state/replay.sqlite3`
- `artifacts/local_proof/invoice_payment/state/escrow.sqlite3`
- `artifacts/local_proof/invoice_payment/state/protected_endpoint_state.json`

Single-node runtime path equivalents:

- labs root: `artifacts/local_runtime/labs/`
- proof lab replay: `artifacts/local_runtime/labs/local_proof/state/replay.sqlite3`
- proof lab escrow: `artifacts/local_runtime/labs/local_proof/state/escrow.sqlite3`
- proof lab receipts: `artifacts/local_runtime/labs/local_proof/outcomes/receipts/`
- proof lab refusals: `artifacts/local_runtime/labs/local_proof/outcomes/refusals/`
- proof lab evidence-query source: `artifacts/local_runtime/labs/local_proof/`
- invoice payment issuer lab: `artifacts/local_runtime/labs/invoice_payment_local_proof/`
- portable verifier lab: `artifacts/local_runtime/labs/portable_local_proof/`
- live runtime artifacts: `artifacts/local_runtime/artifacts/`
- live runtime requests: `artifacts/local_runtime/artifacts/requests/`
- live runtime replay: `artifacts/local_runtime/state/replay.sqlite3`
- live runtime escrow: `artifacts/local_runtime/state/escrow.sqlite3`
- live runtime receipts: `artifacts/local_runtime/artifacts/outcomes/receipts/`
- live runtime refusals: `artifacts/local_runtime/artifacts/outcomes/refusals/`
- local simulations: `artifacts/local_runtime/simulations/`
- local bundles: `artifacts/local_runtime/bundles/`
- local keys: `artifacts/local_runtime/keys/`
- runtime service manifest: `artifacts/local_runtime/service_manifest.json`

Reset options:

- classic demo path: `bash ./scripts/reset_demo_state.sh`
- full single-node runtime reset: remove `artifacts/local_runtime/` or rerun `actenon up --runtime-dir <fresh-dir>`
- live execution reset while keeping seeded labs: remove `artifacts/local_runtime/artifacts/`, `artifacts/local_runtime/state/`, and `artifacts/local_runtime/service_manifest.json`
- simulation cleanup only: remove `artifacts/local_runtime/simulations/`
- bundle cleanup only: remove `artifacts/local_runtime/bundles/`

## Protected Endpoint Example

The local protected endpoint example lives at:

- `examples/refund_guard_local/protected_endpoint.py`
- `examples/invoice_payment_guard_local/protected_endpoint.py`

They simulate protected refund and invoice payment resources locally by updating JSON state files and returning local execution references.

## Determinism Notes

The local proof demo uses:

- fixed local signing material
- fixed base timestamps
- deterministic ID and nonce generation
- reset-by-default runner behavior

That keeps the first run fast and repeated runs stable.
