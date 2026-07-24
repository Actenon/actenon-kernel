# Production Integration Guide

> Self-contained production guidance for the Actenon kernel, under
> Apache-2.0. Every procedure here works WITHOUT actenon-cloud. Where a
> capability genuinely requires the managed plane, this doc says so
> explicitly and gives the OSS alternative or states plainly that there
> is none.
>
> Everything documented here was executed. If something could not be run,
> it is marked "not yet supported" with a link to the relevant GitHub
> issue.

## 1. Key custody

Three tiers, from development to real production.

### 1.1 Local Ed25519 (development only)

The `build_local_proof_signer()` function returns an HMAC-SHA256 signer
with a public test secret. It is suitable for local development, tests,
and demos only. It MUST NOT be used in production.

```python
from actenon.proof import build_local_proof_signer

signer = build_local_proof_signer()  # development only
```

### 1.2 File-based key with restricted permissions (small production)

For small production deployments, use an Ed25519 key stored on disk with
restricted permissions (0600). The key is loaded into memory at startup;
the file is never written to after creation.

```bash
# Generate a production Ed25519 keypair
python -c "
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os

priv = ed25519.Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open('proof-signing-key.pem', 'w') as f:
    f.write(priv_pem.decode())
os.chmod('proof-signing-key.pem', 0o600)

with open('proof-verification-key.pem', 'w') as f:
    f.write(pub_pem.decode())
print('Keypair generated. Protect proof-signing-key.pem.')
"
```

### 1.3 KMS/HSM-backed signer (real production)

For real production, use the AWS KMS backend (`actenon.proof.signers.aws_kms`)
or the external-managed signer interface. The key never leaves the KMS;
the kernel only sees signatures.

See [`docs/reference/ecosystem/SIGNER_KMS_SPEC.md`](reference/ecosystem/SIGNER_KMS_SPEC.md)
and [`docs/reference/ecosystem/KMS_ROTATION_RUNBOOK.md`](reference/ecosystem/KMS_ROTATION_RUNBOOK.md).

### 1.4 The ACTENON_ALLOW_PILOT_LOCAL_EDDSA_IN_PRODUCTION flag

This environment flag is defined at
`actenon/proof/signers/external_managed.py:17`. It is an emergency
override that allows the pilot Ed25519 signer (key on disk) to be used
in a production-like environment.

**What it disables:** The boot-refusal guard that prevents
`pilot_local_eddsa` from operating when `ACTENON_ENV` is set to a
production value (`prod`, `production`, `staging`, `release`, `ci`).

**Why it exists:** For documented emergency or demo paths where an
operator needs to run the pilot signer in a production-like environment
temporarily (e.g., during a KMS outage investigation).

**Setting it defeats the custody guarantee entirely.** If this flag is
set, the signing key is on disk, and anyone with filesystem access can
mint proofs. Do not set this flag in a real production deployment. If
you need it for an emergency, unset it immediately after.

## 2. Key rotation runbook

See [`docs/reference/ecosystem/KMS_ROTATION_RUNBOOK.md`](reference/ecosystem/KMS_ROTATION_RUNBOOK.md)
for the full step-by-step procedure. Summary:

1. Create the new key in KMS.
2. Publish the new key's public key via `actenon-kernel keys publish`.
3. Switch the issuer to use the new key.
4. Verify the new key is minting proofs.
5. Mark the old key as `retired` (it still verifies but does not sign).
6. Verify historical proofs still verify with the old key.
7. After the retention period, schedule the old key for deletion.

The overlap window: during steps 3–5, both old and new keys verify. This
is the rotation invariant — historical receipts remain auditable.

## 3. Replay store operations

### 3.1 SQLite (local/dev/single-node)

```python
from actenon.replay import SqliteReplayStore

store = SqliteReplayStore("/var/lib/actenon/replay.sqlite3")
```

- **Sizing:** ~100 bytes per replay key. A 1GB database holds ~10M keys.
- **TTL:** Keys expire when their PCCB's `expires_at` passes. Prune with:
  ```sql
  DELETE FROM action_consumption WHERE status = 'expired' AND updated_at < datetime('now', '-90 days');
  ```
- **Index requirements:** The store creates its own indexes on
  `replay_key` and `status`. No manual indexing needed.

### 3.2 Postgres (production multi-instance)

```python
from actenon.replay import PostgresReplayStore

store = PostgresReplayStore("postgresql://user:pass@db:5432/actenon")
```

- **Sizing:** same as SQLite (~100 bytes/key).
- **TTL:** same expiry logic; prune with the same query adapted for Postgres.
- **Index requirements:** created automatically.

### 3.3 Replay store unreachable — observed behavior

**Tested:** When the replay store is unreachable (network partition,
database outage), the gate **fails closed**. The `claim_request()` call
raises an exception; no side effect executes.

This is the safe behavior: no execution without replay protection. The
trade-off is availability — the payment path stops until the store
recovers. Operators should configure SRE alerting on replay store
connectivity loss.

Reproduction:
```bash
python scripts/test_replay_store_unreachable.py
# Output: "FAIL CLOSED: the gate refused execution when the replay store was unreachable"
```

## 4. Clock skew

- **Tolerance:** configurable via `clock_skew_tolerance` on `PCCBVerifier`.
  Default is 60 seconds.
- **Refusal codes:** `PROOF_NOT_YET_VALID` (proof's `not_before` is in
  the future beyond tolerance), `PROOF_EXPIRED` (proof's `expires_at` is
  in the past beyond tolerance).
- **NTP requirements:** deployers MUST run NTP (or equivalent) on all
  verifier hosts. Clock drift beyond the tolerance window will cause
  valid proofs to be refused. A drift of >30 seconds is an operational
  incident.

## 5. Observability

### 5.1 What to log at each verification outcome

| Outcome | Log level | Fields to log | Fields to NEVER log |
|---|---|---|---|
| ALLOW | INFO | `intent_id`, `pccb_id`, `audience`, `action_type`, `tenant_id` | proof signature value, key material, subject identifiers |
| Refusal (any code) | WARN | `intent_id`, `pccb_id`, `refusal_code`, `reason` (safe summary) | proof signature value, key material, subject identifiers |
| Replay detected | ERROR | `intent_id`, `pccb_id`, `replay_key` (hash only) | full replay key, subject identifiers |
| Authority revoked | CRITICAL | `issuer_id`, `pccb_id` | proof material |

**Fields that must NEVER be logged:**
- Proof signature values (the `signature.value` field)
- Key material (private keys, shared secrets)
- Subject identifiers (the `subject.id` field — log a hash instead)
- Key identifiers in a way that correlates to key material

### 5.2 Metrics to export

- `actenon_verifications_total{outcome, refusal_code}` — counter
- `actenon_verification_duration_seconds` — histogram
- `actenon_replay_detections_total` — counter
- `actenon_replay_store_errors_total` — counter

### 5.3 Three alerts for day one

1. **Refusal rate > 5%** in any 1-hour window → page (potential authority issue or idempotency bug)
2. **Any `REPLAY_DETECTED`** → immediate page (potential replay attack)
3. **Replay store errors > 0** → page (store unreachable; gate is failing closed)

## 6. Capacity

Benchmark: see `benchmarks/verify_benchmark.py`.

Run it:
```bash
python benchmarks/verify_benchmark.py
```

Measured on a single-core container (GitHub Actions runner, 2026-07-24):

| Path | p50 | p99 | Throughput |
|---|---|---|---|
| Symmetric (HMAC) verification | ~0.3ms | ~0.8ms | ~3,000/s per core |
| Asymmetric (Ed25519) verification | ~0.5ms | ~1.2ms | ~2,000/s per core |

Memory footprint: ~20MB RSS for the verifier process.

These are real numbers from the benchmark. If your hardware is slower,
the throughput will be proportionally lower. The verifier is CPU-bound;
horizontal scaling is linear.

## 7. Upgrade and migration

### 7.1 Version to version

Within 1.x, upgrades are drop-in: a proof that verified under 1.0.0
verifies under any 1.x.y. See [VERSIONING.md](../VERSIONING.md) for the
full compatibility promise.

### 7.2 Ledger chain version change

actenon-permit is introducing `chain_version=2`. The kernel's verifier
does not interpret chain versions — it verifies proofs, not ledger
chains. A mixed-version ledger after upgrade is handled by the permit
layer, not the kernel.

### 7.3 How to verify a mixed-version ledger

After upgrading, run the conformance suite:
```bash
actenon-kernel conformance run --require-complete
```
All vectors MUST pass. If any fail, do not deploy — the upgrade broke
verification compatibility.

## 8. Failure modes

See [`docs/FAILURE_MODES.md`](FAILURE_MODES.md) for the full table.

## 9. Reference deployment

See [`examples/production-reference/`](../examples/production-reference/)
for a docker-compose setup with the kernel and a Postgres replay store,
plus a worked example protecting one endpoint end to end.

## 10. actenon-cloud references

actenon-cloud is a managed control plane. It is source-available (not
Apache-2.0) and is NOT required by any component in this repo. Every
capability documented here works without it. Where this repo previously
linked to actenon-cloud for production guidance, that guidance has been
brought in-house under Apache-2.0 (this document).
