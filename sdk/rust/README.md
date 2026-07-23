# Rust Verifier SDK

Minimal protected-endpoint verifier SDK for Rust, aligned to the Python kernel's public `action_intent` and `pccb` contracts.

This crate is intentionally narrow. It focuses on verifier-side proof checking at the protected execution edge and offline verification of Receipt counter-signatures. It does not issue counter-signatures or contain private-key custody or service code.

Minimum supported Rust version: 1.88.

Choosing between Python, TypeScript, Go, and Rust paths? Start with [`../../SDK_SELECTION_GUIDE.md`](../../SDK_SELECTION_GUIDE.md).

## Current Scope

- `action_intent` v1 and `pccb` v1 Rust data structures
- protected-endpoint proof verification
- exact audience, tenant, subject, action, target, action-hash, not-before, and expiry checks
- optional verifier-side clock skew tolerance, defaulting to zero
- deterministic local-proof verification using the OSS local `HS256` verifier
- custom signature verification via the exported `SignatureVerifier` trait
- offline Receipt counter-signature verification by historical or active `kid`
- offline, fail-closed issuer-status verification
- signed exact-action approval verification
- integration tests that intentionally reuse the portable local-proof fixtures already used by the Go SDK so parity stays visible

## Out Of Scope

- replay enforcement
- escrow enforcement
- receipt and refusal generation
- provider adapters
- approval workflows
- hosted or paid control-plane features
- counter-signature issuance and private-key custody

## Install

From this repository:

```bash
cd sdk/rust
cargo test
```

To consume it locally from another Rust service:

```toml
[dependencies]
actenon-verifier-sdk = { path = "/absolute/path/to/repo/sdk/rust" }
```

Then import:

```rust
use actenon_verifier_sdk::{build_local_proof_verifier, Verifier};
```

## Verify A Proof

```rust
use actenon_verifier_sdk::{
    build_local_proof_verifier,
    parse_action_intent_json,
    parse_pccb_json,
    AudienceRef,
    VerificationContextInput,
    Verifier,
};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

let verifier = Verifier::new(build_local_proof_verifier());

let intent = parse_action_intent_json(intent_payload_bytes)?;
let pccb = parse_pccb_json(pccb_payload_bytes)?;

let mut parameter_constraints = Map::new();
parameter_constraints.insert(
    "exact_message".to_string(),
    Value::String("portable hello world".to_string()),
);

let mut resource_selector = Map::new();
resource_selector.insert(
    "resource_id".to_string(),
    Value::String("hello_resource_demo_001".to_string()),
);

let context = verifier.build_context(VerificationContextInput {
    request_id: "req_rust_001".to_string(),
    audience: AudienceRef {
        r#type: "service".to_string(),
        id: "portable-hello-world-endpoint".to_string(),
        uri: None,
    },
    now: OffsetDateTime::parse("2026-01-01T12:00:00Z", &Rfc3339)?,
    scope_capabilities: vec!["protected_resource.read".to_string()],
    parameter_constraints,
    resource_selectors: vec![resource_selector],
})?;

let verified = verifier.verify(intent, pccb, context)?;
```

Clock skew tolerance is strict by default. If a deployment needs to absorb small NTP drift, configure it explicitly:

```rust
let verifier = Verifier::new(build_local_proof_verifier())
    .with_clock_skew_tolerance(Duration::seconds(10))?;
```

If verification fails, the SDK returns `VerificationError` with stable codes such as:

- `AUDIENCE_MISMATCH`
- `ACTION_MISMATCH`
- `ACTION_HASH_MISMATCH`
- `PROOF_EXPIRED`
- `SIGNATURE_INVALID`

## Verify A Receipt Counter-Signature

```rust
let verified = verify_countersignature(
    &receipt_or_digest,
    &countersignature,
    &pinned_public_keys,
)?;
```

`pinned_public_keys` is a trusted `key_discovery v1` JSON value. Verification
is offline, selects the exact public key by `kid`, and supports retained
historical keys. It performs no key fetch and contains no signing path.

## Verify Transparency Proofs

```rust
let checkpoint = verify_checkpoint_signature(&tree_head, &pinned_public_keys)?;
let inclusion = verify_inclusion(&receipt_digest, &inclusion_proof, &tree_head)?;
let consistency =
    verify_consistency(&old_tree_head, &tree_head, &consistency_proof)?;
```

`verify_monitor_update` combines checkpoint-signature and consistency checks
for an independent monitor. `verify_countersignature_inclusion` rejects a
counter-signature whose exact digest is not included at its declared log leaf.

## Verify Issuer Status And Approval

```rust
let standing = verify_issuer_status(
    &issuer,
    Some(&signed_status),
    Some(&pinned_status_authority_keys),
    OffsetDateTime::now_utc(),
)?;
let approval = verify_approval_artifact_for_action(
    &signed_approval,
    &pinned_approver_keys,
    Some(&expected_action_hash),
)?;
```

Issuer status fails closed by default for missing, stale, expired, revoked, or
unverifiable assertions. `IssuerStatusPolicy::Disabled` is an explicit,
warning-emitting opt-out. Approval verification is public-key-only and can
require the signed approval to match the expected exact-action hash.

## Tests

```bash
cd sdk/rust
cargo test
```

Current coverage includes:

- valid proof
- audience mismatch
- action mutation
- action-hash mismatch
- expired proof
- strict and tolerant clock-boundary behavior
- valid historical counter-signature plus unknown-key, wrong-key, and altered-digest rejection
- transparency inclusion, consistency, key rotation, fork/rewind, and orphan rejection
- fail-closed issuer status and exact-action signed approval verification

Replay validation is intentionally out of scope for this crate. Replay remains a protected-endpoint responsibility outside this verifier-only surface.

## What This Is For

Use this crate when your protected endpoint already lives in:

- a Rust service
- a Rust edge component
- a Rust infrastructure path that only needs verifier-side proof checks

## What This Is Not For

This crate is not:

- a proof minter
- a replay store
- a receipt or refusal pipeline
- a provider runtime service
- a hosted control-plane feature

## Contract Sources

The canonical public specs and schemas remain in the repository root:

- [`../../spec/action-intent/SPEC.md`](../../spec/action-intent/SPEC.md)
- [`../../spec/pccb/SPEC.md`](../../spec/pccb/SPEC.md)
- [`../../schemas/action_intent.v1.json`](../../schemas/action_intent.v1.json)
- [`../../schemas/pccb.v1.json`](../../schemas/pccb.v1.json)
- [`../../spec/countersignature/SPEC.md`](../../spec/countersignature/SPEC.md)
- [`../../schemas/receipt_countersignature.v1.json`](../../schemas/receipt_countersignature.v1.json)
- [`../../spec/transparency-log/SPEC.md`](../../spec/transparency-log/SPEC.md)
- [`../../schemas/transparency_checkpoint.v1.json`](../../schemas/transparency_checkpoint.v1.json)
- [`../../spec/issuer-status/SPEC.md`](../../spec/issuer-status/SPEC.md)
- [`../../schemas/issuer_status.v1.json`](../../schemas/issuer_status.v1.json)
- [`../../spec/approval-artifact/SPEC.md`](../../spec/approval-artifact/SPEC.md)
- [`../../schemas/approval_artifact.v1.json`](../../schemas/approval_artifact.v1.json)
