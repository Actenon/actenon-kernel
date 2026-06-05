# Rust Verifier SDK

Minimal protected-endpoint verifier SDK for Rust, aligned to the Python kernel's public `action_intent` and `pccb` contracts.

This crate is intentionally narrow. It focuses on verifier-side proof checking at the protected execution edge. It does not attempt to port replay, escrow, receipts, refusals, policy engines, or any hosted control-plane behavior.

Choosing between Python, TypeScript, Go, and Rust paths? Start with [`../../SDK_SELECTION_GUIDE.md`](../../SDK_SELECTION_GUIDE.md).

## Current Scope

- `action_intent` v1 and `pccb` v1 Rust data structures
- protected-endpoint proof verification
- exact audience, tenant, subject, action, target, action-hash, not-before, and expiry checks
- optional verifier-side clock skew tolerance, defaulting to zero
- deterministic local-proof verification using the OSS local `HS256` verifier
- custom signature verification via the exported `SignatureVerifier` trait
- integration tests that intentionally reuse the portable local-proof fixtures already used by the Go SDK so parity stays visible

## Out Of Scope

- replay enforcement
- escrow enforcement
- receipt and refusal generation
- provider adapters
- approval workflows
- hosted or paid control-plane features

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
