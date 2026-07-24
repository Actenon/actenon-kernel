use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    build_local_proof_verifier, parse_action_intent_json, parse_pccb_json, AudienceRef, JsonObject,
    VerificationContextInput, VerificationErrorCode, Verifier,
};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../go/fixtures/portable-local-proof")
}

fn load_fixture(name: &str) -> Vec<u8> {
    fs::read(fixtures_dir().join(name)).expect("failed to read portable local proof fixture")
}

fn build_context_input() -> VerificationContextInput {
    let mut parameter_constraints = JsonObject::new();
    parameter_constraints.insert(
        "exact_message".to_string(),
        Value::String("portable hello world".to_string()),
    );

    let mut resource_selector = JsonObject::new();
    resource_selector.insert(
        "resource_id".to_string(),
        Value::String("hello_resource_demo_001".to_string()),
    );

    VerificationContextInput {
        request_id: "req_rust_conformance_001".to_string(),
        audience: AudienceRef {
            r#type: "service".to_string(),
            id: "portable-hello-world-endpoint".to_string(),
            uri: None,
        },
        now: OffsetDateTime::parse("2026-01-01T12:00:00Z", &Rfc3339).expect("valid time"),
        scope_capabilities: vec!["protected_resource.read".to_string()],
        parameter_constraints,
        resource_selectors: vec![resource_selector],
    }
}

fn build_verifier() -> Verifier<actenon_verifier_sdk::HmacSha256Verifier> {
    Verifier::new(build_local_proof_verifier())
}

fn build_verifier_with_skew(seconds: i64) -> Verifier<actenon_verifier_sdk::HmacSha256Verifier> {
    Verifier::new(build_local_proof_verifier())
        .with_clock_skew_tolerance(Duration::seconds(seconds))
        .expect("valid clock skew tolerance")
}

#[test]
fn verifier_accepts_valid_local_proof() {
    let verifier = build_verifier();
    let intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");
    let context = verifier
        .build_context(build_context_input())
        .expect("valid context");

    let verified = verifier.verify(intent, pccb, context).expect("valid proof");

    assert_eq!(verified.intent.action.name, "hello_world.read");
    assert_eq!(verified.pccb.pccb_id, "pccb_portable_hello_world_001");
}

#[test]
fn verifier_refuses_audience_mismatch() {
    let verifier = build_verifier();
    let intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");
    let mut context_input = build_context_input();
    context_input.audience.id = "wrong-endpoint".to_string();
    let context = verifier
        .build_context(context_input)
        .expect("valid context");

    let error = verifier
        .verify(intent, pccb, context)
        .expect_err("expected audience mismatch");
    assert_eq!(error.code(), VerificationErrorCode::AudienceMismatch);
}

#[test]
fn verifier_refuses_action_mutation() {
    let verifier = build_verifier();
    let mut intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");
    let context = verifier
        .build_context(build_context_input())
        .expect("valid context");

    intent.action.parameters.insert(
        "message".to_string(),
        Value::String("tampered hello world".to_string()),
    );

    let error = verifier
        .verify(intent, pccb, context)
        .expect_err("expected action mismatch");
    assert_eq!(error.code(), VerificationErrorCode::ActionMismatch);
}

#[test]
fn verifier_refuses_action_hash_mismatch() {
    let verifier = build_verifier();
    let intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let mut pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");
    let context = verifier
        .build_context(build_context_input())
        .expect("valid context");

    pccb.action_hash.value = "deadbeef".repeat(8);

    let error = verifier
        .verify(intent, pccb, context)
        .expect_err("expected signature invalid (mutation to signed PCCB payload detected by signature check first)");
    // After the fix that moved signature verification before semantic checks,
    // any mutation to a signed PCCB field (including action_hash.value) must
    // produce SIGNATURE_INVALID, not the semantic mismatch error. This matches
    // the Python reference verifier and the conformance vector expectations.
    assert_eq!(error.code(), VerificationErrorCode::SignatureInvalid);
}

#[test]
fn verifier_refuses_expired_proof() {
    let verifier = build_verifier();
    let intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");
    let mut context_input = build_context_input();
    context_input.now =
        OffsetDateTime::parse("2026-01-01T12:06:00Z", &Rfc3339).expect("valid time");
    let context = verifier
        .build_context(context_input)
        .expect("valid context");

    let error = verifier
        .verify(intent, pccb, context)
        .expect_err("expected proof expiry");
    assert_eq!(error.code(), VerificationErrorCode::ProofExpired);
}

#[test]
fn verifier_keeps_strict_not_before_behavior_by_default() {
    let verifier = build_verifier();
    let intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");
    let mut context_input = build_context_input();
    context_input.now =
        OffsetDateTime::parse("2026-01-01T11:59:59Z", &Rfc3339).expect("valid time");
    let context = verifier
        .build_context(context_input)
        .expect("valid context");

    let error = verifier
        .verify(intent, pccb, context)
        .expect_err("expected proof not yet valid");
    assert_eq!(error.code(), VerificationErrorCode::ProofNotYetValid);
}

#[test]
fn verifier_accepts_proof_within_clock_skew_tolerance() {
    let verifier = build_verifier_with_skew(2);
    let intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");

    let mut early_context_input = build_context_input();
    early_context_input.now =
        OffsetDateTime::parse("2026-01-01T11:59:59Z", &Rfc3339).expect("valid time");
    let early_context = verifier
        .build_context(early_context_input)
        .expect("valid context");
    verifier
        .verify(intent.clone(), pccb.clone(), early_context)
        .expect("early proof within tolerance");

    let mut late_context_input = build_context_input();
    late_context_input.now =
        OffsetDateTime::parse("2026-01-01T12:05:01Z", &Rfc3339).expect("valid time");
    let late_context = verifier
        .build_context(late_context_input)
        .expect("valid context");
    verifier
        .verify(intent, pccb, late_context)
        .expect("late proof within tolerance");
}

#[test]
fn verifier_refuses_proof_beyond_clock_skew_tolerance() {
    let verifier = build_verifier_with_skew(2);
    let intent =
        parse_action_intent_json(&load_fixture("action_intent.json")).expect("valid intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("valid pccb");

    let mut early_context_input = build_context_input();
    early_context_input.now =
        OffsetDateTime::parse("2026-01-01T11:59:57Z", &Rfc3339).expect("valid time");
    let early_context = verifier
        .build_context(early_context_input)
        .expect("valid context");
    let early_error = verifier
        .verify(intent.clone(), pccb.clone(), early_context)
        .expect_err("expected proof not yet valid");
    assert_eq!(early_error.code(), VerificationErrorCode::ProofNotYetValid);

    let mut late_context_input = build_context_input();
    late_context_input.now =
        OffsetDateTime::parse("2026-01-01T12:05:03Z", &Rfc3339).expect("valid time");
    let late_context = verifier
        .build_context(late_context_input)
        .expect("valid context");
    let late_error = verifier
        .verify(intent, pccb, late_context)
        .expect_err("expected proof expired");
    assert_eq!(late_error.code(), VerificationErrorCode::ProofExpired);
}
