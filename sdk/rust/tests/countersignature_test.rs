use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    verify_countersignature, CounterSignatureVerificationError, ReceiptDigest,
};
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/receipt_countersignature_v1")
}

fn load_fixture(name: &str) -> Value {
    let raw =
        fs::read(fixtures_dir().join(name)).expect("failed to read counter-signature fixture");
    serde_json::from_slice(&raw).expect("failed to parse counter-signature fixture")
}

fn assert_error_code(error: CounterSignatureVerificationError, expected: &str) {
    assert_eq!(error.code(), expected);
}

#[test]
fn countersignature_verifies_historical_key_offline() {
    let verified = verify_countersignature(
        &load_fixture("receipt.json"),
        &load_fixture("countersignature.json"),
        &load_fixture("trusted_keys.json"),
    )
    .expect("valid historical counter-signature");

    assert_eq!(verified.key_id, "actenon-countersignature-fixture-2025-11");
}

#[test]
fn countersignature_accepts_pinned_digest() {
    let artifact = load_fixture("countersignature.json");
    let digest: ReceiptDigest =
        serde_json::from_value(artifact["receipt_digest"].clone()).expect("valid digest");
    let verified = verify_countersignature(
        &serde_json::to_value(digest).expect("serializable digest"),
        &artifact,
        &load_fixture("trusted_keys.json"),
    )
    .expect("valid digest counter-signature");

    assert_eq!(verified.witness.id, "actenon-countersignature-fixture");
}

#[test]
fn countersignature_rejects_unknown_kid() {
    let error = verify_countersignature(
        &load_fixture("receipt.json"),
        &load_fixture("mutations/countersignature_unknown_kid.json"),
        &load_fixture("trusted_keys.json"),
    )
    .expect_err("unknown kid must fail");

    assert_error_code(error, "UNKNOWN_KEY_ID");
}

#[test]
fn countersignature_rejects_wrong_key() {
    let error = verify_countersignature(
        &load_fixture("receipt.json"),
        &load_fixture("countersignature.json"),
        &load_fixture("mutations/trusted_keys_wrong_key.json"),
    )
    .expect_err("wrong key must fail");

    assert_error_code(error, "SIGNATURE_INVALID");
}

#[test]
fn countersignature_rejects_altered_digest() {
    let error = verify_countersignature(
        &load_fixture("receipt.json"),
        &load_fixture("mutations/countersignature_altered_digest.json"),
        &load_fixture("trusted_keys.json"),
    )
    .expect_err("altered digest must fail");

    assert_error_code(error, "RECEIPT_DIGEST_MISMATCH");
}
