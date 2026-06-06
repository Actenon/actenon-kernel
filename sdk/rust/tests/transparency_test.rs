use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    verify_checkpoint_signature, verify_consistency, verify_countersignature,
    verify_countersignature_inclusion, verify_inclusion, verify_monitor_update,
    TransparencyVerificationError,
};
use serde_json::{json, Value};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/transparency_log_v1")
}

fn load_fixture(name: &str) -> Value {
    let raw = fs::read(fixtures_dir().join(name)).expect("failed to read transparency fixture");
    serde_json::from_slice(&raw).expect("failed to parse transparency fixture")
}

fn assert_error_code(error: TransparencyVerificationError, expected: &str) {
    assert_eq!(error.code(), expected);
}

#[test]
fn transparency_proofs_and_historical_kids_verify_offline() {
    let keys = load_fixture("trusted_keys.json");
    let old_checkpoint = load_fixture("checkpoint_old.json");
    let new_checkpoint = load_fixture("checkpoint_new.json");

    let old_verified =
        verify_checkpoint_signature(&old_checkpoint, &keys).expect("valid old checkpoint");
    let new_verified =
        verify_checkpoint_signature(&new_checkpoint, &keys).expect("valid new checkpoint");
    let inclusion = verify_inclusion(
        &load_fixture("leaf_digest.json"),
        &load_fixture("inclusion_proof.json"),
        &new_checkpoint,
    )
    .expect("valid inclusion");
    let consistency = verify_consistency(
        &old_checkpoint,
        &new_checkpoint,
        &load_fixture("consistency_proof.json"),
    )
    .expect("valid consistency");

    assert_eq!(old_verified.key_id, "fixture-log-2025");
    assert_eq!(new_verified.key_id, "fixture-log-2026");
    assert_eq!(inclusion.leaf_index, 2);
    assert_eq!(consistency.new_tree_size, 4);
}

#[test]
fn monitor_rejects_signed_fork_and_rewind() {
    let keys = load_fixture("trusted_keys.json");
    let old_checkpoint = load_fixture("checkpoint_old.json");
    let new_checkpoint = load_fixture("checkpoint_new.json");
    let proof = load_fixture("consistency_proof.json");

    verify_monitor_update(&old_checkpoint, &new_checkpoint, &proof, &keys)
        .expect("valid monitor update");
    let same_size_proof = json!({
        "contract": {
            "name": "transparency_consistency_proof",
            "version": "v1",
        },
        "log_id": "actenon-transparency-fixture",
        "hash_algorithm": "sha-256",
        "old_tree_size": 4,
        "new_tree_size": 4,
        "consistency_path": [],
    });
    let fork_error = verify_monitor_update(
        &new_checkpoint,
        &load_fixture("mutations/checkpoint_new_forked.json"),
        &same_size_proof,
        &keys,
    )
    .expect_err("signed fork must fail");
    assert_error_code(fork_error, "EQUIVOCATION_DETECTED");

    let rewind_error =
        verify_consistency(&new_checkpoint, &old_checkpoint, &proof).expect_err("rewind must fail");
    assert_error_code(rewind_error, "REWIND_DETECTED");
}

#[test]
fn checkpoint_rejects_unknown_kid() {
    let error = verify_checkpoint_signature(
        &load_fixture("mutations/checkpoint_unknown_kid.json"),
        &load_fixture("trusted_keys.json"),
    )
    .expect_err("unknown kid must fail");

    assert_error_code(error, "UNKNOWN_KEY_ID");
}

#[test]
fn signed_but_unlogged_countersignature_is_rejected() {
    let orphan = load_fixture("mutations/countersignature_orphan.json");
    let keys = load_fixture("trusted_keys.json");

    verify_countersignature(&orphan["receipt_digest"], &orphan, &keys)
        .expect("orphan fixture has a valid counter-signature");
    let error = verify_countersignature_inclusion(
        &orphan,
        &load_fixture("inclusion_proof.json"),
        &load_fixture("checkpoint_new.json"),
        &keys,
    )
    .expect_err("unlogged digest must fail");

    assert_error_code(error, "ORPHAN_COUNTERSIGNATURE");
}
