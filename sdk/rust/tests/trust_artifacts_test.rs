use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    verify_approval_artifact_for_action, verify_issuer_status, ActionHashSpec,
    TrustArtifactVerificationError,
};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/trust_artifacts_v1")
}

fn load_fixture(name: &str) -> Value {
    let raw = fs::read(fixtures_dir().join(name)).expect("failed to read trust artifact fixture");
    serde_json::from_slice(&raw).expect("failed to parse trust artifact fixture")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-06-06T12:05:00Z", &Rfc3339).expect("valid timestamp")
}

fn assert_error_code(error: TrustArtifactVerificationError, expected: &str) {
    assert_eq!(error.code(), expected);
}

#[test]
fn issuer_status_is_fail_closed_and_approval_verifies_offline() {
    let issuer = load_fixture("issuer.json");
    let status_keys = load_fixture("issuer_status_trusted_keys.json");
    let approval_keys = load_fixture("approval_trusted_keys.json");
    let approval = load_fixture("approval.json");
    let action_hash: ActionHashSpec =
        serde_json::from_value(approval["action_hash"].clone()).expect("valid action hash");

    let status = verify_issuer_status(
        &issuer,
        Some(&load_fixture("issuer_status_good.json")),
        Some(&status_keys),
        now(),
    )
    .expect("valid issuer status")
    .expect("required status returns evidence");
    assert_eq!(status.status, "good_standing");

    let verified =
        verify_approval_artifact_for_action(&approval, &approval_keys, Some(&action_hash))
            .expect("valid approval");
    assert_eq!(verified.approval_type, "finance_approver");

    let revoked = verify_issuer_status(
        &issuer,
        Some(&load_fixture("issuer_status_revoked.json")),
        Some(&status_keys),
        now(),
    )
    .expect_err("revoked issuer must fail");
    assert_error_code(revoked, "ISSUER_REVOKED");

    let missing = verify_issuer_status(&issuer, None, None, now())
        .expect_err("missing status must fail closed");
    assert_error_code(missing, "ISSUER_STATUS_REQUIRED");

    let stale = verify_issuer_status(
        &issuer,
        Some(&load_fixture("issuer_status_stale.json")),
        Some(&status_keys),
        now(),
    )
    .expect_err("stale status must fail");
    assert_error_code(stale, "ISSUER_STATUS_STALE");

    let changed = verify_approval_artifact_for_action(
        &load_fixture("mutations/approval_action_changed.json"),
        &approval_keys,
        Some(&action_hash),
    )
    .expect_err("changed action must fail");
    assert_error_code(changed, "APPROVAL_ACTION_MISMATCH");

    let forged = verify_approval_artifact_for_action(
        &load_fixture("mutations/approval_signature_changed.json"),
        &approval_keys,
        Some(&action_hash),
    )
    .expect_err("forged approval must fail");
    assert_error_code(forged, "SIGNATURE_INVALID");
}
