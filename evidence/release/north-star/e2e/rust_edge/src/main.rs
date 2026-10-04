//! Protected edge (verifier only): the actenon-verifier-sdk 0.2.0 crate as a consumer installs it,
//! verifying Permit-minted EdDSA proofs through verify_json (raw bytes, strict parse). Same arguments
//! and output as evidence/release/phase2/e2e/ts_edge.mjs:
//!   rust-edge PROOF JWK LABEL [--audience-id ID] [--capabilities a,b] [--mutate-amount N]
//!             [--param-constraints JSON] [--resource-selectors JSON] [--revocation-db PATH]
//! --revocation-db: Permit's SQLite state store, read-only, mirroring
//! actenon_permit.revocation.StoreRevocationChecker (walk the parent chain; revoked/expired/past
//! expires_at => revoked; unknown grant or wrong issuer => error => AUTHORITY_REVOKED).
use actenon_verifier_sdk::{AudienceRef, Ed25519Verifier, VerificationContextInput, Verifier};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

fn revoked_check(db: String) -> impl Fn(&actenon_verifier_sdk::PCCB, &actenon_verifier_sdk::VerificationContext) -> Result<bool, String> {
    move |pccb, _ctx| {
        let authority = pccb.extensions.get("authority").and_then(Value::as_object).ok_or("no authority")?;
        let grant_id = authority.get("grant_id").and_then(Value::as_str).ok_or("no grant_id")?;
        if authority.get("issuer").and_then(Value::as_str) != Some("service:actenon-permit") {
            return Err("not a Permit authority reference".into());
        }
        let conn = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())?;
        let mut seen = HashSet::new();
        let mut current = Some(grant_id.to_string());
        while let Some(id) = current {
            if !seen.insert(id.clone()) || seen.len() > 64 {
                return Err("grant ancestry cyclic or too deep".into());
            }
            let body: String = conn
                .query_row("SELECT body FROM grants WHERE id = ?1", [&id], |r| r.get(0))
                .map_err(|e| format!("grant {id} unknown: {e}"))?;
            let grant: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
            let expires = OffsetDateTime::parse(grant["expires_at"].as_str().unwrap_or(""), &Rfc3339).map_err(|e| e.to_string())?;
            let status = grant["status"].as_str().unwrap_or("");
            if status == "revoked" || status == "expired" || expires <= OffsetDateTime::now_utc() {
                return Ok(false);
            }
            current = grant["parent_grant_id"].as_str().map(str::to_string);
        }
        Ok(true)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (proof_file, jwk_file, label) = (&args[0], &args[1], args[2].clone());
    let mut opts: HashMap<&str, String> = HashMap::from([
        ("--audience-id", "actenon-permit-gateway".to_string()),
        ("--capabilities", "payments.refund".to_string()),
        ("--param-constraints", "{}".to_string()),
        ("--resource-selectors", "[]".to_string()),
    ]);
    for pair in args[3..].chunks(2) {
        if let [k, v] = pair {
            opts.insert(k.as_str(), v.clone());
        }
    }
    let mut doc: Value = serde_json::from_slice(&std::fs::read(proof_file).unwrap()).unwrap();
    if let Some(m) = opts.get("--mutate-amount") {
        doc["intent"]["action"]["parameters"]["amount_minor"] = serde_json::from_str(m).unwrap();
    }
    let intent_raw = serde_json::to_vec(&doc["intent"]).unwrap();
    let pccb_raw = serde_json::to_vec(&doc["pccb"]).unwrap();
    let jwk = std::fs::read_to_string(jwk_file).unwrap();
    let mut verifier = Verifier::new(Ed25519Verifier::new().with_jwk(&jwk).expect("jwk"));
    if let Some(db) = opts.get("--revocation-db") {
        verifier = verifier.with_revocation_checker(revoked_check(db.clone()));
    }
    let input = VerificationContextInput {
        request_id: format!("req-rust-{label}"),
        audience: AudienceRef { r#type: "service".into(), id: opts["--audience-id"].clone(), uri: None },
        now: OffsetDateTime::now_utc(),
        scope_capabilities: opts["--capabilities"].split(',').filter(|c| !c.is_empty()).map(str::to_string).collect(),
        parameter_constraints: serde_json::from_str(&opts["--param-constraints"]).unwrap(),
        resource_selectors: serde_json::from_str(&opts["--resource-selectors"]).unwrap(),
    };
    let out = match verifier.build_context(input).and_then(|ctx| verifier.verify_json(&intent_raw, &pccb_raw, ctx)) {
        Ok(_) => json!({"label": label, "edge": "rust", "outcome": "verified"}),
        Err(e) => json!({"label": label, "edge": "rust", "outcome": "refused", "reason_code": e.code().to_string()}),
    };
    println!("{}", serde_json::to_string(&out).unwrap());
}
