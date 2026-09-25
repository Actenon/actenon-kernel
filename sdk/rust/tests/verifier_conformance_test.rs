use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    build_local_proof_verifier, parse_action_intent_json, parse_pccb_json, AudienceRef,
    VerificationContextInput, Verifier, LOCAL_PROOF_SECRET,
};
use serde::Deserialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Deserialize)]
struct Mutation {
    document: String,
    path: Vec<String>,
    value: Value,
}

#[derive(Deserialize)]
struct Expected {
    outcome: String,
    #[serde(default)]
    reason_code: String,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct VectorCase {
    id: String,
    clock_skew_tolerance_ms: i64,
    mutation: Option<Mutation>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Base {
    intent: String,
    pccb: String,
    context: Value,
}

#[derive(Deserialize)]
struct Manifest {
    base: Base,
    cases: Vec<VectorCase>,
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../actenon/conformance/vectors/verifier_sdk_v1")
}

fn load_value(name: &str) -> Value {
    serde_json::from_slice(
        &fs::read(vector_root().join(name)).expect("failed to read shared vector"),
    )
    .expect("failed to decode shared vector")
}

fn set_path(document: &mut Value, path: &[String], value: Value) {
    let mut current = document;
    for segment in &path[..path.len() - 1] {
        current = current
            .as_object_mut()
            .and_then(|object| object.get_mut(segment))
            .expect("shared vector path must resolve to an object");
    }
    current
        .as_object_mut()
        .expect("shared vector path parent must be an object")
        .insert(path[path.len() - 1].clone(), value);
}

fn context_from_value(value: &Value) -> VerificationContextInput {
    let object = value.as_object().expect("context must be an object");
    let audience = object["audience"]
        .as_object()
        .expect("audience must be an object");
    let scope_capabilities = object["scope_capabilities"]
        .as_array()
        .expect("scope capabilities must be an array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("capability must be a string")
                .to_string()
        })
        .collect();
    let resource_selectors = object["resource_selectors"]
        .as_array()
        .expect("resource selectors must be an array")
        .iter()
        .map(|item| {
            item.as_object()
                .expect("resource selector must be an object")
                .clone()
        })
        .collect();
    VerificationContextInput {
        request_id: object["request_id"]
            .as_str()
            .expect("request id must be a string")
            .to_string(),
        audience: AudienceRef {
            r#type: audience["type"]
                .as_str()
                .expect("audience type must be a string")
                .to_string(),
            id: audience["id"]
                .as_str()
                .expect("audience id must be a string")
                .to_string(),
            uri: audience
                .get("uri")
                .and_then(Value::as_str)
                .map(str::to_string),
        },
        now: OffsetDateTime::parse(
            object["now"].as_str().expect("now must be a string"),
            &Rfc3339,
        )
        .expect("now must be RFC3339"),
        scope_capabilities,
        parameter_constraints: object["parameter_constraints"]
            .as_object()
            .expect("parameter constraints must be an object")
            .clone(),
        resource_selectors,
    }
}

#[test]
fn shared_verifier_sdk_conformance_vectors() {
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(vector_root().join("cases.json")).expect("failed to read manifest"),
    )
    .expect("failed to decode manifest");
    let base_intent = load_value(&manifest.base.intent);
    let base_pccb = load_value(&manifest.base.pccb);

    for vector in manifest.cases {
        let mut intent_document = base_intent.clone();
        let mut pccb_document = base_pccb.clone();
        let mut context_document = manifest.base.context.clone();
        if let Some(mutation) = vector.mutation {
            let document = match mutation.document.as_str() {
                "intent" => &mut intent_document,
                "pccb" => &mut pccb_document,
                "context" => &mut context_document,
                other => panic!("unsupported shared vector document: {other}"),
            };
            set_path(document, &mutation.path, mutation.value);
        }

        let verifier = Verifier::new(build_local_proof_verifier())
            .with_clock_skew_tolerance(Duration::milliseconds(vector.clock_skew_tolerance_ms))
            .expect("shared vector skew must be valid");
        let intent = parse_action_intent_json(
            &serde_json::to_vec(&intent_document).expect("intent must encode"),
        )
        .expect("intent must parse");
        let pccb = parse_pccb_json(&serde_json::to_vec(&pccb_document).expect("pccb must encode"))
            .expect("pccb must parse");
        let context = verifier
            .build_context(context_from_value(&context_document))
            .expect("context must parse");
        let result = verifier.verify(intent, pccb, context);

        if vector.expected.outcome == "verified" {
            let verified = result
                .unwrap_or_else(|error| panic!("{} expected verification, got {error}", vector.id));
            assert_eq!(verified.pccb.pccb_id, "pccb_portable_hello_world_001");
            continue;
        }

        let error = result.expect_err("shared refusal vector must fail");
        assert_eq!(
            error.code().as_str(),
            vector.expected.reason_code,
            "{} reason code",
            vector.id,
        );
        assert_eq!(
            error.message(),
            vector.expected.message,
            "{} public message",
            vector.id,
        );
    }
}

// The kernel mints every new PCCB with the ACTENON-JCS-STRICT-1 action-hash
// label (actenon-protocol >= 1.1); RFC8785-JCS is the accepted legacy alias.
// The shared vectors only carry the legacy label, so re-label the base proof,
// re-sign it with the public local development key, and require the verdicts
// the Python reference gives. serde_json's default (sorted, compact) output is
// the canonical form for this all-ASCII, float-free vector.
fn verify_relabelled(label: &str) -> Result<String, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let manifest: Manifest = serde_json::from_slice(
        &fs::read(vector_root().join("cases.json")).expect("failed to read manifest"),
    )
    .expect("failed to decode manifest");
    let intent_document = load_value(&manifest.base.intent);
    let mut pccb_document = load_value(&manifest.base.pccb);
    let object = pccb_document
        .as_object_mut()
        .expect("pccb must be an object");
    object["action_hash"]["canonicalization"] = Value::String(label.to_string());
    let mut signature = object.remove("signature").expect("pccb must be signed");
    let unsigned = serde_json::to_vec(&pccb_document).expect("pccb must encode");
    let mut mac = Hmac::<Sha256>::new_from_slice(LOCAL_PROOF_SECRET.as_bytes())
        .expect("hmac accepts any key");
    mac.update(&unsigned);
    signature["value"] = Value::String(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()));
    pccb_document
        .as_object_mut()
        .expect("pccb must be an object")
        .insert("signature".to_string(), signature);

    let verifier = Verifier::new(build_local_proof_verifier());
    let intent = parse_action_intent_json(
        &serde_json::to_vec(&intent_document).expect("intent must encode"),
    )
    .map_err(|error| error.to_string())?;
    let pccb = parse_pccb_json(&serde_json::to_vec(&pccb_document).expect("pccb must encode"))
        .map_err(|error| error.to_string())?;
    let context = verifier
        .build_context(context_from_value(&manifest.base.context))
        .expect("context must parse");
    verifier
        .verify(intent, pccb, context)
        .map(|verified| verified.pccb.action_hash.canonicalization)
        .map_err(|error| error.to_string())
}

#[test]
fn verifier_accepts_both_canonicalization_profile_labels() {
    for label in ["ACTENON-JCS-STRICT-1", "RFC8785-JCS"] {
        assert_eq!(
            verify_relabelled(label).unwrap_or_else(|error| panic!("{label}: {error}")),
            label
        );
    }
}

#[test]
fn verifier_refuses_unknown_canonicalization_profile_labels() {
    for label in ["actenon-jcs-sha256-v1", "JCS"] {
        assert!(verify_relabelled(label).is_err(), "{label} must be refused");
    }
}
