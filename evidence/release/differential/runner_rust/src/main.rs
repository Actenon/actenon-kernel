//! Rust SDK runner. argv: corpus out.jsonl label
//! Depends on the SDK by git revision (no crates.io release exists).
//! Raw bytes go through the SDK's own parse_action_intent_json / parse_pccb_json.
use actenon_verifier_sdk::{
    parse_action_intent_json, parse_pccb_json, AudienceRef, HmacSha256Verifier, SignatureVerifier,
    VerificationContextInput, Verifier,
};
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

fn run<V: SignatureVerifier>(v: V, d: &Path, ctx: &Value) -> Result<(), String> {
    let skew = ctx["clock_skew_ms"].as_i64().unwrap_or(0);
    let verifier = Verifier::new(v)
        .with_clock_skew_tolerance(Duration::milliseconds(skew))
        .map_err(|e| e.code().to_string())?;
    let intent = parse_action_intent_json(&fs::read(d.join("intent.json")).unwrap()).map_err(|e| e.code().to_string())?;
    let pccb = parse_pccb_json(&fs::read(d.join("pccb.json")).unwrap()).map_err(|e| e.code().to_string())?;
    let o = ctx.as_object().ok_or("CTX")?;
    let a = o["audience"].as_object().ok_or("CTX")?;
    let input = VerificationContextInput {
        request_id: o["request_id"].as_str().ok_or("CTX")?.to_string(),
        audience: AudienceRef {
            r#type: a["type"].as_str().ok_or("CTX")?.to_string(),
            id: a["id"].as_str().ok_or("CTX")?.to_string(),
            uri: None,
        },
        now: OffsetDateTime::parse(o["now"].as_str().ok_or("CTX")?, &Rfc3339).map_err(|_| "CTX_NOW")?,
        scope_capabilities: o["scope_capabilities"].as_array().ok_or("CTX")?.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect(),
        parameter_constraints: o["parameter_constraints"].as_object().ok_or("CTX")?.clone(),
        resource_selectors: o["resource_selectors"].as_array().ok_or("CTX")?.iter().map(|x| x.as_object().cloned().unwrap_or_default()).collect(),
    };
    let context = verifier.build_context(input).map_err(|e| e.code().to_string())?;
    verifier.verify(intent, pccb, context).map(|_| ()).map_err(|e| e.code().to_string())
}

#[cfg(feature = "ed25519")]
fn ed(trust: &Value) -> Option<actenon_verifier_sdk::Ed25519Verifier> {
    Some(actenon_verifier_sdk::Ed25519Verifier::new().with_jwk(&trust["ed25519"].to_string()).unwrap())
}
#[cfg(not(feature = "ed25519"))]
fn ed(_: &Value) -> Option<HmacSha256Verifier> {
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (corpus, out_path, label) = (Path::new(&args[1]), &args[2], &args[3]);
    let manifest: Value = serde_json::from_slice(&fs::read(corpus.join("manifest.json")).unwrap()).unwrap();
    let trust: Value = serde_json::from_slice(&fs::read(corpus.join("trust.json")).unwrap()).unwrap();
    let mut out = fs::File::create(out_path).unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let d = corpus.join(id);
        let ctx: Value = serde_json::from_slice(&fs::read(d.join("context.json")).unwrap()).unwrap();
        let hmac = HmacSha256Verifier::new(trust["hmac"]["secret_utf8"].as_str().unwrap().as_bytes().to_vec(), trust["hmac"]["key_id"].as_str().unwrap());
        let result = if c["alg"] == "EdDSA" {
            match ed(&trust) {
                Some(v) => Some(std::panic::catch_unwind(|| run(v, &d, &ctx))),
                None => None,
            }
        } else {
            Some(std::panic::catch_unwind(|| run(hmac, &d, &ctx)))
        };
        let row = match result {
            None => json!({"id": id, "outcome": "UNSUPPORTED", "code": "NO_EDDSA_VERIFIER"}),
            Some(Ok(Ok(()))) => json!({"id": id, "outcome": "ACCEPT", "code": null}),
            Some(Ok(Err(code))) => json!({"id": id, "outcome": "REFUSE", "code": code}),
            Some(Err(_)) => json!({"id": id, "outcome": "REFUSE", "code": "PANIC"}),
        };
        writeln!(out, "{}", row).unwrap();
    }
    println!("{}: {} cases -> {}", label, cases.len(), out_path);
}
