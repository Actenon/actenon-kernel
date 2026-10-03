//! Public-API smoke: a consumer program that compiles against the installed crate and verifies
//! the kernel's portable local proof (intent + PCCB from the INSTALLED kernel wheel's vectors).
use actenon_verifier_sdk::{parse_action_intent_json, parse_pccb_json};
fn main() {
    let root = std::env::var("ACTENON_VECTORS").expect("ACTENON_VECTORS");
    let intent = parse_action_intent_json(&std::fs::read(format!("{root}/action_intent.json")).unwrap()).expect("intent parses");
    let pccb = parse_pccb_json(&std::fs::read(format!("{root}/pccb.json")).unwrap()).expect("pccb parses");
    println!("parsed intent {} and pccb {}", intent.intent_id, pccb.pccb_id);
}
