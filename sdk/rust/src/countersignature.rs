use std::error::Error;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::canonical::{canonicalize_bytes, sha256_hex};
use crate::types::PartyRef;

pub const COUNTERSIGNATURE_CONTEXT: &str = "actenon.receipt-countersignature.v1";
pub const COUNTERSIGNATURE_KEY_USE: &str = "receipt_countersignature";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterSignatureVerificationError {
    code: &'static str,
    message: String,
}

impl CounterSignatureVerificationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CounterSignatureVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for CounterSignatureVerificationError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptDigest {
    pub algorithm: String,
    pub canonicalization: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedCounterSignature {
    pub receipt_digest: ReceiptDigest,
    pub witness: PartyRef,
    pub signed_at: OffsetDateTime,
    pub key_id: String,
    pub anchor_reference: Option<Map<String, Value>>,
}

fn error(code: &'static str, message: impl Into<String>) -> CounterSignatureVerificationError {
    CounterSignatureVerificationError::new(code, message)
}

fn object<'a>(
    value: &'a Value,
    field_name: &str,
    code: &'static str,
) -> Result<&'a Map<String, Value>, CounterSignatureVerificationError> {
    value
        .as_object()
        .ok_or_else(|| error(code, format!("{field_name} must be a JSON object")))
}

fn string<'a>(
    value: Option<&'a Value>,
    field_name: &str,
    code: &'static str,
) -> Result<&'a str, CounterSignatureVerificationError> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| error(code, format!("{field_name} must be a non-empty string")))
}

fn parse_digest(
    value: &Value,
    field_name: &str,
) -> Result<ReceiptDigest, CounterSignatureVerificationError> {
    let data = object(value, field_name, "INVALID_RECEIPT_DIGEST")?;
    let digest = ReceiptDigest {
        algorithm: string(
            data.get("algorithm"),
            &format!("{field_name}.algorithm"),
            "INVALID_RECEIPT_DIGEST",
        )?
        .to_string(),
        canonicalization: string(
            data.get("canonicalization"),
            &format!("{field_name}.canonicalization"),
            "INVALID_RECEIPT_DIGEST",
        )?
        .to_string(),
        value: string(
            data.get("value"),
            &format!("{field_name}.value"),
            "INVALID_RECEIPT_DIGEST",
        )?
        .to_string(),
    };
    if digest.algorithm != "sha-256"
        || digest.canonicalization != "RFC8785-JCS"
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            "INVALID_RECEIPT_DIGEST",
            "receipt digest must declare sha-256, RFC8785-JCS, and a lowercase 64-character hex value",
        ));
    }
    Ok(digest)
}

fn resolve_receipt_digest(
    receipt_or_digest: &Value,
) -> Result<ReceiptDigest, CounterSignatureVerificationError> {
    let data = object(
        receipt_or_digest,
        "receipt_or_digest",
        "INVALID_RECEIPT_DIGEST",
    )?;
    if data.contains_key("algorithm")
        && data.contains_key("canonicalization")
        && data.contains_key("value")
    {
        return parse_digest(receipt_or_digest, "receipt_or_digest");
    }
    let contract = data
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            error(
                "INVALID_RECEIPT_DIGEST",
                "receipt_or_digest must contain a Receipt v1 contract",
            )
        })?;
    if contract.get("name").and_then(Value::as_str) != Some("receipt")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
    {
        return Err(error(
            "INVALID_RECEIPT_DIGEST",
            "receipt_or_digest must be a Receipt v1 object or digest",
        ));
    }
    let value = sha256_hex(receipt_or_digest).map_err(|_| {
        error(
            "INVALID_RECEIPT_DIGEST",
            "receipt could not be canonicalized for digest verification",
        )
    })?;
    Ok(ReceiptDigest {
        algorithm: "sha-256".to_string(),
        canonicalization: "RFC8785-JCS".to_string(),
        value,
    })
}

fn parse_party(
    value: &Value,
    field_name: &str,
    code: &'static str,
) -> Result<PartyRef, CounterSignatureVerificationError> {
    let party: PartyRef = serde_json::from_value(value.clone())
        .map_err(|_| error(code, format!("{field_name} is invalid")))?;
    if party.r#type.is_empty() || party.id.is_empty() {
        return Err(error(
            code,
            format!("{field_name} must include type and id"),
        ));
    }
    Ok(party)
}

fn parse_timestamp(
    raw: &str,
    field_name: &str,
    code: &'static str,
) -> Result<OffsetDateTime, CounterSignatureVerificationError> {
    OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|_| error(code, format!("{field_name} must be an RFC3339 timestamp")))
}

fn parse_uses(value: Option<&Value>) -> Result<Vec<&str>, CounterSignatureVerificationError> {
    match value {
        Some(Value::String(use_name)) if !use_name.is_empty() => Ok(vec![use_name.as_str()]),
        Some(Value::Array(items)) if !items.is_empty() => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|text| !text.is_empty())
                    .ok_or_else(|| {
                        error(
                            "TRUSTED_KEYS_INVALID",
                            "trusted key use entries must be strings",
                        )
                    })
            })
            .collect(),
        _ => Err(error(
            "TRUSTED_KEYS_INVALID",
            "trusted key use must be a non-empty string or array",
        )),
    }
}

pub fn verify_countersignature(
    receipt_or_digest: &Value,
    countersignature: &Value,
    trusted_keys: &Value,
) -> Result<VerifiedCounterSignature, CounterSignatureVerificationError> {
    let expected_digest = resolve_receipt_digest(receipt_or_digest)?;
    let artifact = object(
        countersignature,
        "countersignature",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let contract = object(
        artifact.get("contract").ok_or_else(|| {
            error(
                "INVALID_COUNTERSIGNATURE",
                "countersignature.contract is required",
            )
        })?,
        "countersignature.contract",
        "INVALID_COUNTERSIGNATURE",
    )?;
    if contract.get("name").and_then(Value::as_str) != Some("receipt_countersignature")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
    {
        return Err(error(
            "INVALID_COUNTERSIGNATURE",
            "contract must declare receipt_countersignature v1",
        ));
    }
    let observed_digest = parse_digest(
        artifact
            .get("receipt_digest")
            .ok_or_else(|| error("INVALID_COUNTERSIGNATURE", "receipt_digest is required"))?,
        "countersignature.receipt_digest",
    )?;
    if observed_digest != expected_digest {
        return Err(error(
            "RECEIPT_DIGEST_MISMATCH",
            "counter-signature receipt digest does not match the supplied receipt or digest",
        ));
    }
    let witness = parse_party(
        artifact
            .get("witness")
            .ok_or_else(|| error("INVALID_COUNTERSIGNATURE", "witness is required"))?,
        "countersignature.witness",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let signed_at_raw = string(
        artifact.get("signed_at"),
        "countersignature.signed_at",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let signed_at = parse_timestamp(
        signed_at_raw,
        "countersignature.signed_at",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let anchor_reference = match artifact.get("anchor_reference") {
        Some(value) => Some(
            object(
                value,
                "countersignature.anchor_reference",
                "INVALID_COUNTERSIGNATURE",
            )?
            .clone(),
        ),
        None => None,
    };
    let signature = object(
        artifact
            .get("signature")
            .ok_or_else(|| error("INVALID_COUNTERSIGNATURE", "signature is required"))?,
        "countersignature.signature",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let algorithm = string(
        signature.get("algorithm"),
        "countersignature.signature.algorithm",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let key_id = string(
        signature.get("key_id"),
        "countersignature.signature.key_id",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let encoding = string(
        signature.get("encoding"),
        "countersignature.signature.encoding",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let signature_value = string(
        signature.get("value"),
        "countersignature.signature.value",
        "INVALID_COUNTERSIGNATURE",
    )?;

    let key_set = object(trusted_keys, "trusted_keys", "TRUSTED_KEYS_INVALID")?;
    let key_contract = object(
        key_set
            .get("contract")
            .ok_or_else(|| error("TRUSTED_KEYS_INVALID", "trusted_keys.contract is required"))?,
        "trusted_keys.contract",
        "TRUSTED_KEYS_INVALID",
    )?;
    if key_contract.get("name").and_then(Value::as_str) != Some("key_discovery")
        || key_contract.get("version").and_then(Value::as_str) != Some("v1")
    {
        return Err(error(
            "TRUSTED_KEYS_INVALID",
            "trusted key set must declare key_discovery v1",
        ));
    }
    let issuer = parse_party(
        key_set
            .get("issuer")
            .ok_or_else(|| error("TRUSTED_KEYS_INVALID", "trusted_keys.issuer is required"))?,
        "trusted_keys.issuer",
        "TRUSTED_KEYS_INVALID",
    )?;
    if issuer.r#type != witness.r#type || issuer.id != witness.id {
        return Err(error(
            "WITNESS_MISMATCH",
            "counter-signature witness does not match the trusted key-set issuer",
        ));
    }
    let keys = key_set
        .get("keys")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| {
            error(
                "TRUSTED_KEYS_INVALID",
                "trusted key set must contain a non-empty keys array",
            )
        })?;
    let matches: Vec<&Map<String, Value>> = keys
        .iter()
        .filter_map(Value::as_object)
        .filter(|key| key.get("key_id").and_then(Value::as_str) == Some(key_id))
        .collect();
    if matches.is_empty() {
        return Err(error(
            "UNKNOWN_KEY_ID",
            format!("no trusted counter-signing key matched key_id {key_id:?}"),
        ));
    }
    if matches.len() != 1 {
        return Err(error(
            "TRUSTED_KEYS_INVALID",
            format!("trusted key set contains duplicate key_id {key_id:?}"),
        ));
    }
    let key = matches[0];
    if key.get("algorithm").and_then(Value::as_str) != Some(algorithm) {
        return Err(error(
            "SIGNATURE_INVALID",
            "trusted key algorithm does not match the counter-signature",
        ));
    }
    if !parse_uses(key.get("use"))?.contains(&COUNTERSIGNATURE_KEY_USE) {
        return Err(error(
            "KEY_PURPOSE_MISMATCH",
            "trusted key is not authorized for receipt counter-signatures",
        ));
    }
    if !matches!(
        key.get("status").and_then(Value::as_str),
        Some("active" | "retired")
    ) {
        return Err(error(
            "KEY_NOT_VALID",
            "trusted counter-signing key is not active or retired",
        ));
    }
    for (field_name, inclusive, message) in [
        (
            "not_before",
            false,
            "trusted counter-signing key was not valid at signing time",
        ),
        (
            "expires_at",
            true,
            "trusted counter-signing key was expired at signing time",
        ),
        (
            "revoked_at",
            true,
            "trusted counter-signing key was revoked at signing time",
        ),
    ] {
        if let Some(raw) = key.get(field_name).and_then(Value::as_str) {
            let bound =
                parse_timestamp(raw, &format!("keys[].{field_name}"), "TRUSTED_KEYS_INVALID")?;
            if (!inclusive && signed_at < bound) || (inclusive && signed_at >= bound) {
                return Err(error("KEY_NOT_VALID", message));
            }
        }
    }
    if algorithm != "EdDSA" || encoding != "base64url" {
        return Err(error(
            "UNSUPPORTED_ALGORITHM",
            "receipt counter-signature v1 supports EdDSA/Ed25519 with base64url encoding",
        ));
    }
    let jwk = object(
        key.get("public_key_jwk")
            .ok_or_else(|| error("TRUSTED_KEYS_INVALID", "public_key_jwk is required"))?,
        "keys[].public_key_jwk",
        "TRUSTED_KEYS_INVALID",
    )?;
    let jwk_kid = jwk.get("kid").and_then(Value::as_str);
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || (jwk_kid.is_some() && jwk_kid != Some(key_id))
        || !matches!(jwk.get("alg").and_then(Value::as_str), None | Some("EdDSA"))
    {
        return Err(error(
            "TRUSTED_KEYS_INVALID",
            "counter-signing key must be an Ed25519 OKP JWK matching signature.key_id",
        ));
    }
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(string(
            jwk.get("x"),
            "public_key_jwk.x",
            "TRUSTED_KEYS_INVALID",
        )?)
        .map_err(|_| error("TRUSTED_KEYS_INVALID", "public_key_jwk.x must be base64url"))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_value)
        .map_err(|_| error("SIGNATURE_INVALID", "signature.value must be base64url"))?;
    let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        error(
            "TRUSTED_KEYS_INVALID",
            "public_key_jwk.x must encode 32 bytes",
        )
    })?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| error("SIGNATURE_INVALID", "signature.value must encode 64 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|_| {
        error(
            "TRUSTED_KEYS_INVALID",
            "public_key_jwk.x is not a valid Ed25519 public key",
        )
    })?;
    let mut statement = json!({
        "context": COUNTERSIGNATURE_CONTEXT,
        "receipt_digest": observed_digest,
        "witness": witness,
        "signed_at": signed_at_raw,
    });
    if let (Some(anchor), Some(statement_object)) =
        (anchor_reference.as_ref(), statement.as_object_mut())
    {
        statement_object.insert(
            "anchor_reference".to_string(),
            Value::Object(anchor.clone()),
        );
    }
    let payload = canonicalize_bytes(&statement).map_err(|_| {
        error(
            "INVALID_COUNTERSIGNATURE",
            "counter-signature statement could not be canonicalized",
        )
    })?;
    verifying_key
        .verify(&payload, &Signature::from_bytes(&signature_array))
        .map_err(|_| {
            error(
                "SIGNATURE_INVALID",
                "receipt counter-signature could not be verified",
            )
        })?;

    Ok(VerifiedCounterSignature {
        receipt_digest: observed_digest,
        witness,
        signed_at,
        key_id: key_id.to_string(),
        anchor_reference,
    })
}
