use std::error::Error;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::canonical::canonicalize_bytes;
use crate::countersignature::ReceiptDigest;
use crate::types::PartyRef;

pub const CHECKPOINT_CONTEXT: &str = "actenon.transparency-checkpoint.v1";
pub const CHECKPOINT_KEY_USE: &str = "transparency_checkpoint";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparencyVerificationError {
    code: &'static str,
    message: String,
}

impl TransparencyVerificationError {
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

impl fmt::Display for TransparencyVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for TransparencyVerificationError {}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedCheckpoint {
    pub log: PartyRef,
    pub tree_size: u64,
    pub root_hash: String,
    pub issued_at: OffsetDateTime,
    pub key_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedInclusion {
    pub log_id: String,
    pub tree_size: u64,
    pub leaf_index: u64,
    pub leaf_digest: ReceiptDigest,
    pub checkpoint: Option<VerifiedCheckpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedConsistency {
    pub log_id: String,
    pub old_tree_size: u64,
    pub new_tree_size: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedMonitorUpdate {
    pub previous: VerifiedCheckpoint,
    pub current: VerifiedCheckpoint,
    pub consistency: VerifiedConsistency,
}

#[derive(Clone)]
struct ParsedCheckpoint {
    log: PartyRef,
    log_raw: Value,
    tree_size: u64,
    root_hash: [u8; 32],
    issued_at_raw: String,
    issued_at: OffsetDateTime,
    signature_algorithm: String,
    signature_key_id: String,
    signature_encoding: String,
    signature_value: String,
}

fn error(code: &'static str, message: impl Into<String>) -> TransparencyVerificationError {
    TransparencyVerificationError::new(code, message)
}

fn object<'a>(
    value: &'a Value,
    field_name: &str,
    code: &'static str,
) -> Result<&'a Map<String, Value>, TransparencyVerificationError> {
    value
        .as_object()
        .ok_or_else(|| error(code, format!("{field_name} must be a JSON object")))
}

fn string<'a>(
    value: Option<&'a Value>,
    field_name: &str,
    code: &'static str,
) -> Result<&'a str, TransparencyVerificationError> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| error(code, format!("{field_name} must be a non-empty string")))
}

fn nonnegative_integer(
    value: Option<&Value>,
    field_name: &str,
    code: &'static str,
) -> Result<u64, TransparencyVerificationError> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| error(code, format!("{field_name} must be a non-negative integer")))
}

fn parse_timestamp(
    raw: &str,
    field_name: &str,
    code: &'static str,
) -> Result<OffsetDateTime, TransparencyVerificationError> {
    OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|_| error(code, format!("{field_name} must be an RFC3339 timestamp")))
}

fn parse_party(
    value: &Value,
    field_name: &str,
    code: &'static str,
) -> Result<PartyRef, TransparencyVerificationError> {
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

fn decode_hex_32(
    value: &str,
    field_name: &str,
    code: &'static str,
) -> Result<[u8; 32], TransparencyVerificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            code,
            format!("{field_name} must be a lowercase 64-character SHA-256 hex value"),
        ));
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("hex input is validated before decoding"),
    }
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn parse_digest(
    value: &Value,
    field_name: &str,
) -> Result<ReceiptDigest, TransparencyVerificationError> {
    let data = object(value, field_name, "INVALID_LEAF_DIGEST")?;
    let digest = ReceiptDigest {
        algorithm: string(
            data.get("algorithm"),
            &format!("{field_name}.algorithm"),
            "INVALID_LEAF_DIGEST",
        )?
        .to_string(),
        canonicalization: string(
            data.get("canonicalization"),
            &format!("{field_name}.canonicalization"),
            "INVALID_LEAF_DIGEST",
        )?
        .to_string(),
        value: string(
            data.get("value"),
            &format!("{field_name}.value"),
            "INVALID_LEAF_DIGEST",
        )?
        .to_string(),
    };
    decode_hex_32(
        &digest.value,
        &format!("{field_name}.value"),
        "INVALID_LEAF_DIGEST",
    )?;
    if digest.algorithm != "sha-256" || digest.canonicalization != "RFC8785-JCS" {
        return Err(error(
            "INVALID_LEAF_DIGEST",
            "leaf digest must declare sha-256 and RFC8785-JCS",
        ));
    }
    Ok(digest)
}

fn parse_hash_path(
    value: Option<&Value>,
    field_name: &str,
    code: &'static str,
) -> Result<Vec<[u8; 32]>, TransparencyVerificationError> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| error(code, format!("{field_name} must be an array")))?
        .iter()
        .enumerate()
        .map(|(index, item)| {
            decode_hex_32(
                string(Some(item), &format!("{field_name}[{index}]"), code)?,
                &format!("{field_name}[{index}]"),
                code,
            )
        })
        .collect()
}

fn parse_checkpoint(value: &Value) -> Result<ParsedCheckpoint, TransparencyVerificationError> {
    let checkpoint = object(value, "checkpoint", "INVALID_CHECKPOINT")?;
    let contract = object(
        checkpoint
            .get("contract")
            .ok_or_else(|| error("INVALID_CHECKPOINT", "checkpoint.contract is required"))?,
        "checkpoint.contract",
        "INVALID_CHECKPOINT",
    )?;
    if contract.get("name").and_then(Value::as_str) != Some("transparency_checkpoint")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
    {
        return Err(error(
            "INVALID_CHECKPOINT",
            "checkpoint contract must declare transparency_checkpoint v1",
        ));
    }
    let log_raw = checkpoint
        .get("log")
        .ok_or_else(|| error("INVALID_CHECKPOINT", "checkpoint.log is required"))?;
    let log = parse_party(log_raw, "checkpoint.log", "INVALID_CHECKPOINT")?;
    let tree_size = nonnegative_integer(
        checkpoint.get("tree_size"),
        "checkpoint.tree_size",
        "INVALID_CHECKPOINT",
    )?;
    let root_spec = object(
        checkpoint
            .get("root_hash")
            .ok_or_else(|| error("INVALID_CHECKPOINT", "checkpoint.root_hash is required"))?,
        "checkpoint.root_hash",
        "INVALID_CHECKPOINT",
    )?;
    if root_spec.get("algorithm").and_then(Value::as_str) != Some("sha-256")
        || root_spec.get("encoding").and_then(Value::as_str) != Some("hex")
    {
        return Err(error(
            "INVALID_CHECKPOINT",
            "checkpoint.root_hash must declare sha-256 with hex encoding",
        ));
    }
    let root_hash = decode_hex_32(
        string(
            root_spec.get("value"),
            "checkpoint.root_hash.value",
            "INVALID_CHECKPOINT",
        )?,
        "checkpoint.root_hash.value",
        "INVALID_CHECKPOINT",
    )?;
    let issued_at_raw = string(
        checkpoint.get("issued_at"),
        "checkpoint.issued_at",
        "INVALID_CHECKPOINT",
    )?
    .to_string();
    let issued_at = parse_timestamp(&issued_at_raw, "checkpoint.issued_at", "INVALID_CHECKPOINT")?;
    let signature = object(
        checkpoint
            .get("signature")
            .ok_or_else(|| error("INVALID_CHECKPOINT", "checkpoint.signature is required"))?,
        "checkpoint.signature",
        "INVALID_CHECKPOINT",
    )?;
    Ok(ParsedCheckpoint {
        log,
        log_raw: log_raw.clone(),
        tree_size,
        root_hash,
        issued_at_raw,
        issued_at,
        signature_algorithm: string(
            signature.get("algorithm"),
            "checkpoint.signature.algorithm",
            "INVALID_CHECKPOINT",
        )?
        .to_string(),
        signature_key_id: string(
            signature.get("key_id"),
            "checkpoint.signature.key_id",
            "INVALID_CHECKPOINT",
        )?
        .to_string(),
        signature_encoding: string(
            signature.get("encoding"),
            "checkpoint.signature.encoding",
            "INVALID_CHECKPOINT",
        )?
        .to_string(),
        signature_value: string(
            signature.get("value"),
            "checkpoint.signature.value",
            "INVALID_CHECKPOINT",
        )?
        .to_string(),
    })
}

fn parse_uses(value: Option<&Value>) -> Result<Vec<&str>, TransparencyVerificationError> {
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

fn leaf_hash(digest: &ReceiptDigest) -> Result<[u8; 32], TransparencyVerificationError> {
    let digest_bytes = decode_hex_32(&digest.value, "digest.value", "INVALID_LEAF_DIGEST")?;
    let mut hasher = Sha256::new();
    hasher.update([0_u8]);
    hasher.update(digest_bytes);
    Ok(hasher.finalize().into())
}

fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1_u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn verify_checkpoint_signature(
    checkpoint_value: &Value,
    trusted_keys: &Value,
) -> Result<VerifiedCheckpoint, TransparencyVerificationError> {
    let checkpoint = parse_checkpoint(checkpoint_value)?;
    if checkpoint.signature_algorithm != "EdDSA" || checkpoint.signature_encoding != "base64url" {
        return Err(error(
            "UNSUPPORTED_ALGORITHM",
            "transparency checkpoint v1 supports EdDSA/Ed25519 with base64url encoding",
        ));
    }
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
    if issuer.r#type != checkpoint.log.r#type || issuer.id != checkpoint.log.id {
        return Err(error(
            "LOG_IDENTITY_MISMATCH",
            "checkpoint log identity does not match the trusted key-set issuer",
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
        .filter(|key| {
            key.get("key_id").and_then(Value::as_str) == Some(checkpoint.signature_key_id.as_str())
        })
        .collect();
    if matches.is_empty() {
        return Err(error(
            "UNKNOWN_KEY_ID",
            format!(
                "no trusted checkpoint key matched key_id {:?}",
                checkpoint.signature_key_id
            ),
        ));
    }
    if matches.len() != 1 {
        return Err(error(
            "TRUSTED_KEYS_INVALID",
            format!(
                "trusted key set contains duplicate key_id {:?}",
                checkpoint.signature_key_id
            ),
        ));
    }
    let key = matches[0];
    if key.get("algorithm").and_then(Value::as_str) != Some(checkpoint.signature_algorithm.as_str())
    {
        return Err(error(
            "SIGNATURE_INVALID",
            "trusted key algorithm does not match the checkpoint signature",
        ));
    }
    if !parse_uses(key.get("use"))?.contains(&CHECKPOINT_KEY_USE) {
        return Err(error(
            "KEY_PURPOSE_MISMATCH",
            "trusted key is not authorized for transparency checkpoints",
        ));
    }
    if !matches!(
        key.get("status").and_then(Value::as_str),
        Some("active" | "retired")
    ) {
        return Err(error(
            "KEY_NOT_VALID",
            "trusted checkpoint key is not active or retired",
        ));
    }
    for (field_name, inclusive, message) in [
        (
            "not_before",
            false,
            "trusted checkpoint key was not valid at signing time",
        ),
        (
            "expires_at",
            true,
            "trusted checkpoint key was expired at signing time",
        ),
        (
            "revoked_at",
            true,
            "trusted checkpoint key was revoked at signing time",
        ),
    ] {
        if let Some(raw) = key.get(field_name).and_then(Value::as_str) {
            let bound =
                parse_timestamp(raw, &format!("keys[].{field_name}"), "TRUSTED_KEYS_INVALID")?;
            if (!inclusive && checkpoint.issued_at < bound)
                || (inclusive && checkpoint.issued_at >= bound)
            {
                return Err(error("KEY_NOT_VALID", message));
            }
        }
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
        || (jwk_kid.is_some() && jwk_kid != Some(checkpoint.signature_key_id.as_str()))
        || !matches!(jwk.get("alg").and_then(Value::as_str), None | Some("EdDSA"))
    {
        return Err(error(
            "TRUSTED_KEYS_INVALID",
            "checkpoint key must be an Ed25519 OKP JWK matching signature.key_id",
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
        .decode(&checkpoint.signature_value)
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
    let statement = json!({
        "context": CHECKPOINT_CONTEXT,
        "log": checkpoint.log_raw,
        "tree_size": checkpoint.tree_size,
        "root_hash": {
            "algorithm": "sha-256",
            "encoding": "hex",
            "value": encode_hex(&checkpoint.root_hash),
        },
        "issued_at": checkpoint.issued_at_raw,
    });
    let payload = canonicalize_bytes(&statement).map_err(|_| {
        error(
            "INVALID_CHECKPOINT",
            "checkpoint could not be canonicalized",
        )
    })?;
    verifying_key
        .verify(&payload, &Signature::from_bytes(&signature_array))
        .map_err(|_| {
            error(
                "SIGNATURE_INVALID",
                "transparency checkpoint signature could not be verified",
            )
        })?;
    Ok(VerifiedCheckpoint {
        log: checkpoint.log,
        tree_size: checkpoint.tree_size,
        root_hash: encode_hex(&checkpoint.root_hash),
        issued_at: checkpoint.issued_at,
        key_id: checkpoint.signature_key_id,
    })
}

pub fn verify_inclusion(
    digest_value: &Value,
    inclusion_proof: &Value,
    checkpoint_value: &Value,
) -> Result<VerifiedInclusion, TransparencyVerificationError> {
    let digest = parse_digest(digest_value, "digest")?;
    let proof = object(
        inclusion_proof,
        "inclusion_proof",
        "INVALID_INCLUSION_PROOF",
    )?;
    let contract = object(
        proof
            .get("contract")
            .ok_or_else(|| error("INVALID_INCLUSION_PROOF", "contract is required"))?,
        "inclusion_proof.contract",
        "INVALID_INCLUSION_PROOF",
    )?;
    if contract.get("name").and_then(Value::as_str) != Some("transparency_inclusion_proof")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
        || proof.get("hash_algorithm").and_then(Value::as_str) != Some("sha-256")
    {
        return Err(error(
            "INVALID_INCLUSION_PROOF",
            "proof must declare transparency_inclusion_proof v1 with sha-256",
        ));
    }
    let observed_digest = parse_digest(
        proof
            .get("leaf_digest")
            .ok_or_else(|| error("INVALID_INCLUSION_PROOF", "leaf_digest is required"))?,
        "inclusion_proof.leaf_digest",
    )?;
    if observed_digest != digest {
        return Err(error(
            "LEAF_DIGEST_MISMATCH",
            "inclusion proof leaf digest does not match the supplied digest",
        ));
    }
    let log_id = string(
        proof.get("log_id"),
        "inclusion_proof.log_id",
        "INVALID_INCLUSION_PROOF",
    )?;
    let tree_size = nonnegative_integer(
        proof.get("tree_size"),
        "inclusion_proof.tree_size",
        "INVALID_INCLUSION_PROOF",
    )?;
    let leaf_index = nonnegative_integer(
        proof.get("leaf_index"),
        "inclusion_proof.leaf_index",
        "INVALID_INCLUSION_PROOF",
    )?;
    if tree_size == 0 || leaf_index >= tree_size {
        return Err(error(
            "INVALID_INCLUSION_PROOF",
            "leaf_index must identify a leaf within the non-empty proof tree",
        ));
    }
    let path = parse_hash_path(
        proof.get("audit_path"),
        "inclusion_proof.audit_path",
        "INVALID_INCLUSION_PROOF",
    )?;
    let checkpoint = parse_checkpoint(checkpoint_value)?;
    if checkpoint.log.id != log_id || checkpoint.tree_size != tree_size {
        return Err(error(
            "CHECKPOINT_MISMATCH",
            "inclusion proof log or tree size does not match the checkpoint",
        ));
    }
    let mut node = leaf_hash(&digest)?;
    let mut fn_index = leaf_index;
    let mut sn = tree_size - 1;
    for sibling in path {
        if fn_index & 1 == 1 || fn_index == sn {
            node = node_hash(sibling, node);
            while fn_index != 0 && fn_index & 1 == 0 {
                fn_index >>= 1;
                sn >>= 1;
            }
        } else {
            node = node_hash(node, sibling);
        }
        fn_index >>= 1;
        sn >>= 1;
    }
    if sn != 0 || node != checkpoint.root_hash {
        return Err(error(
            "INCLUSION_PROOF_INVALID",
            "digest is not included in the supplied checkpoint",
        ));
    }
    Ok(VerifiedInclusion {
        log_id: log_id.to_string(),
        tree_size,
        leaf_index,
        leaf_digest: digest,
        checkpoint: None,
    })
}

pub fn verify_consistency(
    old_checkpoint_value: &Value,
    new_checkpoint_value: &Value,
    consistency_proof: &Value,
) -> Result<VerifiedConsistency, TransparencyVerificationError> {
    let old_checkpoint = parse_checkpoint(old_checkpoint_value)?;
    let new_checkpoint = parse_checkpoint(new_checkpoint_value)?;
    if old_checkpoint.log.r#type != new_checkpoint.log.r#type
        || old_checkpoint.log.id != new_checkpoint.log.id
    {
        return Err(error(
            "LOG_IDENTITY_MISMATCH",
            "consistency checkpoints identify different logs",
        ));
    }
    if new_checkpoint.tree_size < old_checkpoint.tree_size {
        return Err(error(
            "REWIND_DETECTED",
            "new checkpoint tree size is smaller than the previous checkpoint",
        ));
    }
    let proof = object(
        consistency_proof,
        "consistency_proof",
        "INVALID_CONSISTENCY_PROOF",
    )?;
    let contract = object(
        proof
            .get("contract")
            .ok_or_else(|| error("INVALID_CONSISTENCY_PROOF", "contract is required"))?,
        "consistency_proof.contract",
        "INVALID_CONSISTENCY_PROOF",
    )?;
    if contract.get("name").and_then(Value::as_str) != Some("transparency_consistency_proof")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
        || proof.get("hash_algorithm").and_then(Value::as_str) != Some("sha-256")
    {
        return Err(error(
            "INVALID_CONSISTENCY_PROOF",
            "proof must declare transparency_consistency_proof v1 with sha-256",
        ));
    }
    let log_id = string(
        proof.get("log_id"),
        "consistency_proof.log_id",
        "INVALID_CONSISTENCY_PROOF",
    )?;
    let old_size = nonnegative_integer(
        proof.get("old_tree_size"),
        "consistency_proof.old_tree_size",
        "INVALID_CONSISTENCY_PROOF",
    )?;
    let new_size = nonnegative_integer(
        proof.get("new_tree_size"),
        "consistency_proof.new_tree_size",
        "INVALID_CONSISTENCY_PROOF",
    )?;
    if log_id != old_checkpoint.log.id
        || old_size != old_checkpoint.tree_size
        || new_size != new_checkpoint.tree_size
    {
        return Err(error(
            "CHECKPOINT_MISMATCH",
            "consistency proof does not match the supplied checkpoints",
        ));
    }
    let path = parse_hash_path(
        proof.get("consistency_path"),
        "consistency_proof.consistency_path",
        "INVALID_CONSISTENCY_PROOF",
    )?;
    if old_size == 0 {
        if !path.is_empty() {
            return Err(error(
                "CONSISTENCY_PROOF_INVALID",
                "empty-tree consistency proof must have an empty path",
            ));
        }
    } else if old_size == new_size {
        if !path.is_empty() || old_checkpoint.root_hash != new_checkpoint.root_hash {
            return Err(error(
                "EQUIVOCATION_DETECTED",
                "same-size checkpoints have different roots or a non-empty proof",
            ));
        }
    } else {
        let mut fn_index = old_size - 1;
        let mut sn = new_size - 1;
        while fn_index & 1 == 1 {
            fn_index >>= 1;
            sn >>= 1;
        }
        let (mut first, mut second, mut proof_index) = if fn_index == 0 {
            (old_checkpoint.root_hash, old_checkpoint.root_hash, 0)
        } else {
            let initial = path.first().copied().ok_or_else(|| {
                error(
                    "CONSISTENCY_PROOF_INVALID",
                    "consistency proof path is incomplete",
                )
            })?;
            (initial, initial, 1)
        };
        while proof_index < path.len() {
            if sn == 0 {
                return Err(error(
                    "CONSISTENCY_PROOF_INVALID",
                    "consistency proof path contains extra hashes",
                ));
            }
            let sibling = path[proof_index];
            if fn_index & 1 == 1 || fn_index == sn {
                first = node_hash(sibling, first);
                second = node_hash(sibling, second);
                while fn_index != 0 && fn_index & 1 == 0 {
                    fn_index >>= 1;
                    sn >>= 1;
                }
            } else {
                second = node_hash(second, sibling);
            }
            fn_index >>= 1;
            sn >>= 1;
            proof_index += 1;
        }
        if sn != 0 || first != old_checkpoint.root_hash || second != new_checkpoint.root_hash {
            return Err(error(
                "CONSISTENCY_PROOF_INVALID",
                "checkpoints are not append-only consistent",
            ));
        }
    }
    Ok(VerifiedConsistency {
        log_id: log_id.to_string(),
        old_tree_size: old_size,
        new_tree_size: new_size,
    })
}

pub fn verify_countersignature_inclusion(
    countersignature: &Value,
    inclusion_proof: &Value,
    checkpoint: &Value,
    trusted_keys: &Value,
) -> Result<VerifiedInclusion, TransparencyVerificationError> {
    let artifact = object(
        countersignature,
        "countersignature",
        "INVALID_COUNTERSIGNATURE",
    )?;
    let contract = object(
        artifact
            .get("contract")
            .ok_or_else(|| error("INVALID_COUNTERSIGNATURE", "contract is required"))?,
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
    let digest_value = artifact
        .get("receipt_digest")
        .ok_or_else(|| error("INVALID_COUNTERSIGNATURE", "receipt_digest is required"))?;
    parse_digest(digest_value, "countersignature.receipt_digest")?;
    let anchor = object(
        artifact
            .get("anchor_reference")
            .ok_or_else(|| error("ORPHAN_COUNTERSIGNATURE", "anchor_reference is required"))?,
        "countersignature.anchor_reference",
        "ORPHAN_COUNTERSIGNATURE",
    )?;
    if anchor.get("type").and_then(Value::as_str) != Some("transparency_log") {
        return Err(error(
            "ORPHAN_COUNTERSIGNATURE",
            "counter-signature is not anchored to a transparency log",
        ));
    }
    let anchor_log_id = string(
        anchor.get("id"),
        "countersignature.anchor_reference.id",
        "ORPHAN_COUNTERSIGNATURE",
    )?;
    let anchor_leaf_index = nonnegative_integer(
        anchor.get("leaf_index"),
        "countersignature.anchor_reference.leaf_index",
        "ORPHAN_COUNTERSIGNATURE",
    )?;
    let verified_checkpoint = verify_checkpoint_signature(checkpoint, trusted_keys)?;
    let proof = object(
        inclusion_proof,
        "inclusion_proof",
        "INVALID_INCLUSION_PROOF",
    )?;
    let proof_digest = parse_digest(
        proof
            .get("leaf_digest")
            .ok_or_else(|| error("INVALID_INCLUSION_PROOF", "leaf_digest is required"))?,
        "inclusion_proof.leaf_digest",
    )?;
    let counter_digest = parse_digest(digest_value, "countersignature.receipt_digest")?;
    if proof_digest != counter_digest {
        return Err(error(
            "ORPHAN_COUNTERSIGNATURE",
            "counter-signature digest is not the digest proven at the declared log leaf",
        ));
    }
    let mut inclusion = verify_inclusion(digest_value, inclusion_proof, checkpoint)?;
    if anchor_log_id != inclusion.log_id || anchor_leaf_index != inclusion.leaf_index {
        return Err(error(
            "ORPHAN_COUNTERSIGNATURE",
            "counter-signature anchor does not match the verified inclusion proof",
        ));
    }
    inclusion.checkpoint = Some(verified_checkpoint);
    Ok(inclusion)
}

pub fn verify_monitor_update(
    previous_checkpoint: &Value,
    current_checkpoint: &Value,
    consistency_proof: &Value,
    trusted_keys: &Value,
) -> Result<VerifiedMonitorUpdate, TransparencyVerificationError> {
    let previous = verify_checkpoint_signature(previous_checkpoint, trusted_keys)?;
    let current = verify_checkpoint_signature(current_checkpoint, trusted_keys)?;
    let consistency =
        verify_consistency(previous_checkpoint, current_checkpoint, consistency_proof)?;
    Ok(VerifiedMonitorUpdate {
        previous,
        current,
        consistency,
    })
}
