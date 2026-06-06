use std::error::Error;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::canonical::canonicalize_bytes;
use crate::types::{ActionHashSpec, PartyRef, SignatureSpec};

pub const ISSUER_STATUS_CONTEXT: &str = "actenon.issuer-status.v1";
pub const ISSUER_STATUS_KEY_USE: &str = "issuer_status";
pub const APPROVAL_CONTEXT: &str = "actenon.approval-artifact.v1";
pub const APPROVAL_KEY_USE: &str = "approval_artifact";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustArtifactVerificationError {
    code: &'static str,
    message: String,
}

impl TrustArtifactVerificationError {
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

impl fmt::Display for TrustArtifactVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for TrustArtifactVerificationError {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IssuerStatusPolicy {
    #[default]
    Required,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerStatusOptions {
    pub max_age_seconds: i64,
    pub status_policy: IssuerStatusPolicy,
}

impl Default for IssuerStatusOptions {
    fn default() -> Self {
        Self {
            max_age_seconds: 3600,
            status_policy: IssuerStatusPolicy::Required,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedIssuerStatus {
    pub issuer: PartyRef,
    pub authority: PartyRef,
    pub status: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub key_id: String,
    pub status_reference: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedApprovalArtifact {
    pub approval_id: String,
    pub approver: PartyRef,
    pub approval_type: String,
    pub decision: String,
    pub action_hash: ActionHashSpec,
    pub issued_at: OffsetDateTime,
    pub key_id: String,
}

fn error(code: &'static str, message: impl Into<String>) -> TrustArtifactVerificationError {
    TrustArtifactVerificationError::new(code, message)
}

fn object<'a>(
    value: &'a Value,
    field: &str,
    code: &'static str,
) -> Result<&'a Map<String, Value>, TrustArtifactVerificationError> {
    value
        .as_object()
        .ok_or_else(|| error(code, format!("{field} must be a JSON object")))
}

fn string<'a>(
    value: Option<&'a Value>,
    field: &str,
    code: &'static str,
) -> Result<&'a str, TrustArtifactVerificationError> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| error(code, format!("{field} must be a non-empty string")))
}

fn timestamp(
    value: Option<&Value>,
    field: &str,
    code: &'static str,
) -> Result<(String, OffsetDateTime), TrustArtifactVerificationError> {
    let raw = string(value, field, code)?;
    let parsed = OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|_| error(code, format!("{field} must be an RFC3339 timestamp")))?;
    Ok((raw.to_string(), parsed))
}

fn party(
    value: Option<&Value>,
    field: &str,
    code: &'static str,
) -> Result<PartyRef, TrustArtifactVerificationError> {
    let party: PartyRef = serde_json::from_value(
        value
            .cloned()
            .ok_or_else(|| error(code, format!("{field} is required")))?,
    )
    .map_err(|_| error(code, format!("{field} is invalid")))?;
    if party.r#type.is_empty() || party.id.is_empty() {
        return Err(error(code, format!("{field} must include type and id")));
    }
    Ok(party)
}

fn signature(
    value: Option<&Value>,
    field: &str,
    code: &'static str,
) -> Result<SignatureSpec, TrustArtifactVerificationError> {
    let signature: SignatureSpec = serde_json::from_value(
        value
            .cloned()
            .ok_or_else(|| error(code, format!("{field} is required")))?,
    )
    .map_err(|_| error(code, format!("{field} is invalid")))?;
    if signature.algorithm.is_empty()
        || signature.key_id.is_empty()
        || signature.encoding.is_empty()
        || signature.value.is_empty()
    {
        return Err(error(code, format!("{field} is incomplete")));
    }
    Ok(signature)
}

fn action_hash(value: Option<&Value>) -> Result<ActionHashSpec, TrustArtifactVerificationError> {
    let parsed: ActionHashSpec = serde_json::from_value(
        value
            .cloned()
            .ok_or_else(|| error("INVALID_APPROVAL_ARTIFACT", "action_hash is required"))?,
    )
    .map_err(|_| error("INVALID_APPROVAL_ARTIFACT", "action_hash is invalid"))?;
    if parsed.algorithm != "sha-256"
        || parsed.canonicalization != "RFC8785-JCS"
        || parsed.value.len() != 64
        || !parsed
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            "INVALID_APPROVAL_ARTIFACT",
            "action_hash must declare sha-256, RFC8785-JCS, and lowercase hex",
        ));
    }
    Ok(parsed)
}

fn key_uses(value: Option<&Value>) -> Result<Vec<&str>, TrustArtifactVerificationError> {
    match value {
        Some(Value::String(use_name)) if !use_name.is_empty() => Ok(vec![use_name]),
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

fn select_key<'a>(
    trusted_keys: &'a Value,
    signer: &PartyRef,
    artifact_signature: &SignatureSpec,
    signed_at: OffsetDateTime,
    required_use: &str,
) -> Result<&'a Map<String, Value>, TrustArtifactVerificationError> {
    let key_set = object(trusted_keys, "trusted_keys", "TRUSTED_KEYS_INVALID")?;
    let contract = object(
        key_set
            .get("contract")
            .ok_or_else(|| error("TRUSTED_KEYS_INVALID", "trusted_keys.contract is required"))?,
        "trusted_keys.contract",
        "TRUSTED_KEYS_INVALID",
    )?;
    if contract.get("name").and_then(Value::as_str) != Some("key_discovery")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
    {
        return Err(error(
            "TRUSTED_KEYS_INVALID",
            "trusted key set must declare key_discovery v1",
        ));
    }
    let key_issuer = party(
        key_set.get("issuer"),
        "trusted_keys.issuer",
        "TRUSTED_KEYS_INVALID",
    )?;
    if key_issuer.r#type != signer.r#type || key_issuer.id != signer.id {
        return Err(error(
            "SIGNER_MISMATCH",
            "artifact signer does not match the trusted key-set issuer",
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
        .filter(|key| key.get("key_id").and_then(Value::as_str) == Some(&artifact_signature.key_id))
        .collect();
    let key = match matches.as_slice() {
        [] => {
            return Err(error(
                "UNKNOWN_KEY_ID",
                format!(
                    "no trusted key matched key_id {:?}",
                    artifact_signature.key_id
                ),
            ))
        }
        [key] => *key,
        _ => {
            return Err(error(
                "TRUSTED_KEYS_INVALID",
                "trusted key set contains a duplicate key_id",
            ))
        }
    };
    if key.get("algorithm").and_then(Value::as_str) != Some(&artifact_signature.algorithm) {
        return Err(error(
            "SIGNATURE_INVALID",
            "trusted key algorithm does not match the artifact signature",
        ));
    }
    if !key_uses(key.get("use"))?.contains(&required_use) {
        return Err(error(
            "KEY_PURPOSE_MISMATCH",
            "trusted key is not authorized for this artifact",
        ));
    }
    if !matches!(
        key.get("status").and_then(Value::as_str),
        Some("active" | "retired")
    ) {
        return Err(error(
            "KEY_NOT_VALID",
            "trusted key is not active or retired",
        ));
    }
    for (field, inclusive) in [
        ("not_before", false),
        ("expires_at", true),
        ("revoked_at", true),
    ] {
        let Some(value) = key.get(field) else {
            continue;
        };
        let (_, bound) = timestamp(Some(value), field, "TRUSTED_KEYS_INVALID")?;
        if (!inclusive && signed_at < bound) || (inclusive && signed_at >= bound) {
            return Err(error(
                "KEY_NOT_VALID",
                "trusted key was not valid at signing time",
            ));
        }
    }
    Ok(key)
}

fn verify_signature(
    statement: &Value,
    artifact_signature: &SignatureSpec,
    key: &Map<String, Value>,
) -> Result<(), TrustArtifactVerificationError> {
    if artifact_signature.algorithm != "EdDSA" || artifact_signature.encoding != "base64url" {
        return Err(error(
            "UNSUPPORTED_ALGORITHM",
            "trust artifact v1 supports EdDSA/Ed25519 with base64url encoding",
        ));
    }
    let jwk = object(
        key.get("public_key_jwk")
            .ok_or_else(|| error("TRUSTED_KEYS_INVALID", "public_key_jwk is required"))?,
        "public_key_jwk",
        "TRUSTED_KEYS_INVALID",
    )?;
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || jwk
            .get("kid")
            .and_then(Value::as_str)
            .is_some_and(|kid| kid != artifact_signature.key_id)
        || jwk
            .get("alg")
            .and_then(Value::as_str)
            .is_some_and(|algorithm| algorithm != "EdDSA")
    {
        return Err(error(
            "TRUSTED_KEYS_INVALID",
            "trusted key must be an Ed25519 OKP JWK matching signature.key_id",
        ));
    }
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(string(
            jwk.get("x"),
            "public_key_jwk.x",
            "TRUSTED_KEYS_INVALID",
        )?)
        .map_err(|_| error("TRUSTED_KEYS_INVALID", "public key is not valid base64url"))?;
    let public_key: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| error("TRUSTED_KEYS_INVALID", "public key must be 32 bytes"))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&artifact_signature.value)
        .map_err(|_| error("SIGNATURE_INVALID", "signature is not valid base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| error("SIGNATURE_INVALID", "signature must be 64 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| error("TRUSTED_KEYS_INVALID", "public key is invalid"))?;
    let payload = canonicalize_bytes(statement)
        .map_err(|_| error("SIGNATURE_INVALID", "statement could not be canonicalized"))?;
    verifying_key.verify(&payload, &signature).map_err(|_| {
        error(
            "SIGNATURE_INVALID",
            "artifact signature could not be verified",
        )
    })
}

pub fn verify_issuer_status(
    issuer: &Value,
    status_artifact: Option<&Value>,
    trusted_keys: Option<&Value>,
    now: OffsetDateTime,
) -> Result<Option<VerifiedIssuerStatus>, TrustArtifactVerificationError> {
    verify_issuer_status_with_options(
        issuer,
        status_artifact,
        trusted_keys,
        now,
        IssuerStatusOptions::default(),
    )
}

pub fn verify_issuer_status_with_options(
    issuer: &Value,
    status_artifact: Option<&Value>,
    trusted_keys: Option<&Value>,
    now: OffsetDateTime,
    options: IssuerStatusOptions,
) -> Result<Option<VerifiedIssuerStatus>, TrustArtifactVerificationError> {
    if options.status_policy == IssuerStatusPolicy::Disabled {
        eprintln!(
            "Actenon: issuer-status verification DISABLED — revoked or stale issuers may be accepted."
        );
        return Ok(None);
    }
    if options.max_age_seconds <= 0 {
        return Err(error(
            "INVALID_ISSUER_STATUS",
            "maximum status age must be positive",
        ));
    }
    let artifact = object(
        status_artifact.ok_or_else(|| {
            error(
                "ISSUER_STATUS_REQUIRED",
                "high-assurance verification requires signed issuer status",
            )
        })?,
        "status_artifact",
        "INVALID_ISSUER_STATUS",
    )?;
    let trusted_keys = trusted_keys.ok_or_else(|| {
        error(
            "ISSUER_STATUS_REQUIRED",
            "high-assurance verification requires trusted status keys",
        )
    })?;
    let contract = object(
        artifact
            .get("contract")
            .ok_or_else(|| error("INVALID_ISSUER_STATUS", "contract is required"))?,
        "status_artifact.contract",
        "INVALID_ISSUER_STATUS",
    )?;
    if contract.get("name").and_then(Value::as_str) != Some("issuer_status")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
    {
        return Err(error(
            "INVALID_ISSUER_STATUS",
            "contract must declare issuer_status v1",
        ));
    }
    let expected_issuer = party(Some(issuer), "issuer", "INVALID_ISSUER_STATUS")?;
    let observed_issuer = party(
        artifact.get("issuer"),
        "status_artifact.issuer",
        "INVALID_ISSUER_STATUS",
    )?;
    if expected_issuer.r#type != observed_issuer.r#type || expected_issuer.id != observed_issuer.id
    {
        return Err(error(
            "ISSUER_MISMATCH",
            "issuer status describes a different issuer",
        ));
    }
    let authority = party(
        artifact.get("authority"),
        "status_artifact.authority",
        "INVALID_ISSUER_STATUS",
    )?;
    let status = string(
        artifact.get("status"),
        "status_artifact.status",
        "INVALID_ISSUER_STATUS",
    )?;
    if !matches!(status, "good_standing" | "suspended" | "revoked") {
        return Err(error(
            "INVALID_ISSUER_STATUS",
            "issuer status token is invalid",
        ));
    }
    let (issued_at_raw, issued_at) = timestamp(
        artifact.get("issued_at"),
        "status_artifact.issued_at",
        "INVALID_ISSUER_STATUS",
    )?;
    let (expires_at_raw, expires_at) = timestamp(
        artifact.get("expires_at"),
        "status_artifact.expires_at",
        "INVALID_ISSUER_STATUS",
    )?;
    if expires_at <= issued_at {
        return Err(error(
            "INVALID_ISSUER_STATUS",
            "issuer status expiry must be after issuance",
        ));
    }
    if now < issued_at {
        return Err(error(
            "ISSUER_STATUS_NOT_YET_VALID",
            "issuer status is not yet valid",
        ));
    }
    if now >= expires_at {
        return Err(error("ISSUER_STATUS_EXPIRED", "issuer status has expired"));
    }
    if (now - issued_at).whole_seconds() > options.max_age_seconds {
        return Err(error("ISSUER_STATUS_STALE", "issuer status is stale"));
    }
    let status_reference = artifact
        .get("status_reference")
        .map(|value| {
            string(
                Some(value),
                "status_artifact.status_reference",
                "INVALID_ISSUER_STATUS",
            )
            .map(str::to_string)
        })
        .transpose()?;
    let artifact_signature = signature(
        artifact.get("signature"),
        "status_artifact.signature",
        "INVALID_ISSUER_STATUS",
    )?;
    let key = select_key(
        trusted_keys,
        &authority,
        &artifact_signature,
        issued_at,
        ISSUER_STATUS_KEY_USE,
    )?;
    let mut statement = json!({
        "context": ISSUER_STATUS_CONTEXT,
        "issuer": observed_issuer,
        "authority": authority,
        "status": status,
        "issued_at": issued_at_raw,
        "expires_at": expires_at_raw,
    });
    if let Some(reference) = &status_reference {
        statement
            .as_object_mut()
            .expect("issuer status statement is an object")
            .insert(
                "status_reference".to_string(),
                Value::String(reference.clone()),
            );
    }
    verify_signature(&statement, &artifact_signature, key)?;
    match status {
        "revoked" => return Err(error("ISSUER_REVOKED", "issuer is revoked")),
        "suspended" => return Err(error("ISSUER_SUSPENDED", "issuer is suspended")),
        _ => {}
    }
    Ok(Some(VerifiedIssuerStatus {
        issuer: observed_issuer,
        authority,
        status: status.to_string(),
        issued_at,
        expires_at,
        key_id: artifact_signature.key_id,
        status_reference,
    }))
}

pub fn verify_approval_artifact(
    approval: &Value,
    trusted_keys: &Value,
) -> Result<VerifiedApprovalArtifact, TrustArtifactVerificationError> {
    verify_approval_artifact_for_action(approval, trusted_keys, None)
}

pub fn verify_approval_artifact_for_action(
    approval: &Value,
    trusted_keys: &Value,
    expected_action_hash: Option<&ActionHashSpec>,
) -> Result<VerifiedApprovalArtifact, TrustArtifactVerificationError> {
    let artifact = object(approval, "approval", "INVALID_APPROVAL_ARTIFACT")?;
    let contract = object(
        artifact
            .get("contract")
            .ok_or_else(|| error("INVALID_APPROVAL_ARTIFACT", "contract is required"))?,
        "approval.contract",
        "INVALID_APPROVAL_ARTIFACT",
    )?;
    if contract.get("name").and_then(Value::as_str) != Some("approval_artifact")
        || contract.get("version").and_then(Value::as_str) != Some("v1")
    {
        return Err(error(
            "INVALID_APPROVAL_ARTIFACT",
            "contract must declare approval_artifact v1",
        ));
    }
    let approval_id = string(
        artifact.get("approval_id"),
        "approval.approval_id",
        "INVALID_APPROVAL_ARTIFACT",
    )?;
    let approver = party(
        artifact.get("approver"),
        "approval.approver",
        "INVALID_APPROVAL_ARTIFACT",
    )?;
    let approval_type = string(
        artifact.get("approval_type"),
        "approval.approval_type",
        "INVALID_APPROVAL_ARTIFACT",
    )?;
    let decision = string(
        artifact.get("decision"),
        "approval.decision",
        "INVALID_APPROVAL_ARTIFACT",
    )?;
    if decision != "approved" {
        return Err(error(
            "APPROVAL_NOT_GRANTED",
            "approval decision is not approved",
        ));
    }
    let parsed_action_hash = action_hash(artifact.get("action_hash"))?;
    if expected_action_hash.is_some_and(|expected| expected != &parsed_action_hash) {
        return Err(error(
            "APPROVAL_ACTION_MISMATCH",
            "approval is not bound to the expected action",
        ));
    }
    let (issued_at_raw, issued_at) = timestamp(
        artifact.get("issued_at"),
        "approval.issued_at",
        "INVALID_APPROVAL_ARTIFACT",
    )?;
    let artifact_signature = signature(
        artifact.get("signature"),
        "approval.signature",
        "INVALID_APPROVAL_ARTIFACT",
    )?;
    let key = select_key(
        trusted_keys,
        &approver,
        &artifact_signature,
        issued_at,
        APPROVAL_KEY_USE,
    )?;
    let statement = json!({
        "context": APPROVAL_CONTEXT,
        "approval_id": approval_id,
        "approver": approver,
        "approval_type": approval_type,
        "decision": decision,
        "action_hash": parsed_action_hash,
        "issued_at": issued_at_raw,
    });
    verify_signature(&statement, &artifact_signature, key)?;
    Ok(VerifiedApprovalArtifact {
        approval_id: approval_id.to_string(),
        approver,
        approval_type: approval_type.to_string(),
        decision: decision.to_string(),
        action_hash: parsed_action_hash,
        issued_at,
        key_id: artifact_signature.key_id,
    })
}
