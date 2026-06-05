use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;


pub type JsonObject = Map<String, Value>;

fn map_is_empty(value: &JsonObject) -> bool {
    value.is_empty()
}

fn vec_is_empty<T>(value: &[T]) -> bool {
    value.is_empty()
}

fn option_is_none<T>(value: &Option<T>) -> bool {
    value.is_none()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TenantRef {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub attributes: JsonObject,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartyRef {
    #[serde(rename = "type")]
    pub r#type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub attributes: JsonObject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudienceRef {
    #[serde(rename = "type")]
    pub r#type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "option_is_none")]
    pub uri: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionSpec {
    pub name: String,
    pub capability: String,
    pub parameters: JsonObject,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub constraints: JsonObject,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub scope: JsonObject,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TargetRef {
    pub resource_type: String,
    pub resource_id: String,
    #[serde(default, skip_serializing_if = "option_is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub selectors: JsonObject,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScopeSpec {
    pub mode: String,
    pub capabilities: Vec<String>,
    pub single_use: bool,
    #[serde(default, skip_serializing_if = "vec_is_empty")]
    pub resource_selectors: Vec<JsonObject>,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub parameter_constraints: JsonObject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionHashSpec {
    pub algorithm: String,
    pub canonicalization: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowReference {
    pub escrow_id: String,
    #[serde(default, skip_serializing_if = "option_is_none")]
    pub single_use: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSpec {
    pub algorithm: String,
    pub key_id: String,
    pub encoding: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionIntent {
    pub contract: Contract,
    pub intent_id: String,
    #[serde(default, skip_serializing_if = "option_is_none")]
    pub idempotency_key: Option<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub tenant: TenantRef,
    pub requester: PartyRef,
    pub action: ActionSpec,
    pub target: TargetRef,
    #[serde(default, skip_serializing_if = "option_is_none")]
    pub justification: Option<String>,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub context: JsonObject,
    #[serde(default, skip_serializing_if = "vec_is_empty")]
    pub evidence_refs: Vec<JsonObject>,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub metadata: JsonObject,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub extensions: JsonObject,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PCCB {
    pub contract: Contract,
    pub pccb_id: String,
    #[serde(default, skip_serializing_if = "option_is_none")]
    pub intent_id: Option<String>,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub issuer: PartyRef,
    pub subject: PartyRef,
    pub tenant: TenantRef,
    pub audience: AudienceRef,
    pub action: ActionSpec,
    pub target: TargetRef,
    pub scope: ScopeSpec,
    pub nonce: String,
    pub action_hash: ActionHashSpec,
    #[serde(default, skip_serializing_if = "option_is_none")]
    pub escrow_reference: Option<EscrowReference>,
    pub signature: SignatureSpec,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub extensions: JsonObject,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationContextInput {
    pub request_id: String,
    pub audience: AudienceRef,
    pub now: OffsetDateTime,
    pub scope_capabilities: Vec<String>,
    pub parameter_constraints: JsonObject,
    pub resource_selectors: Vec<JsonObject>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationContext {
    pub request_id: String,
    pub audience: AudienceRef,
    pub now: OffsetDateTime,
    pub scope_capabilities: Vec<String>,
    pub parameter_constraints: JsonObject,
    pub resource_selectors: Vec<JsonObject>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedProtectedRequest {
    pub intent: ActionIntent,
    pub pccb: PCCB,
    pub context: VerificationContext,
}
