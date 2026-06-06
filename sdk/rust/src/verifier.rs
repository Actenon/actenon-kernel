use serde::de::DeserializeOwned;
use serde_json::{json, Deserializer, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::canonical::{canonicalize_bytes, sha256_hex};
use crate::errors::{VerificationError, VerificationErrorCode};
use crate::signers::SignatureVerifier;
use crate::types::{
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
    VerificationContext,
    VerificationContextInput,
    VerifiedProtectedRequest,
};

pub const DEFAULT_CLOCK_SKEW_TOLERANCE: Duration = Duration::ZERO;

pub fn parse_action_intent_json(raw: &[u8]) -> Result<ActionIntent, VerificationError> {
    let intent: ActionIntent = decode_json(raw, VerificationErrorCode::InvalidIntent, "action intent")?;
    normalize_action_intent(intent)
}

pub fn parse_pccb_json(raw: &[u8]) -> Result<PCCB, VerificationError> {
    let pccb: PCCB = decode_json(raw, VerificationErrorCode::InvalidPccb, "pccb")?;
    normalize_pccb(pccb)
}

pub struct Verifier<V: SignatureVerifier> {
    signature_verifier: V,
    clock_skew_tolerance: Duration,
}

impl<V: SignatureVerifier> Verifier<V> {
    pub fn new(signature_verifier: V) -> Self {
        Self {
            signature_verifier,
            clock_skew_tolerance: DEFAULT_CLOCK_SKEW_TOLERANCE,
        }
    }

    pub fn with_clock_skew_tolerance(
        mut self,
        tolerance: Duration,
    ) -> Result<Self, VerificationError> {
        if tolerance.is_negative() {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidContext,
                "clock skew tolerance must be non-negative.",
            ));
        }
        self.clock_skew_tolerance = tolerance;
        Ok(self)
    }

    pub fn parse_action_intent_json(&self, raw: &[u8]) -> Result<ActionIntent, VerificationError> {
        parse_action_intent_json(raw)
    }

    pub fn parse_pccb_json(&self, raw: &[u8]) -> Result<PCCB, VerificationError> {
        parse_pccb_json(raw)
    }

    pub fn build_context(
        &self,
        input: VerificationContextInput,
    ) -> Result<VerificationContext, VerificationError> {
        normalize_context(input)
    }

    pub fn verify(
        &self,
        intent: ActionIntent,
        pccb: PCCB,
        context: VerificationContext,
    ) -> Result<VerifiedProtectedRequest, VerificationError> {
        let normalized_intent = normalize_action_intent(intent)?;
        let normalized_pccb = normalize_pccb(pccb)?;
        let normalized_context = normalize_context(VerificationContextInput {
            request_id: context.request_id,
            audience: context.audience,
            now: context.now,
            scope_capabilities: context.scope_capabilities,
            parameter_constraints: context.parameter_constraints,
            resource_selectors: context.resource_selectors,
        })?;

        let not_before = parse_timestamp(
            &normalized_pccb.not_before,
            "pccb.not_before",
            VerificationErrorCode::InvalidPccb,
        )?;
        let expires_at = parse_timestamp(
            &normalized_pccb.expires_at,
            "pccb.expires_at",
            VerificationErrorCode::InvalidPccb,
        )?;

        if normalized_context.now + self.clock_skew_tolerance < not_before {
            return Err(VerificationError::new(
                VerificationErrorCode::ProofNotYetValid,
                "The proof is not yet valid.",
            ));
        }
        if normalized_context.now - self.clock_skew_tolerance > expires_at {
            return Err(VerificationError::new(
                VerificationErrorCode::ProofExpired,
                "The proof has expired.",
            ));
        }
        if normalized_pccb.audience != normalized_context.audience {
            return Err(VerificationError::new(
                VerificationErrorCode::AudienceMismatch,
                "The proof audience does not match this endpoint.",
            ));
        }
        if normalized_pccb.scope.mode != "exact" {
            return Err(VerificationError::new(
                VerificationErrorCode::ScopeModeInvalid,
                "The proof scope mode is not supported.",
            ));
        }
        if !normalized_pccb
            .scope
            .capabilities
            .iter()
            .any(|capability| capability == &normalized_intent.action.capability)
        {
            return Err(VerificationError::new(
                VerificationErrorCode::ScopeCapabilityMismatch,
                "The proof scope does not allow this capability.",
            ));
        }
        if normalized_pccb.intent_id.as_deref().is_some()
            && normalized_pccb.intent_id.as_deref() != Some(normalized_intent.intent_id.as_str())
        {
            return Err(VerificationError::new(
                VerificationErrorCode::IntentMismatch,
                "The proof does not match the supplied action intent.",
            ));
        }
        if normalized_pccb.tenant != normalized_intent.tenant {
            return Err(VerificationError::new(
                VerificationErrorCode::TenantMismatch,
                "The proof tenant does not match the action intent.",
            ));
        }
        if normalized_pccb.subject != normalized_intent.requester {
            return Err(VerificationError::new(
                VerificationErrorCode::SubjectMismatch,
                "The proof subject does not match the action intent.",
            ));
        }
        if normalized_pccb.action != normalized_intent.action {
            return Err(VerificationError::new(
                VerificationErrorCode::ActionMismatch,
                "The proof action does not exactly match the action intent.",
            ));
        }
        if normalized_pccb.target != normalized_intent.target {
            return Err(VerificationError::new(
                VerificationErrorCode::TargetMismatch,
                "The proof target does not exactly match the action intent.",
            ));
        }
        if normalized_pccb.action_hash.algorithm != "sha-256"
            || normalized_pccb.action_hash.canonicalization != "RFC8785-JCS"
        {
            return Err(VerificationError::new(
                VerificationErrorCode::ActionHashAlgorithmInvalid,
                "The proof action hash metadata is invalid.",
            ));
        }

        let expected_hash =
            sha256_hex(&build_action_hash_input(&normalized_intent)).map_err(|_error| {
                VerificationError::new(
                    VerificationErrorCode::InvalidIntent,
                    "The action intent cannot be canonicalized for verification.",
                )
            })?;
        if normalized_pccb.action_hash.value != expected_hash {
            return Err(VerificationError::new(
                VerificationErrorCode::ActionHashMismatch,
                "The proof action hash does not match the action intent.",
            ));
        }

        let unsigned_payload = canonicalize_bytes(&build_unsigned_pccb_payload(&normalized_pccb))
            .map_err(|_error| {
                VerificationError::new(
                    VerificationErrorCode::InvalidPccb,
                    "The proof cannot be canonicalized for signature verification.",
                )
            })?;
        if !self
            .signature_verifier
            .verify(&unsigned_payload, &normalized_pccb.signature)
        {
            return Err(VerificationError::new(
                VerificationErrorCode::SignatureInvalid,
                "The proof signature could not be verified.",
            ));
        }

        Ok(VerifiedProtectedRequest {
            intent: normalized_intent,
            pccb: normalized_pccb,
            context: normalized_context,
        })
    }

    pub fn verify_json(
        &self,
        intent_raw: &[u8],
        pccb_raw: &[u8],
        context: VerificationContext,
    ) -> Result<VerifiedProtectedRequest, VerificationError> {
        let intent = self.parse_action_intent_json(intent_raw)?;
        let pccb = self.parse_pccb_json(pccb_raw)?;
        self.verify(intent, pccb, context)
    }
}

fn decode_json<T: DeserializeOwned>(
    raw: &[u8],
    code: VerificationErrorCode,
    artifact_name: &str,
) -> Result<T, VerificationError> {
    let mut deserializer = Deserializer::from_slice(raw);
    let value = T::deserialize(&mut deserializer).map_err(|_error| {
        VerificationError::new(
            code,
            format!("failed to decode {artifact_name} JSON payload."),
        )
    })?;
    deserializer.end().map_err(|_error| {
        VerificationError::new(
            code,
            format!("{artifact_name} JSON payload must contain a single top-level object."),
        )
    })?;
    Ok(value)
}

fn require_non_empty(
    value: &str,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<(), VerificationError> {
    if value.trim().is_empty() {
        return Err(VerificationError::new(
            code,
            format!("{field_name} must be a non-empty string."),
        ));
    }
    Ok(())
}

fn parse_timestamp(
    raw: &str,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<OffsetDateTime, VerificationError> {
    if raw.trim().is_empty() {
        return Err(VerificationError::new(
            code,
            format!("{field_name} must be an RFC3339 timestamp string."),
        ));
    }
    OffsetDateTime::parse(raw, &Rfc3339)
        .map(|value| value.to_offset(UtcOffset::UTC))
        .map_err(|_error| {
            VerificationError::new(
                VerificationErrorCode::InvalidTimestamp,
                format!("{field_name} must be an RFC3339 timestamp string."),
            )
        })
}

fn normalize_timestamp(
    raw: &str,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<String, VerificationError> {
    let parsed = parse_timestamp(raw, field_name, code)?;
    parsed.format(&Rfc3339).map_err(|_error| {
        VerificationError::new(
            code,
            format!("{field_name} must be an RFC3339 timestamp string."),
        )
    })
}

fn normalize_action_intent(intent: ActionIntent) -> Result<ActionIntent, VerificationError> {
    if intent.contract.name != "action_intent" || intent.contract.version != "v1" {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidIntent,
            "contract must declare action_intent v1.",
        ));
    }
    require_non_empty(
        &intent.intent_id,
        "action_intent.intent_id",
        VerificationErrorCode::InvalidIntent,
    )?;
    let tenant = normalize_tenant_ref(
        intent.tenant,
        "action_intent.tenant",
        VerificationErrorCode::InvalidIntent,
    )?;
    let requester = normalize_party_ref(
        intent.requester,
        "action_intent.requester",
        VerificationErrorCode::InvalidIntent,
    )?;
    let action = normalize_action_spec(
        intent.action,
        "action_intent.action",
        VerificationErrorCode::InvalidIntent,
    )?;
    let target = normalize_target_ref(
        intent.target,
        "action_intent.target",
        VerificationErrorCode::InvalidIntent,
    )?;

    Ok(ActionIntent {
        contract: crate::types::Contract {
            name: "action_intent".to_string(),
            version: "v1".to_string(),
        },
        intent_id: intent.intent_id,
        idempotency_key: intent.idempotency_key,
        issued_at: normalize_timestamp(
            &intent.issued_at,
            "action_intent.issued_at",
            VerificationErrorCode::InvalidIntent,
        )?,
        expires_at: normalize_timestamp(
            &intent.expires_at,
            "action_intent.expires_at",
            VerificationErrorCode::InvalidIntent,
        )?,
        tenant,
        requester,
        action,
        target,
        justification: intent.justification,
        context: intent.context,
        evidence_refs: intent.evidence_refs,
        metadata: intent.metadata,
        extensions: intent.extensions,
    })
}

fn normalize_pccb(pccb: PCCB) -> Result<PCCB, VerificationError> {
    if pccb.contract.name != "pccb" || pccb.contract.version != "v1" {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidPccb,
            "contract must declare pccb v1.",
        ));
    }
    require_non_empty(
        &pccb.pccb_id,
        "pccb.pccb_id",
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(&pccb.nonce, "pccb.nonce", VerificationErrorCode::InvalidPccb)?;

    Ok(PCCB {
        contract: crate::types::Contract {
            name: "pccb".to_string(),
            version: "v1".to_string(),
        },
        pccb_id: pccb.pccb_id,
        intent_id: pccb.intent_id,
        issued_at: normalize_timestamp(
            &pccb.issued_at,
            "pccb.issued_at",
            VerificationErrorCode::InvalidPccb,
        )?,
        not_before: normalize_timestamp(
            &pccb.not_before,
            "pccb.not_before",
            VerificationErrorCode::InvalidPccb,
        )?,
        expires_at: normalize_timestamp(
            &pccb.expires_at,
            "pccb.expires_at",
            VerificationErrorCode::InvalidPccb,
        )?,
        issuer: normalize_party_ref(
            pccb.issuer,
            "pccb.issuer",
            VerificationErrorCode::InvalidPccb,
        )?,
        subject: normalize_party_ref(
            pccb.subject,
            "pccb.subject",
            VerificationErrorCode::InvalidPccb,
        )?,
        tenant: normalize_tenant_ref(
            pccb.tenant,
            "pccb.tenant",
            VerificationErrorCode::InvalidPccb,
        )?,
        audience: normalize_audience_ref(
            pccb.audience,
            "pccb.audience",
            VerificationErrorCode::InvalidPccb,
        )?,
        action: normalize_action_spec(
            pccb.action,
            "pccb.action",
            VerificationErrorCode::InvalidPccb,
        )?,
        target: normalize_target_ref(
            pccb.target,
            "pccb.target",
            VerificationErrorCode::InvalidPccb,
        )?,
        scope: normalize_scope_spec(pccb.scope, "pccb.scope")?,
        nonce: pccb.nonce,
        action_hash: normalize_action_hash_spec(pccb.action_hash, "pccb.action_hash")?,
        escrow_reference: normalize_escrow_reference(pccb.escrow_reference),
        signature: normalize_signature_spec(pccb.signature, "pccb.signature")?,
        extensions: pccb.extensions,
    })
}

fn normalize_context(input: VerificationContextInput) -> Result<VerificationContext, VerificationError> {
    require_non_empty(
        &input.request_id,
        "context.request_id",
        VerificationErrorCode::InvalidContext,
    )?;
    let mut capabilities = input.scope_capabilities;
    if capabilities.is_empty() {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidContext,
            "context.scope_capabilities must contain at least one capability.",
        ));
    }
    capabilities.sort();

    Ok(VerificationContext {
        request_id: input.request_id,
        audience: normalize_audience_ref(
            input.audience,
            "context.audience",
            VerificationErrorCode::InvalidContext,
        )?,
        now: input.now.to_offset(UtcOffset::UTC),
        scope_capabilities: capabilities,
        parameter_constraints: input.parameter_constraints,
        resource_selectors: input.resource_selectors,
    })
}

fn normalize_tenant_ref(
    tenant: TenantRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<TenantRef, VerificationError> {
    require_non_empty(&tenant.tenant_id, &format!("{field_name}.tenant_id"), code)?;
    Ok(tenant)
}

fn normalize_party_ref(
    party: PartyRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<PartyRef, VerificationError> {
    require_non_empty(&party.r#type, &format!("{field_name}.type"), code)?;
    require_non_empty(&party.id, &format!("{field_name}.id"), code)?;
    Ok(party)
}

fn normalize_audience_ref(
    audience: AudienceRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<AudienceRef, VerificationError> {
    require_non_empty(&audience.r#type, &format!("{field_name}.type"), code)?;
    require_non_empty(&audience.id, &format!("{field_name}.id"), code)?;
    Ok(audience)
}

fn normalize_action_spec(
    action: ActionSpec,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<ActionSpec, VerificationError> {
    require_non_empty(&action.name, &format!("{field_name}.name"), code)?;
    require_non_empty(&action.capability, &format!("{field_name}.capability"), code)?;
    Ok(action)
}

fn normalize_target_ref(
    target: TargetRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<TargetRef, VerificationError> {
    require_non_empty(&target.resource_type, &format!("{field_name}.resource_type"), code)?;
    require_non_empty(&target.resource_id, &format!("{field_name}.resource_id"), code)?;
    Ok(target)
}

fn normalize_scope_spec(scope: ScopeSpec, field_name: &str) -> Result<ScopeSpec, VerificationError> {
    if scope.mode != "exact" {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidPccb,
            format!("{field_name}.mode must be 'exact'."),
        ));
    }
    if scope.capabilities.is_empty() {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidPccb,
            format!("{field_name}.capabilities must contain at least one capability."),
        ));
    }

    let mut capabilities = scope.capabilities;
    capabilities.sort();

    Ok(ScopeSpec {
        mode: scope.mode,
        capabilities,
        single_use: scope.single_use,
        resource_selectors: scope.resource_selectors,
        parameter_constraints: scope.parameter_constraints,
    })
}

fn normalize_action_hash_spec(
    action_hash: crate::types::ActionHashSpec,
    field_name: &str,
) -> Result<crate::types::ActionHashSpec, VerificationError> {
    require_non_empty(
        &action_hash.algorithm,
        &format!("{field_name}.algorithm"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &action_hash.canonicalization,
        &format!("{field_name}.canonicalization"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &action_hash.value,
        &format!("{field_name}.value"),
        VerificationErrorCode::InvalidPccb,
    )?;
    Ok(action_hash)
}

fn normalize_signature_spec(
    signature: SignatureSpec,
    field_name: &str,
) -> Result<SignatureSpec, VerificationError> {
    require_non_empty(
        &signature.algorithm,
        &format!("{field_name}.algorithm"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &signature.key_id,
        &format!("{field_name}.key_id"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &signature.encoding,
        &format!("{field_name}.encoding"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &signature.value,
        &format!("{field_name}.value"),
        VerificationErrorCode::InvalidPccb,
    )?;
    Ok(signature)
}

fn normalize_escrow_reference(
    reference: Option<crate::types::EscrowReference>,
) -> Option<crate::types::EscrowReference> {
    reference.and_then(|value| {
        if value.escrow_id.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn build_action_hash_input(intent: &ActionIntent) -> Value {
    json!({
        "intent_id": intent.intent_id,
        "tenant": intent.tenant,
        "requester": intent.requester,
        "action": intent.action,
        "target": intent.target,
        "issued_at": intent.issued_at,
        "expires_at": intent.expires_at,
    })
}

fn build_unsigned_pccb_payload(pccb: &PCCB) -> Value {
    let mut payload = json!({
        "contract": {"name": "pccb", "version": "v1"},
        "pccb_id": pccb.pccb_id,
        "issued_at": pccb.issued_at,
        "not_before": pccb.not_before,
        "expires_at": pccb.expires_at,
        "issuer": pccb.issuer,
        "subject": pccb.subject,
        "tenant": pccb.tenant,
        "audience": pccb.audience,
        "action": pccb.action,
        "target": pccb.target,
        "scope": pccb.scope,
        "nonce": pccb.nonce,
        "action_hash": pccb.action_hash,
    });

    if let Some(intent_id) = &pccb.intent_id {
        if let Value::Object(ref mut map) = payload {
            map.insert("intent_id".to_string(), Value::String(intent_id.clone()));
        }
    }
    if let Some(reference) = &pccb.escrow_reference {
        if let Value::Object(ref mut map) = payload {
            map.insert(
                "escrow_reference".to_string(),
                json!({
                    "escrow_id": reference.escrow_id,
                    "single_use": pccb.scope.single_use,
                }),
            );
        }
    }
    if !pccb.extensions.is_empty() {
        if let Value::Object(ref mut map) = payload {
            map.insert(
                "extensions".to_string(),
                Value::Object(pccb.extensions.clone()),
            );
        }
    }

    payload
}
