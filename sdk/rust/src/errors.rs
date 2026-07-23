use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationErrorCode {
    InvalidIntent,
    InvalidPccb,
    InvalidContext,
    InvalidTimestamp,
    ProofNotYetValid,
    ProofExpired,
    AudienceMismatch,
    ScopeModeInvalid,
    ScopeCapabilityMismatch,
    IntentMismatch,
    TenantMismatch,
    SubjectMismatch,
    ActionMismatch,
    TargetMismatch,
    ActionHashAlgorithmInvalid,
    ActionHashMismatch,
    SignatureInvalid,
}

impl VerificationErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidIntent => "INVALID_INTENT",
            Self::InvalidPccb => "INVALID_PCCB",
            Self::InvalidContext => "INVALID_CONTEXT",
            Self::InvalidTimestamp => "INVALID_TIMESTAMP",
            Self::ProofNotYetValid => "PROOF_NOT_YET_VALID",
            Self::ProofExpired => "PROOF_EXPIRED",
            Self::AudienceMismatch => "AUDIENCE_MISMATCH",
            Self::ScopeModeInvalid => "SCOPE_MODE_INVALID",
            Self::ScopeCapabilityMismatch => "SCOPE_CAPABILITY_MISMATCH",
            Self::IntentMismatch => "INTENT_MISMATCH",
            Self::TenantMismatch => "TENANT_MISMATCH",
            Self::SubjectMismatch => "SUBJECT_MISMATCH",
            Self::ActionMismatch => "ACTION_MISMATCH",
            Self::TargetMismatch => "TARGET_MISMATCH",
            Self::ActionHashAlgorithmInvalid => "ACTION_HASH_ALGORITHM_INVALID",
            Self::ActionHashMismatch => "ACTION_HASH_MISMATCH",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
        }
    }
}

impl fmt::Display for VerificationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationError {
    code: VerificationErrorCode,
    message: String,
    details: Option<BTreeMap<String, String>>,
}

impl VerificationError {
    pub fn new(code: VerificationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(
        code: VerificationErrorCode,
        message: impl Into<String>,
        details: BTreeMap<String, String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            details: Some(details),
        }
    }

    pub fn code(&self) -> VerificationErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn details(&self) -> Option<&BTreeMap<String, String>> {
        self.details.as_ref()
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl Error for VerificationError {}
