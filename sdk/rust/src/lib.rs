mod canonical;
mod countersignature;
mod errors;
mod signers;
mod types;
mod verifier;

pub use countersignature::{
    verify_countersignature, CounterSignatureVerificationError, ReceiptDigest,
    VerifiedCounterSignature, COUNTERSIGNATURE_CONTEXT, COUNTERSIGNATURE_KEY_USE,
};
pub use errors::{VerificationError, VerificationErrorCode};
pub use signers::{
    build_local_proof_verifier,
    HmacSha256Verifier,
    SignatureVerifier,
    LOCAL_PROOF_KEY_ID,
    LOCAL_PROOF_SECRET,
};
pub use types::{
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    AudienceRef,
    Contract,
    EscrowReference,
    JsonObject,
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
pub use verifier::{
    parse_action_intent_json,
    parse_pccb_json,
    Verifier,
};
