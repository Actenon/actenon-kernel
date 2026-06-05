use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::types::SignatureSpec;


type HmacSha256 = Hmac<Sha256>;

pub const LOCAL_PROOF_KEY_ID: &str = "local-proof-v1";
pub const LOCAL_PROOF_SECRET: &str = "actenon-local-proof-secret-v1";

pub trait SignatureVerifier {
    fn verify(&self, payload: &[u8], signature: &SignatureSpec) -> bool;
}

#[derive(Clone, Debug)]
pub struct HmacSha256Verifier {
    secret: Vec<u8>,
    key_id: String,
    algorithm: String,
}

impl HmacSha256Verifier {
    pub fn new(secret: impl Into<Vec<u8>>, key_id: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            key_id: key_id.into(),
            algorithm: "HS256".to_string(),
        }
    }
}

impl SignatureVerifier for HmacSha256Verifier {
    fn verify(&self, payload: &[u8], signature: &SignatureSpec) -> bool {
        if signature.algorithm != self.algorithm
            || signature.key_id != self.key_id
            || signature.encoding != "base64url"
        {
            return false;
        }

        let provided = match URL_SAFE_NO_PAD.decode(signature.value.as_bytes()) {
            Ok(value) => value,
            Err(_) => return false,
        };

        let mut mac = match HmacSha256::new_from_slice(&self.secret) {
            Ok(value) => value,
            Err(_) => return false,
        };
        mac.update(payload);
        mac.verify_slice(&provided).is_ok()
    }
}

pub fn build_local_proof_verifier() -> HmacSha256Verifier {
    HmacSha256Verifier::new(LOCAL_PROOF_SECRET.as_bytes().to_vec(), LOCAL_PROOF_KEY_ID)
}
