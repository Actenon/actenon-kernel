export { canonicalizeBytes, canonicalizeJson, sha256Hex } from "./canonical.js";
export {
  CounterSignatureVerificationError,
  verifyCountersignature,
  verify_countersignature,
} from "./countersignature.js";
export { VerificationError } from "./errors.js";
export { buildLocalProofVerifier, HmacSha256Verifier, LOCAL_PROOF_KEY_ID, LOCAL_PROOF_SECRET } from "./signers.js";
export { VerifierSDK } from "./verifier.js";
export type { SignatureVerifier } from "./signers.js";
export type { VerifierSDKOptions } from "./verifier.js";
export type {
  CounterSignatureVerificationErrorCode,
  ReceiptDigest,
  VerifiedCounterSignature,
} from "./countersignature.js";
export type {
  ActionHashSpec,
  ActionIntent,
  ActionSpec,
  AudienceRef,
  JsonScalar,
  JsonValue,
  PCCB,
  ScopeSpec,
  SignatureSpec,
  TargetRef,
  TenantRef,
  VerificationContext,
  VerifiedProtectedRequest,
} from "./types.js";
