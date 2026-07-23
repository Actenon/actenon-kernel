export type VerificationErrorCode =
  | "INVALID_INTENT"
  | "INVALID_PCCB"
  | "INVALID_CONTEXT"
  | "INVALID_TIMESTAMP"
  | "PROOF_NOT_YET_VALID"
  | "PROOF_EXPIRED"
  | "AUDIENCE_MISMATCH"
  | "SCOPE_MODE_INVALID"
  | "SCOPE_CAPABILITY_MISMATCH"
  | "INTENT_MISMATCH"
  | "TENANT_MISMATCH"
  | "SUBJECT_MISMATCH"
  | "ACTION_MISMATCH"
  | "TARGET_MISMATCH"
  | "ACTION_HASH_ALGORITHM_INVALID"
  | "ACTION_HASH_MISMATCH"
  | "SIGNATURE_INVALID";

export class VerificationError extends Error {
  readonly code: VerificationErrorCode;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: VerificationErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "VerificationError";
    this.code = code;
    this.details = details;
  }
}
