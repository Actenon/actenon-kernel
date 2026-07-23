package verifier

import "errors"

type VerificationErrorCode string

const (
	ErrInvalidIntent             VerificationErrorCode = "INVALID_INTENT"
	ErrInvalidPCCB              VerificationErrorCode = "INVALID_PCCB"
	ErrInvalidContext           VerificationErrorCode = "INVALID_CONTEXT"
	ErrInvalidTimestamp         VerificationErrorCode = "INVALID_TIMESTAMP"
	ErrProofNotYetValid         VerificationErrorCode = "PROOF_NOT_YET_VALID"
	ErrProofExpired             VerificationErrorCode = "PROOF_EXPIRED"
	ErrAudienceMismatch         VerificationErrorCode = "AUDIENCE_MISMATCH"
	ErrScopeModeInvalid         VerificationErrorCode = "SCOPE_MODE_INVALID"
	ErrScopeCapabilityMismatch  VerificationErrorCode = "SCOPE_CAPABILITY_MISMATCH"
	ErrIntentMismatch           VerificationErrorCode = "INTENT_MISMATCH"
	ErrTenantMismatch           VerificationErrorCode = "TENANT_MISMATCH"
	ErrSubjectMismatch          VerificationErrorCode = "SUBJECT_MISMATCH"
	ErrActionMismatch           VerificationErrorCode = "ACTION_MISMATCH"
	ErrTargetMismatch           VerificationErrorCode = "TARGET_MISMATCH"
	ErrActionHashAlgorithmInvalid VerificationErrorCode = "ACTION_HASH_ALGORITHM_INVALID"
	ErrActionHashMismatch       VerificationErrorCode = "ACTION_HASH_MISMATCH"
	ErrSignatureInvalid         VerificationErrorCode = "SIGNATURE_INVALID"
)

type VerificationError struct {
	Code    VerificationErrorCode
	Message string
	Details map[string]any
}

func (e *VerificationError) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code) + ": " + e.Message
}

func (e *VerificationError) Is(target error) bool {
	other, ok := target.(*VerificationError)
	if !ok {
		return false
	}
	return e.Code == other.Code
}

func newVerificationError(code VerificationErrorCode, message string, details map[string]any) *VerificationError {
	return &VerificationError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

func IsVerificationErrorCode(err error, code VerificationErrorCode) bool {
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) {
		return false
	}
	return verificationErr.Code == code
}
