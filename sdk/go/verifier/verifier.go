package verifier

import "time"

const DefaultClockSkewTolerance time.Duration = 0

type Verifier struct {
        signatureVerifier  SignatureVerifier
        clockSkewTolerance time.Duration
}

type VerifierOption func(*Verifier)

func WithClockSkewTolerance(tolerance time.Duration) VerifierOption {
        return func(v *Verifier) {
                v.clockSkewTolerance = tolerance
        }
}

func NewVerifier(signatureVerifier SignatureVerifier, options ...VerifierOption) *Verifier {
        v := &Verifier{
                signatureVerifier:  signatureVerifier,
                clockSkewTolerance: DefaultClockSkewTolerance,
        }
        for _, option := range options {
                option(v)
        }
        return v
}

func (v *Verifier) Verify(intent ActionIntent, pccb PCCB, context VerificationContext) (VerifiedProtectedRequest, error) {
        normalizedIntent, err := normalizeActionIntent(intent)
        if err != nil {
                return VerifiedProtectedRequest{}, err
        }
        normalizedPCCB, err := normalizePCCB(pccb)
        if err != nil {
                return VerifiedProtectedRequest{}, err
        }
        normalizedContext, err := normalizeVerificationContext(context)
        if err != nil {
                return VerifiedProtectedRequest{}, err
        }

        notBefore, err := parseTimestamp(normalizedPCCB.NotBefore, "pccb.not_before", ErrInvalidPCCB)
        if err != nil {
                return VerifiedProtectedRequest{}, err
        }
        expiresAt, err := parseTimestamp(normalizedPCCB.ExpiresAt, "pccb.expires_at", ErrInvalidPCCB)
        if err != nil {
                return VerifiedProtectedRequest{}, err
        }

        if v.clockSkewTolerance < 0 {
                return VerifiedProtectedRequest{}, newVerificationError(ErrInvalidContext, "clock skew tolerance must be non-negative.", nil)
        }
        if normalizedContext.Now.Add(v.clockSkewTolerance).Before(notBefore) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrProofNotYetValid, "The proof is not yet valid.", nil)
        }
        if normalizedContext.Now.Add(-v.clockSkewTolerance).After(expiresAt) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrProofExpired, "The proof has expired.", nil)
        }

        // ── Signature verification (before semantic checks) ──────────────
        // Security principle: verify cryptographic integrity BEFORE interpreting
        // semantic fields. Any mutation to the signed PCCB payload (scope,
        // action_hash, etc.) must produce SIGNATURE_INVALID, not a semantic
        // mismatch error. This matches the Python reference verifier (steps 4-5
        // in PCCBVerifier.verify) and the conformance vector expectations.
        unsignedPayload, err := canonicalizeBytes(normalizedUnsignedPCCBPayload(normalizedPCCB))
        if err != nil {
                return VerifiedProtectedRequest{}, newVerificationError(
                        ErrInvalidPCCB,
                        "The proof cannot be canonicalized for signature verification.",
                        nil,
                )
        }
        if v.signatureVerifier == nil || !v.signatureVerifier.Verify(unsignedPayload, normalizedPCCB.Signature) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrSignatureInvalid, "The proof signature could not be verified.", nil)
        }

        // ── Semantic checks (after signature is verified) ────────────────
        if !normalizedEqual(normalizedPCCB.Audience, normalizedContext.Audience) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrAudienceMismatch, "The proof audience does not match this endpoint.", nil)
        }
        if normalizedPCCB.Scope.Mode != "exact" {
                return VerifiedProtectedRequest{}, newVerificationError(ErrScopeModeInvalid, "The proof scope mode is not supported.", nil)
        }
        if !containsString(normalizedPCCB.Scope.Capabilities, normalizedIntent.Action.Capability) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrScopeCapabilityMismatch, "The proof scope does not allow this capability.", nil)
        }
        if normalizedPCCB.IntentID != "" && normalizedPCCB.IntentID != normalizedIntent.IntentID {
                return VerifiedProtectedRequest{}, newVerificationError(ErrIntentMismatch, "The proof does not match the supplied action intent.", nil)
        }
        if !normalizedEqual(normalizedPCCB.Tenant, normalizedIntent.Tenant) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrTenantMismatch, "The proof tenant does not match the action intent.", nil)
        }
        if !normalizedEqual(normalizedPCCB.Subject, normalizedIntent.Requester) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrSubjectMismatch, "The proof subject does not match the action intent.", nil)
        }
        if !normalizedEqual(normalizedPCCB.Action, normalizedIntent.Action) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrActionMismatch, "The proof action does not exactly match the action intent.", nil)
        }
        if !normalizedEqual(normalizedPCCB.Target, normalizedIntent.Target) {
                return VerifiedProtectedRequest{}, newVerificationError(ErrTargetMismatch, "The proof target does not exactly match the action intent.", nil)
        }
        if normalizedPCCB.ActionHash.Algorithm != "sha-256" || normalizedPCCB.ActionHash.Canonicalization != "RFC8785-JCS" {
                return VerifiedProtectedRequest{}, newVerificationError(ErrActionHashAlgorithmInvalid, "The proof action hash metadata is invalid.", nil)
        }

        expectedHash, err := sha256Hex(normalizedIntentActionHashInput(normalizedIntent))
        if err != nil {
                return VerifiedProtectedRequest{}, newVerificationError(
                        ErrInvalidIntent,
                        "The action intent cannot be canonicalized for verification.",
                        nil,
                )
        }
        if normalizedPCCB.ActionHash.Value != expectedHash {
                return VerifiedProtectedRequest{}, newVerificationError(ErrActionHashMismatch, "The proof action hash does not match the action intent.", nil)
        }

        return VerifiedProtectedRequest{
                Intent:  normalizedIntent,
                PCCB:    normalizedPCCB,
                Context: normalizedContext,
        }, nil
}

func (v *Verifier) VerifyJSON(intentRaw []byte, pccbRaw []byte, context VerificationContext) (VerifiedProtectedRequest, error) {
        intent, err := ParseActionIntentJSON(intentRaw)
        if err != nil {
                return VerifiedProtectedRequest{}, err
        }
        pccb, err := ParsePCCBJSON(pccbRaw)
        if err != nil {
                return VerifiedProtectedRequest{}, err
        }
        return v.Verify(intent, pccb, context)
}
