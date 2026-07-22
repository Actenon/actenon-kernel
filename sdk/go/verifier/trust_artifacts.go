package verifier

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

const (
	IssuerStatusContext = "actenon.issuer-status.v1"
	IssuerStatusKeyUse  = "issuer_status"
	ApprovalContext     = "actenon.approval-artifact.v1"
	ApprovalKeyUse      = "approval_artifact"
)

type TrustArtifactVerificationError struct {
	Code    string
	Message string
}

func (e *TrustArtifactVerificationError) Error() string {
	return e.Code + ": " + e.Message
}

type IssuerStatusArtifact struct {
	Contract        Contract      `json:"contract"`
	Issuer          PartyRef      `json:"issuer"`
	Authority       PartyRef      `json:"authority"`
	Status          string        `json:"status"`
	IssuedAt        string        `json:"issued_at"`
	ExpiresAt       string        `json:"expires_at"`
	StatusReference string        `json:"status_reference,omitempty"`
	Signature       SignatureSpec `json:"signature"`
}

type ApprovalArtifact struct {
	Contract     Contract       `json:"contract"`
	ApprovalID   string         `json:"approval_id"`
	Approver     PartyRef       `json:"approver"`
	ApprovalType string         `json:"approval_type"`
	Decision     string         `json:"decision"`
	ActionHash   ActionHashSpec `json:"action_hash"`
	IssuedAt     string         `json:"issued_at"`
	Signature    SignatureSpec  `json:"signature"`
}

type VerifiedIssuerStatus struct {
	Issuer          PartyRef
	Authority       PartyRef
	Status          string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	KeyID           string
	StatusReference string
}

type VerifiedApprovalArtifact struct {
	ApprovalID   string
	Approver     PartyRef
	ApprovalType string
	Decision     string
	ActionHash   ActionHashSpec
	IssuedAt     time.Time
	KeyID        string
}

type IssuerStatusOptions struct {
	MaxAge       time.Duration
	StatusPolicy string
}

func trustArtifactError(code string, message string) error {
	return &TrustArtifactVerificationError{Code: code, Message: message}
}

func ParseIssuerStatusJSON(raw []byte) (IssuerStatusArtifact, error) {
	var artifact IssuerStatusArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return artifact, trustArtifactError("INVALID_ISSUER_STATUS", "issuer status must be valid JSON")
	}
	return artifact, nil
}

func ParseApprovalArtifactJSON(raw []byte) (ApprovalArtifact, error) {
	var artifact ApprovalArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return artifact, trustArtifactError("INVALID_APPROVAL_ARTIFACT", "approval must be valid JSON")
	}
	return artifact, nil
}

func VerifyIssuerStatus(
	issuer PartyRef,
	statusArtifact *IssuerStatusArtifact,
	trustedKeys *TrustedCounterSignatureKeys,
	now time.Time,
	options ...IssuerStatusOptions,
) (VerifiedIssuerStatus, error) {
	config := IssuerStatusOptions{MaxAge: time.Hour, StatusPolicy: "required"}
	if len(options) > 1 {
		return VerifiedIssuerStatus{}, fmt.Errorf("only one IssuerStatusOptions value is supported")
	}
	if len(options) == 1 {
		config = options[0]
		if config.MaxAge == 0 {
			config.MaxAge = time.Hour
		}
		if config.StatusPolicy == "" {
			config.StatusPolicy = "required"
		}
	}
	if config.StatusPolicy == "disabled" {
		log.Printf("Actenon: issuer-status verification DISABLED — revoked or stale issuers may be accepted.")
		return VerifiedIssuerStatus{}, nil
	}
	if config.StatusPolicy != "required" {
		return VerifiedIssuerStatus{}, fmt.Errorf("status policy must be required or disabled")
	}
	if statusArtifact == nil || trustedKeys == nil {
		return VerifiedIssuerStatus{}, trustArtifactError("ISSUER_STATUS_REQUIRED", "high-assurance verification requires signed issuer status")
	}
	if config.MaxAge <= 0 {
		return VerifiedIssuerStatus{}, fmt.Errorf("issuer status maximum age must be positive")
	}
	artifact := *statusArtifact
	if artifact.Contract.Name != "issuer_status" || artifact.Contract.Version != "v1" {
		return VerifiedIssuerStatus{}, trustArtifactError("INVALID_ISSUER_STATUS", "contract must declare issuer_status v1")
	}
	if artifact.Issuer.Type != issuer.Type || artifact.Issuer.ID != issuer.ID {
		return VerifiedIssuerStatus{}, trustArtifactError("ISSUER_MISMATCH", "issuer status describes a different issuer")
	}
	if artifact.Authority.Type == "" || artifact.Authority.ID == "" {
		return VerifiedIssuerStatus{}, trustArtifactError("INVALID_ISSUER_STATUS", "status authority is required")
	}
	if artifact.Status != "good_standing" && artifact.Status != "suspended" && artifact.Status != "revoked" {
		return VerifiedIssuerStatus{}, trustArtifactError("INVALID_ISSUER_STATUS", "issuer status token is invalid")
	}
	issuedAt, err := time.Parse(time.RFC3339, artifact.IssuedAt)
	if err != nil {
		return VerifiedIssuerStatus{}, trustArtifactError("INVALID_ISSUER_STATUS", "issued_at must be RFC3339")
	}
	expiresAt, err := time.Parse(time.RFC3339, artifact.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) {
		return VerifiedIssuerStatus{}, trustArtifactError("INVALID_ISSUER_STATUS", "expires_at must be RFC3339 and after issuance")
	}
	if now.Before(issuedAt) {
		return VerifiedIssuerStatus{}, trustArtifactError("ISSUER_STATUS_NOT_YET_VALID", "issuer status is not yet valid")
	}
	if !now.Before(expiresAt) {
		return VerifiedIssuerStatus{}, trustArtifactError("ISSUER_STATUS_EXPIRED", "issuer status has expired")
	}
	if now.Sub(issuedAt) > config.MaxAge {
		return VerifiedIssuerStatus{}, trustArtifactError("ISSUER_STATUS_STALE", "issuer status is stale")
	}
	key, err := selectTrustArtifactKey(*trustedKeys, artifact.Authority, artifact.Signature, issuedAt, IssuerStatusKeyUse)
	if err != nil {
		return VerifiedIssuerStatus{}, err
	}
	statement := map[string]any{
		"context":    IssuerStatusContext,
		"issuer":     partyRefMap(artifact.Issuer),
		"authority":  partyRefMap(artifact.Authority),
		"status":     artifact.Status,
		"issued_at":  artifact.IssuedAt,
		"expires_at": artifact.ExpiresAt,
	}
	if artifact.StatusReference != "" {
		statement["status_reference"] = artifact.StatusReference
	}
	if err := verifyTrustArtifactSignature(statement, artifact.Signature, key); err != nil {
		return VerifiedIssuerStatus{}, err
	}
	if artifact.Status == "revoked" {
		return VerifiedIssuerStatus{}, trustArtifactError("ISSUER_REVOKED", "issuer is revoked")
	}
	if artifact.Status == "suspended" {
		return VerifiedIssuerStatus{}, trustArtifactError("ISSUER_SUSPENDED", "issuer is suspended")
	}
	return VerifiedIssuerStatus{
		Issuer: artifact.Issuer, Authority: artifact.Authority, Status: artifact.Status,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, KeyID: artifact.Signature.KeyID,
		StatusReference: artifact.StatusReference,
	}, nil
}

func VerifyApprovalArtifact(
	approval ApprovalArtifact,
	trustedKeys TrustedCounterSignatureKeys,
) (VerifiedApprovalArtifact, error) {
	return verifyApprovalArtifact(approval, trustedKeys, nil)
}

func VerifyApprovalArtifactForAction(
	approval ApprovalArtifact,
	trustedKeys TrustedCounterSignatureKeys,
	expectedActionHash ActionHashSpec,
) (VerifiedApprovalArtifact, error) {
	return verifyApprovalArtifact(approval, trustedKeys, &expectedActionHash)
}

func verifyApprovalArtifact(
	approval ApprovalArtifact,
	trustedKeys TrustedCounterSignatureKeys,
	expectedActionHash *ActionHashSpec,
) (VerifiedApprovalArtifact, error) {
	if approval.Contract.Name != "approval_artifact" || approval.Contract.Version != "v1" {
		return VerifiedApprovalArtifact{}, trustArtifactError("INVALID_APPROVAL_ARTIFACT", "contract must declare approval_artifact v1")
	}
	if approval.ApprovalID == "" || approval.Approver.Type == "" || approval.Approver.ID == "" || approval.ApprovalType == "" {
		return VerifiedApprovalArtifact{}, trustArtifactError("INVALID_APPROVAL_ARTIFACT", "approval identity fields are required")
	}
	if approval.Decision != "approved" {
		return VerifiedApprovalArtifact{}, trustArtifactError("APPROVAL_NOT_GRANTED", "approval decision is not approved")
	}
	if approval.ActionHash.Algorithm != "sha-256" || approval.ActionHash.Canonicalization != "RFC8785-JCS" || !sha256HexPattern.MatchString(approval.ActionHash.Value) {
		return VerifiedApprovalArtifact{}, trustArtifactError("INVALID_APPROVAL_ARTIFACT", "approval action hash is invalid")
	}
	if expectedActionHash != nil && approval.ActionHash != *expectedActionHash {
		return VerifiedApprovalArtifact{}, trustArtifactError("APPROVAL_ACTION_MISMATCH", "approval is not bound to the expected action")
	}
	issuedAt, err := time.Parse(time.RFC3339, approval.IssuedAt)
	if err != nil {
		return VerifiedApprovalArtifact{}, trustArtifactError("INVALID_APPROVAL_ARTIFACT", "approval issued_at must be RFC3339")
	}
	key, err := selectTrustArtifactKey(trustedKeys, approval.Approver, approval.Signature, issuedAt, ApprovalKeyUse)
	if err != nil {
		return VerifiedApprovalArtifact{}, err
	}
	statement := map[string]any{
		"context":       ApprovalContext,
		"approval_id":   approval.ApprovalID,
		"approver":      partyRefMap(approval.Approver),
		"approval_type": approval.ApprovalType,
		"decision":      approval.Decision,
		"action_hash": map[string]any{
			"algorithm": approval.ActionHash.Algorithm, "canonicalization": approval.ActionHash.Canonicalization, "value": approval.ActionHash.Value,
		},
		"issued_at": approval.IssuedAt,
	}
	if err := verifyTrustArtifactSignature(statement, approval.Signature, key); err != nil {
		return VerifiedApprovalArtifact{}, err
	}
	return VerifiedApprovalArtifact{
		ApprovalID: approval.ApprovalID, Approver: approval.Approver,
		ApprovalType: approval.ApprovalType, Decision: approval.Decision,
		ActionHash: approval.ActionHash, IssuedAt: issuedAt, KeyID: approval.Signature.KeyID,
	}, nil
}

func selectTrustArtifactKey(
	trustedKeys TrustedCounterSignatureKeys,
	signer PartyRef,
	signature SignatureSpec,
	signedAt time.Time,
	requiredUse string,
) (TrustedCountersigningKey, error) {
	if trustedKeys.Contract.Name != "key_discovery" || trustedKeys.Contract.Version != "v1" || len(trustedKeys.Keys) == 0 {
		return TrustedCountersigningKey{}, trustArtifactError("TRUSTED_KEYS_INVALID", "trusted key set is invalid")
	}
	if trustedKeys.Issuer.Type != signer.Type || trustedKeys.Issuer.ID != signer.ID {
		return TrustedCountersigningKey{}, trustArtifactError("SIGNER_MISMATCH", "artifact signer does not match key-set issuer")
	}
	var matches []TrustedCountersigningKey
	for _, key := range trustedKeys.Keys {
		if key.KeyID == signature.KeyID {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return TrustedCountersigningKey{}, trustArtifactError("UNKNOWN_KEY_ID", "no trusted key matched artifact kid")
	}
	if len(matches) != 1 {
		return TrustedCountersigningKey{}, trustArtifactError("TRUSTED_KEYS_INVALID", "trusted key kid is duplicated")
	}
	key := matches[0]
	normalizedUses, err := normalizeCountersignatureUses(key.Use)
	if err != nil {
		return key, trustArtifactError("TRUSTED_KEYS_INVALID", "trusted key use is invalid")
	}
	if !containsString(normalizedUses, requiredUse) {
		return key, trustArtifactError("KEY_PURPOSE_MISMATCH", "trusted key purpose is invalid")
	}
	if key.Algorithm != signature.Algorithm || (key.Status != "active" && key.Status != "retired") {
		return key, trustArtifactError("KEY_NOT_VALID", "trusted key is not valid")
	}
	if err := validateCountersigningKeyTime(key, signedAt); err != nil {
		return key, trustArtifactError("KEY_NOT_VALID", "trusted key was not valid at signing time")
	}
	return key, nil
}

func verifyTrustArtifactSignature(
	statement map[string]any,
	signature SignatureSpec,
	key TrustedCountersigningKey,
) error {
	if signature.Algorithm != "EdDSA" || signature.Encoding != "base64url" {
		return trustArtifactError("UNSUPPORTED_ALGORITHM", "trust artifact v1 supports Ed25519")
	}
	if key.PublicKeyJWK["kty"] != "OKP" || key.PublicKeyJWK["crv"] != "Ed25519" {
		return trustArtifactError("TRUSTED_KEYS_INVALID", "trusted key must be Ed25519")
	}
	if kid, ok := key.PublicKeyJWK["kid"].(string); ok && kid != signature.KeyID {
		return trustArtifactError("TRUSTED_KEYS_INVALID", "public key kid does not match signature")
	}
	if algorithm, ok := key.PublicKeyJWK["alg"].(string); ok && algorithm != "EdDSA" {
		return trustArtifactError("TRUSTED_KEYS_INVALID", "public key algorithm must be EdDSA")
	}
	x, ok := key.PublicKeyJWK["x"].(string)
	if !ok {
		return trustArtifactError("TRUSTED_KEYS_INVALID", "public key x is required")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return trustArtifactError("TRUSTED_KEYS_INVALID", "public key is invalid")
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return trustArtifactError("SIGNATURE_INVALID", "signature is invalid")
	}
	payload, err := canonicalizeBytes(statement)
	if err != nil {
		return trustArtifactError("SIGNATURE_INVALID", "statement could not be canonicalized")
	}
	if !ed25519.Verify(publicKey, payload, signatureBytes) {
		return trustArtifactError("SIGNATURE_INVALID", "artifact signature could not be verified")
	}
	return nil
}
