package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

const (
	CountersignatureContext = "actenon.receipt-countersignature.v1"
	CountersignatureKeyUse  = "receipt_countersignature"
)

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type CountersignatureVerificationError struct {
	Code    string
	Message string
}

func (e *CountersignatureVerificationError) Error() string {
	return e.Code + ": " + e.Message
}

type ReceiptDigest struct {
	Algorithm        string `json:"algorithm"`
	Canonicalization string `json:"canonicalization"`
	Value            string `json:"value"`
}

type ReceiptCountersignature struct {
	Contract        Contract       `json:"contract"`
	ReceiptDigest   ReceiptDigest  `json:"receipt_digest"`
	Witness         PartyRef       `json:"witness"`
	SignedAt        string         `json:"signed_at"`
	AnchorReference map[string]any `json:"anchor_reference,omitempty"`
	Signature       SignatureSpec  `json:"signature"`
}

type TrustedCountersigningKey struct {
	KeyID        string         `json:"key_id"`
	Algorithm    string         `json:"algorithm"`
	Use          any            `json:"use"`
	Status       string         `json:"status"`
	NotBefore    string         `json:"not_before,omitempty"`
	ExpiresAt    string         `json:"expires_at,omitempty"`
	RevokedAt    string         `json:"revoked_at,omitempty"`
	PublicKeyJWK map[string]any `json:"public_key_jwk"`
}

type TrustedCounterSignatureKeys struct {
	Contract Contract                   `json:"contract"`
	Issuer   PartyRef                   `json:"issuer"`
	Keys     []TrustedCountersigningKey `json:"keys"`
}

type VerifiedCountersignature struct {
	ReceiptDigest   ReceiptDigest
	Witness         PartyRef
	SignedAt        time.Time
	KeyID           string
	AnchorReference map[string]any
}

func countersignatureError(code string, message string) error {
	return &CountersignatureVerificationError{Code: code, Message: message}
}

func ParseReceiptCountersignatureJSON(raw []byte) (ReceiptCountersignature, error) {
	var artifact ReceiptCountersignature
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&artifact); err != nil {
		return ReceiptCountersignature{}, countersignatureError("INVALID_COUNTERSIGNATURE", "counter-signature must be valid JSON")
	}
	return artifact, nil
}

func ParseTrustedCounterSignatureKeysJSON(raw []byte) (TrustedCounterSignatureKeys, error) {
	var keys TrustedCounterSignatureKeys
	if err := json.Unmarshal(raw, &keys); err != nil {
		return TrustedCounterSignatureKeys{}, countersignatureError("TRUSTED_KEYS_INVALID", "trusted key set must be valid JSON")
	}
	return keys, nil
}

func VerifyCountersignature(
	receiptOrDigest any,
	countersignature ReceiptCountersignature,
	trustedKeys TrustedCounterSignatureKeys,
) (VerifiedCountersignature, error) {
	expectedDigest, err := resolveReceiptDigest(receiptOrDigest)
	if err != nil {
		return VerifiedCountersignature{}, err
	}
	if countersignature.Contract.Name != "receipt_countersignature" || countersignature.Contract.Version != "v1" {
		return VerifiedCountersignature{}, countersignatureError("INVALID_COUNTERSIGNATURE", "contract must declare receipt_countersignature v1")
	}
	if err := validateReceiptDigest(countersignature.ReceiptDigest); err != nil {
		return VerifiedCountersignature{}, err
	}
	if countersignature.ReceiptDigest != expectedDigest {
		return VerifiedCountersignature{}, countersignatureError("RECEIPT_DIGEST_MISMATCH", "counter-signature receipt digest does not match the supplied receipt or digest")
	}
	if countersignature.Witness.Type == "" || countersignature.Witness.ID == "" {
		return VerifiedCountersignature{}, countersignatureError("INVALID_COUNTERSIGNATURE", "counter-signature witness must include type and id")
	}
	signedAt, err := time.Parse(time.RFC3339, countersignature.SignedAt)
	if err != nil {
		return VerifiedCountersignature{}, countersignatureError("INVALID_COUNTERSIGNATURE", "counter-signature signed_at must be RFC3339")
	}
	signature := countersignature.Signature
	if signature.Algorithm == "" || signature.KeyID == "" || signature.Encoding == "" || signature.Value == "" {
		return VerifiedCountersignature{}, countersignatureError("INVALID_COUNTERSIGNATURE", "counter-signature signature is incomplete")
	}
	if trustedKeys.Contract.Name != "key_discovery" || trustedKeys.Contract.Version != "v1" || len(trustedKeys.Keys) == 0 {
		return VerifiedCountersignature{}, countersignatureError("TRUSTED_KEYS_INVALID", "trusted key set must declare key_discovery v1 with at least one key")
	}
	if trustedKeys.Issuer.Type != countersignature.Witness.Type || trustedKeys.Issuer.ID != countersignature.Witness.ID {
		return VerifiedCountersignature{}, countersignatureError("WITNESS_MISMATCH", "counter-signature witness does not match the trusted key-set issuer")
	}

	matches := make([]TrustedCountersigningKey, 0, 1)
	for _, key := range trustedKeys.Keys {
		if key.KeyID == signature.KeyID {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return VerifiedCountersignature{}, countersignatureError("UNKNOWN_KEY_ID", fmt.Sprintf("no trusted counter-signing key matched key_id %q", signature.KeyID))
	}
	if len(matches) != 1 {
		return VerifiedCountersignature{}, countersignatureError("TRUSTED_KEYS_INVALID", fmt.Sprintf("trusted key set contains duplicate key_id %q", signature.KeyID))
	}
	key := matches[0]
	if key.Algorithm != signature.Algorithm {
		return VerifiedCountersignature{}, countersignatureError("SIGNATURE_INVALID", "trusted key algorithm does not match the counter-signature")
	}
	uses, err := normalizeCountersignatureUses(key.Use)
	if err != nil {
		return VerifiedCountersignature{}, err
	}
	if !containsString(uses, CountersignatureKeyUse) {
		return VerifiedCountersignature{}, countersignatureError("KEY_PURPOSE_MISMATCH", "trusted key is not authorized for receipt counter-signatures")
	}
	if key.Status != "active" && key.Status != "retired" {
		return VerifiedCountersignature{}, countersignatureError("KEY_NOT_VALID", "trusted counter-signing key is not active or retired")
	}
	if err := validateCountersigningKeyTime(key, signedAt); err != nil {
		return VerifiedCountersignature{}, err
	}
	if signature.Algorithm != "EdDSA" || signature.Encoding != "base64url" {
		return VerifiedCountersignature{}, countersignatureError("UNSUPPORTED_ALGORITHM", "receipt counter-signature v1 supports EdDSA/Ed25519 with base64url encoding")
	}
	if key.PublicKeyJWK["kty"] != "OKP" || key.PublicKeyJWK["crv"] != "Ed25519" {
		return VerifiedCountersignature{}, countersignatureError("TRUSTED_KEYS_INVALID", "counter-signing key must be an Ed25519 OKP JWK")
	}
	if kid, ok := key.PublicKeyJWK["kid"].(string); ok && kid != signature.KeyID {
		return VerifiedCountersignature{}, countersignatureError("TRUSTED_KEYS_INVALID", "public_key_jwk.kid does not match signature.key_id")
	}
	if algorithm, ok := key.PublicKeyJWK["alg"].(string); ok && algorithm != "EdDSA" {
		return VerifiedCountersignature{}, countersignatureError("TRUSTED_KEYS_INVALID", "public_key_jwk.alg must be EdDSA")
	}
	x, ok := key.PublicKeyJWK["x"].(string)
	if !ok || x == "" {
		return VerifiedCountersignature{}, countersignatureError("TRUSTED_KEYS_INVALID", "public_key_jwk.x must be a base64url string")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return VerifiedCountersignature{}, countersignatureError("TRUSTED_KEYS_INVALID", "public_key_jwk.x must encode a 32-byte Ed25519 public key")
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return VerifiedCountersignature{}, countersignatureError("SIGNATURE_INVALID", "counter-signature must encode a 64-byte Ed25519 signature")
	}
	statement := map[string]any{
		"context": CountersignatureContext,
		"receipt_digest": map[string]any{
			"algorithm":        countersignature.ReceiptDigest.Algorithm,
			"canonicalization": countersignature.ReceiptDigest.Canonicalization,
			"value":            countersignature.ReceiptDigest.Value,
		},
		"witness":   partyRefMap(countersignature.Witness),
		"signed_at": countersignature.SignedAt,
	}
	if countersignature.AnchorReference != nil {
		statement["anchor_reference"] = countersignature.AnchorReference
	}
	payload, err := canonicalizeBytes(statement)
	if err != nil {
		return VerifiedCountersignature{}, countersignatureError("INVALID_COUNTERSIGNATURE", "counter-signature statement could not be canonicalized")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signatureBytes) {
		return VerifiedCountersignature{}, countersignatureError("SIGNATURE_INVALID", "receipt counter-signature could not be verified")
	}
	return VerifiedCountersignature{
		ReceiptDigest:   countersignature.ReceiptDigest,
		Witness:         countersignature.Witness,
		SignedAt:        signedAt,
		KeyID:           signature.KeyID,
		AnchorReference: countersignature.AnchorReference,
	}, nil
}

func validateReceiptDigest(digest ReceiptDigest) error {
	if digest.Algorithm != "sha-256" || digest.Canonicalization != "RFC8785-JCS" || !sha256HexPattern.MatchString(digest.Value) {
		return countersignatureError("INVALID_RECEIPT_DIGEST", "receipt digest must declare sha-256, RFC8785-JCS, and a lowercase 64-character hex value")
	}
	return nil
}

func resolveReceiptDigest(receiptOrDigest any) (ReceiptDigest, error) {
	if digest, ok := receiptOrDigest.(ReceiptDigest); ok {
		return digest, validateReceiptDigest(digest)
	}
	payload, ok := receiptOrDigest.(map[string]any)
	if !ok {
		return ReceiptDigest{}, countersignatureError("INVALID_RECEIPT_DIGEST", "receipt_or_digest must be a Receipt v1 object or digest")
	}
	if _, hasAlgorithm := payload["algorithm"]; hasAlgorithm {
		raw, err := json.Marshal(payload)
		if err != nil {
			return ReceiptDigest{}, countersignatureError("INVALID_RECEIPT_DIGEST", "receipt digest could not be parsed")
		}
		var digest ReceiptDigest
		if err := json.Unmarshal(raw, &digest); err != nil {
			return ReceiptDigest{}, countersignatureError("INVALID_RECEIPT_DIGEST", "receipt digest could not be parsed")
		}
		return digest, validateReceiptDigest(digest)
	}
	contract, ok := payload["contract"].(map[string]any)
	if !ok || contract["name"] != "receipt" || contract["version"] != "v1" {
		return ReceiptDigest{}, countersignatureError("INVALID_RECEIPT_DIGEST", "receipt_or_digest must be a Receipt v1 object or digest")
	}
	canonical, err := canonicalizeBytes(payload)
	if err != nil {
		return ReceiptDigest{}, countersignatureError("INVALID_RECEIPT_DIGEST", "receipt could not be canonicalized")
	}
	sum := sha256.Sum256(canonical)
	return ReceiptDigest{
		Algorithm:        "sha-256",
		Canonicalization: "RFC8785-JCS",
		Value:            hex.EncodeToString(sum[:]),
	}, nil
}

func normalizeCountersignatureUses(value any) ([]string, error) {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			break
		}
		return []string{typed}, nil
	case []any:
		uses := make([]string, 0, len(typed))
		for _, item := range typed {
			use, ok := item.(string)
			if !ok || use == "" {
				return nil, countersignatureError("TRUSTED_KEYS_INVALID", "trusted key use entries must be strings")
			}
			uses = append(uses, use)
		}
		if len(uses) > 0 {
			return uses, nil
		}
	}
	return nil, countersignatureError("TRUSTED_KEYS_INVALID", "trusted key use must be a non-empty string or array")
}

func validateCountersigningKeyTime(key TrustedCountersigningKey, signedAt time.Time) error {
	for _, bound := range []struct {
		raw       string
		inclusive bool
		message   string
	}{
		{key.NotBefore, false, "trusted counter-signing key was not valid at signing time"},
		{key.ExpiresAt, true, "trusted counter-signing key was expired at signing time"},
		{key.RevokedAt, true, "trusted counter-signing key was revoked at signing time"},
	} {
		if bound.raw == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, bound.raw)
		if err != nil {
			return countersignatureError("TRUSTED_KEYS_INVALID", "trusted key time bounds must be RFC3339")
		}
		if (!bound.inclusive && signedAt.Before(parsed)) || (bound.inclusive && !signedAt.Before(parsed)) {
			return countersignatureError("KEY_NOT_VALID", bound.message)
		}
	}
	return nil
}

func partyRefMap(party PartyRef) map[string]any {
	payload := map[string]any{
		"type": party.Type,
		"id":   party.ID,
	}
	if party.DisplayName != "" {
		payload["display_name"] = party.DisplayName
	}
	if len(party.Attributes) > 0 {
		payload["attributes"] = party.Attributes
	}
	return payload
}
