package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

const (
	LocalProofKeyID  = "local-proof-v1"
	LocalProofSecret = "actenon-local-proof-secret-v1"
)

type SignatureVerifier interface {
	Verify(payload []byte, signature SignatureSpec) bool
}

type HMACSHA256Verifier struct {
	Secret    []byte
	KeyID     string
	Algorithm string
}

func BuildLocalProofVerifier() HMACSHA256Verifier {
	return HMACSHA256Verifier{
		Secret:    []byte(LocalProofSecret),
		KeyID:     LocalProofKeyID,
		Algorithm: "HS256",
	}
}

func (v HMACSHA256Verifier) Verify(payload []byte, signature SignatureSpec) bool {
	if signature.Algorithm != v.Algorithm || signature.KeyID != v.KeyID || signature.Encoding != "base64url" {
		return false
	}
	provided, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil {
		return false
	}
	expected := hmac.New(sha256.New, v.Secret)
	expected.Write(payload)
	return hmac.Equal(expected.Sum(nil), provided)
}
