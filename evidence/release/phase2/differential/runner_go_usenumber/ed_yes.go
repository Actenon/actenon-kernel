//go:build ed25519

package main

import (
	"encoding/json"

	"github.com/Actenon/sdk-go/verifier"
)

func edVerifier(jwk json.RawMessage) verifier.SignatureVerifier {
	v, err := verifier.NewEd25519VerifierFromJWKs(jwk)
	if err != nil {
		panic(err)
	}
	return v
}
