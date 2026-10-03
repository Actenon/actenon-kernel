//go:build !ed25519

package main

import (
	"encoding/json"

	"github.com/Actenon/sdk-go/verifier"
)

func edVerifier(json.RawMessage) verifier.SignatureVerifier { return nil }
