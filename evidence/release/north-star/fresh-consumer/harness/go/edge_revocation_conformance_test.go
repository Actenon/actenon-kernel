// Copied from github.com/Actenon/sdk-go@2139da9 verifier/edge_revocation_conformance_test.go. Harness changes: package name,
// and sharedVectorRoot reads ACTENON_VECTORS (the INSTALLED actenon-kernel wheel's vectors).
package consumer_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

// protocol/13-edge-binding.md E5, vendored from the kernel's
// verifier_sdk_v1/edge_revocation_cases.json.
type edgeRevocationManifest struct {
	Base struct {
		Intent  string         `json:"intent"`
		Context map[string]any `json:"context"`
	} `json:"base"`
	Cases []struct {
		ID                   string `json:"id"`
		PCCB                 string `json:"pccb"`
		RevocationSource     string `json:"revocation_source"`
		ClockSkewToleranceMS int    `json:"clock_skew_tolerance_ms"`
		Expected             struct {
			Outcome    string `json:"outcome"`
			ReasonCode string `json:"reason_code"`
			Message    string `json:"message"`
		} `json:"expected"`
	} `json:"cases"`
}

func TestEdgeRevocationVectors(t *testing.T) {
	var manifest edgeRevocationManifest
	loadSharedJSON(t, "edge_revocation_cases.json", &manifest)
	if len(manifest.Cases) == 0 {
		t.Fatal("edge_revocation_cases.json has no cases")
	}
	intentRaw, err := os.ReadFile(filepath.Join(sharedVectorRoot(t), manifest.Base.Intent))
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]verifier.RevocationChecker{
		"not_revoked": func(verifier.PCCB, verifier.VerificationContext) (bool, error) { return true, nil },
		"revoked":     func(verifier.PCCB, verifier.VerificationContext) (bool, error) { return false, nil },
		"unavailable": func(verifier.PCCB, verifier.VerificationContext) (bool, error) {
			return false, errors.New("revocation source unavailable")
		},
	}
	for _, vector := range manifest.Cases {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			pccbRaw, err := os.ReadFile(filepath.Join(sharedVectorRoot(t), vector.PCCB))
			if err != nil {
				t.Fatal(err)
			}
			options := []verifier.VerifierOption{
				verifier.WithClockSkewTolerance(time.Duration(vector.ClockSkewToleranceMS) * time.Millisecond),
			}
			if checker, ok := sources[vector.RevocationSource]; ok {
				options = append(options, verifier.WithRevocationChecker(checker))
			} else if vector.RevocationSource != "none" {
				t.Fatalf("unknown revocation source %q", vector.RevocationSource)
			}
			sdk := verifier.NewVerifier(verifier.BuildLocalProofVerifier(), options...)
			_, err = sdk.VerifyJSON(intentRaw, pccbRaw, sharedContext(t, cloneSharedDocument(t, manifest.Base.Context)))
			if vector.Expected.Outcome == "verified" {
				if err != nil {
					t.Fatalf("expected verified, got %v", err)
				}
				return
			}
			var verificationErr *verifier.VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("expected %s, got %v", vector.Expected.ReasonCode, err)
			}
			if string(verificationErr.Code) != vector.Expected.ReasonCode || verificationErr.Message != vector.Expected.Message {
				t.Fatalf("expected %s %q, got %s %q", vector.Expected.ReasonCode, vector.Expected.Message, verificationErr.Code, verificationErr.Message)
			}
		})
	}
}
