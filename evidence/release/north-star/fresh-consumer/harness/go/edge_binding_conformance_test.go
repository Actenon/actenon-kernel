// Copied from github.com/Actenon/sdk-go@2139da9 verifier/edge_binding_conformance_test.go. Harness changes: package name,
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

// protocol/13-edge-binding.md E1-E4, vendored from the kernel's
// verifier_sdk_v1/edge_binding_cases.json and run through VerifyJSON.
type edgeBindingManifest struct {
	Base struct {
		Intent  string         `json:"intent"`
		PCCB    string         `json:"pccb"`
		Context map[string]any `json:"context"`
	} `json:"base"`
	Cases []struct {
		ID                   string `json:"id"`
		ClockSkewToleranceMS int    `json:"clock_skew_tolerance_ms"`
		PCCB                 string `json:"pccb"`
		ContextMutation      *struct {
			Path  []string `json:"path"`
			Value any      `json:"value"`
		} `json:"context_mutation"`
		Expected struct {
			Outcome    string `json:"outcome"`
			ReasonCode string `json:"reason_code"`
			Message    string `json:"message"`
		} `json:"expected"`
	} `json:"cases"`
}

func TestEdgeBindingVectors(t *testing.T) {
	var manifest edgeBindingManifest
	loadSharedJSON(t, "edge_binding_cases.json", &manifest)
	if len(manifest.Cases) == 0 {
		t.Fatal("edge_binding_cases.json has no cases")
	}
	intentRaw, err := os.ReadFile(filepath.Join(sharedVectorRoot(t), manifest.Base.Intent))
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range manifest.Cases {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			pccbName := manifest.Base.PCCB
			if vector.PCCB != "" {
				pccbName = vector.PCCB
			}
			pccbRaw, err := os.ReadFile(filepath.Join(sharedVectorRoot(t), pccbName))
			if err != nil {
				t.Fatal(err)
			}
			context := cloneSharedDocument(t, manifest.Base.Context)
			if vector.ContextMutation != nil {
				setSharedPath(t, context, vector.ContextMutation.Path, vector.ContextMutation.Value)
			}
			sdk := verifier.NewVerifier(
				verifier.BuildLocalProofVerifier(),
				verifier.WithClockSkewTolerance(time.Duration(vector.ClockSkewToleranceMS)*time.Millisecond),
			)
			_, err = sdk.VerifyJSON(intentRaw, pccbRaw, sharedContext(t, context))
			if vector.Expected.Outcome == "verified" {
				if err != nil {
					t.Fatalf("expected verified, got %v", err)
				}
				return
			}
			var verificationErr *verifier.VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("expected a VerificationError %s, got %v", vector.Expected.ReasonCode, err)
			}
			if string(verificationErr.Code) != vector.Expected.ReasonCode || verificationErr.Message != vector.Expected.Message {
				t.Fatalf("expected %s %q, got %s %q", vector.Expected.ReasonCode, vector.Expected.Message, verificationErr.Code, verificationErr.Message)
			}
		})
	}
}
