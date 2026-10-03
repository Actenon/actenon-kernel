// Copied from github.com/Actenon/sdk-go@2139da9 verifier/verifier_conformance_test.go. Harness changes: package name,
// and sharedVectorRoot reads ACTENON_VECTORS (the INSTALLED actenon-kernel wheel's vectors).
package consumer_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

type sharedMutation struct {
	Document string   `json:"document"`
	Path     []string `json:"path"`
	Value    any      `json:"value"`
}

type sharedExpected struct {
	Outcome    string `json:"outcome"`
	ReasonCode string `json:"reason_code"`
	Message    string `json:"message"`
}

type sharedCase struct {
	ID                   string          `json:"id"`
	ClockSkewToleranceMS int64           `json:"clock_skew_tolerance_ms"`
	Mutation             *sharedMutation `json:"mutation"`
	Expected             sharedExpected  `json:"expected"`
}

type sharedManifest struct {
	Base struct {
		Intent  string         `json:"intent"`
		PCCB    string         `json:"pccb"`
		Context map[string]any `json:"context"`
	} `json:"base"`
	Cases []sharedCase `json:"cases"`
}

func sharedVectorRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("ACTENON_VECTORS")
	if root == "" || !strings.Contains(root, "site-packages") {
		t.Fatalf("ACTENON_VECTORS must point at an installed actenon-kernel wheel's verifier_sdk_v1, got %q", root)
	}
	return root
}

func loadSharedJSON(t *testing.T, name string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(sharedVectorRoot(t), name))
	if err != nil {
		t.Fatalf("failed to read shared vector %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("failed to decode shared vector %s: %v", name, err)
	}
}

func cloneSharedDocument(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("failed to clone shared vector: %v", err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatalf("failed to decode cloned shared vector: %v", err)
	}
	return cloned
}

func setSharedPath(t *testing.T, document map[string]any, path []string, value any) {
	t.Helper()
	current := document
	for _, segment := range path[:len(path)-1] {
		child, ok := current[segment].(map[string]any)
		if !ok {
			t.Fatalf("shared vector path does not resolve to an object: %v", path)
		}
		current = child
	}
	current[path[len(path)-1]] = value
}

func sharedContext(t *testing.T, raw map[string]any) verifier.VerificationContext {
	t.Helper()
	audienceRaw := raw["audience"].(map[string]any)
	now, err := time.Parse(time.RFC3339Nano, raw["now"].(string))
	if err != nil {
		t.Fatalf("invalid shared context time: %v", err)
	}
	capabilitiesRaw := raw["scope_capabilities"].([]any)
	capabilities := make([]string, len(capabilitiesRaw))
	for index, value := range capabilitiesRaw {
		capabilities[index] = value.(string)
	}
	selectorsRaw := raw["resource_selectors"].([]any)
	selectors := make([]map[string]any, len(selectorsRaw))
	for index, value := range selectorsRaw {
		selectors[index] = value.(map[string]any)
	}
	return verifier.VerificationContext{
		RequestID: raw["request_id"].(string),
		Audience: verifier.AudienceRef{
			Type: audienceRaw["type"].(string),
			ID:   audienceRaw["id"].(string),
		},
		Now:                  now,
		ScopeCapabilities:    capabilities,
		ParameterConstraints: raw["parameter_constraints"].(map[string]any),
		ResourceSelectors:    selectors,
	}
}

func TestSharedVerifierConformanceVectors(t *testing.T) {
	var manifest sharedManifest
	loadSharedJSON(t, "cases.json", &manifest)
	var baseIntent map[string]any
	var basePCCB map[string]any
	loadSharedJSON(t, manifest.Base.Intent, &baseIntent)
	loadSharedJSON(t, manifest.Base.PCCB, &basePCCB)

	for _, vector := range manifest.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			intentDocument := cloneSharedDocument(t, baseIntent)
			pccbDocument := cloneSharedDocument(t, basePCCB)
			contextDocument := cloneSharedDocument(t, manifest.Base.Context)
			if vector.Mutation != nil {
				documents := map[string]map[string]any{
					"intent":  intentDocument,
					"pccb":    pccbDocument,
					"context": contextDocument,
				}
				setSharedPath(
					t,
					documents[vector.Mutation.Document],
					vector.Mutation.Path,
					vector.Mutation.Value,
				)
			}
			intentRaw, _ := json.Marshal(intentDocument)
			pccbRaw, _ := json.Marshal(pccbDocument)
			sdk := verifier.NewVerifier(
				verifier.BuildLocalProofVerifier(),
				verifier.WithClockSkewTolerance(
					time.Duration(vector.ClockSkewToleranceMS)*time.Millisecond,
				),
			)
			verified, err := sdk.VerifyJSON(
				intentRaw,
				pccbRaw,
				sharedContext(t, contextDocument),
			)
			if vector.Expected.Outcome == "verified" {
				if err != nil {
					t.Fatalf("expected verification, got %v", err)
				}
				if verified.PCCB.PCCBID != "pccb_portable_hello_world_001" {
					t.Fatalf("unexpected pccb id: %s", verified.PCCB.PCCBID)
				}
				return
			}
			var verificationErr *verifier.VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("expected verification refusal, got %v", err)
			}
			if string(verificationErr.Code) != vector.Expected.ReasonCode {
				t.Fatalf(
					"expected reason %s, got %s",
					vector.Expected.ReasonCode,
					verificationErr.Code,
				)
			}
			if verificationErr.Message != vector.Expected.Message {
				t.Fatalf(
					"expected message %q, got %q",
					vector.Expected.Message,
					verificationErr.Message,
				)
			}
		})
	}
}

type timestampCase struct {
	ID       string         `json:"id"`
	Intent   string         `json:"intent"`
	PCCB     string         `json:"pccb"`
	Context  map[string]any `json:"context"`
	Expected sharedExpected `json:"expected"`
}

type timestampManifest struct {
	ClockSkewToleranceMS int64           `json:"clock_skew_tolerance_ms"`
	Cases                []timestampCase `json:"cases"`
}

func readSharedVector(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(sharedVectorRoot(t), name))
	if err != nil {
		t.Fatalf("failed to read shared vector %s: %v", name, err)
	}
	return raw
}

// Kernel timestamp_cases.json: proofs minted with the ACTENON-JCS-STRICT-1
// label and fractional-second timestamps, plus microsecond window boundaries.
// The vendored intent and PCCB bytes are verified as-is (no re-encoding).
func TestSharedFractionalSecondTimestampVectors(t *testing.T) {
	var manifest timestampManifest
	loadSharedJSON(t, "timestamp_cases.json", &manifest)
	if len(manifest.Cases) == 0 {
		t.Fatal("timestamp_cases.json has no cases")
	}
	for _, vector := range manifest.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			intentRaw := readSharedVector(t, vector.Intent)
			pccbRaw := readSharedVector(t, vector.PCCB)
			var pccbDocument struct {
				PCCBID string `json:"pccb_id"`
			}
			if err := json.Unmarshal(pccbRaw, &pccbDocument); err != nil {
				t.Fatalf("failed to decode %s: %v", vector.PCCB, err)
			}
			sdk := verifier.NewVerifier(
				verifier.BuildLocalProofVerifier(),
				verifier.WithClockSkewTolerance(
					time.Duration(manifest.ClockSkewToleranceMS)*time.Millisecond,
				),
			)
			verified, err := sdk.VerifyJSON(intentRaw, pccbRaw, sharedContext(t, vector.Context))
			if vector.Expected.Outcome == "verified" {
				if err != nil {
					t.Fatalf("expected verification, got %v", err)
				}
				if verified.PCCB.PCCBID != pccbDocument.PCCBID {
					t.Fatalf("unexpected pccb id: %s", verified.PCCB.PCCBID)
				}
				if verified.PCCB.ActionHash.Canonicalization != "ACTENON-JCS-STRICT-1" {
					t.Fatalf("unexpected label %s", verified.PCCB.ActionHash.Canonicalization)
				}
				return
			}
			var verificationErr *verifier.VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("expected verification refusal, got %v", err)
			}
			if string(verificationErr.Code) != vector.Expected.ReasonCode ||
				verificationErr.Message != vector.Expected.Message {
				t.Fatalf(
					"expected %s %q, got %s %q",
					vector.Expected.ReasonCode,
					vector.Expected.Message,
					verificationErr.Code,
					verificationErr.Message,
				)
			}
		})
	}
}

// Every JSON file in fixtures/verifier_sdk_v1 must be a manifest with a
// runner above or a document one of those manifests references, so a vector
// cannot be vendored without being executed.
func TestSharedVerifierVectorsAreAllExecuted(t *testing.T) {
	var shared sharedManifest
	loadSharedJSON(t, "cases.json", &shared)
	var timestamps timestampManifest
	loadSharedJSON(t, "timestamp_cases.json", &timestamps)
	var edge edgeBindingManifest
	loadSharedJSON(t, "edge_binding_cases.json", &edge)
	executed := map[string]bool{
		"cases.json":              true,
		"timestamp_cases.json":    true,
		"edge_binding_cases.json": true,
		shared.Base.Intent:        true,
		shared.Base.PCCB:          true,
		edge.Base.Intent:          true,
		edge.Base.PCCB:            true,
	}
	for _, vector := range edge.Cases {
		if vector.PCCB != "" {
			executed[vector.PCCB] = true
		}
	}
	var revocation edgeRevocationManifest
	loadSharedJSON(t, "edge_revocation_cases.json", &revocation)
	executed["edge_revocation_cases.json"] = true
	executed[revocation.Base.Intent] = true
	for _, vector := range revocation.Cases {
		executed[vector.PCCB] = true
	}
	for _, vector := range timestamps.Cases {
		executed[vector.Intent] = true
		executed[vector.PCCB] = true
	}
	entries, err := os.ReadDir(sharedVectorRoot(t))
	if err != nil {
		t.Fatalf("failed to list shared vectors: %v", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" && !executed[entry.Name()] {
			t.Errorf("fixtures/verifier_sdk_v1/%s is vendored but no runner executes it", entry.Name())
		}
	}
}
