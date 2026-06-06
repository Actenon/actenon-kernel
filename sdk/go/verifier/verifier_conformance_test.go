package verifier_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/actenon/sdk-go/verifier"
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
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve shared vector test path")
	}
	return filepath.Clean(filepath.Join(
		filepath.Dir(filename),
		"..",
		"..",
		"..",
		"actenon",
		"conformance",
		"vectors",
		"verifier_sdk_v1",
	))
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
