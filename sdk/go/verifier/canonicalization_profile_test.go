package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The kernel mints every new PCCB with the ACTENON-JCS-STRICT-1 action-hash
// label (actenon-protocol >= 1.1); RFC8785-JCS is the accepted legacy alias.
// The shared vectors only carry the legacy label, so these tests re-label the
// base proof, re-sign it with the public local development key, and require
// the verdicts the Python reference gives.

func loadProfileVector(t *testing.T, name string) map[string]any {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "..", "actenon", "conformance", "vectors", "verifier_sdk_v1", name))
	if err != nil {
		t.Fatalf("failed to read shared vector %s: %v", name, err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("failed to decode shared vector %s: %v", name, err)
	}
	return document
}

func relabelAndResign(t *testing.T, pccb map[string]any, canonicalization string) []byte {
	t.Helper()
	pccb["action_hash"].(map[string]any)["canonicalization"] = canonicalization
	signature := pccb["signature"].(map[string]any)
	delete(pccb, "signature")
	payload, err := canonicalizeBytes(pccb)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(LocalProofSecret))
	mac.Write(payload)
	signature["value"] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	pccb["signature"] = signature
	raw, err := json.Marshal(pccb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func profileContext(t *testing.T) VerificationContext {
	t.Helper()
	cases := loadProfileVector(t, "cases.json")
	raw := cases["base"].(map[string]any)["context"].(map[string]any)
	now, err := time.Parse(time.RFC3339Nano, raw["now"].(string))
	if err != nil {
		t.Fatalf("invalid context time: %v", err)
	}
	audience := raw["audience"].(map[string]any)
	var capabilities []string
	for _, value := range raw["scope_capabilities"].([]any) {
		capabilities = append(capabilities, value.(string))
	}
	return VerificationContext{
		RequestID:         raw["request_id"].(string),
		Audience:          AudienceRef{Type: audience["type"].(string), ID: audience["id"].(string)},
		Now:               now,
		ScopeCapabilities: capabilities,
	}
}

func TestVerifierAcceptsBothCanonicalizationProfileLabels(t *testing.T) {
	for _, label := range []string{"ACTENON-JCS-STRICT-1", "RFC8785-JCS"} {
		t.Run(label, func(t *testing.T) {
			intentRaw, _ := json.Marshal(loadProfileVector(t, "action_intent.json"))
			pccbRaw := relabelAndResign(t, loadProfileVector(t, "pccb.json"), label)
			verified, err := NewVerifier(BuildLocalProofVerifier()).VerifyJSON(intentRaw, pccbRaw, profileContext(t))
			if err != nil {
				t.Fatalf("expected verification with label %s, got %v", label, err)
			}
			if verified.PCCB.ActionHash.Canonicalization != label {
				t.Fatalf("unexpected label %s", verified.PCCB.ActionHash.Canonicalization)
			}
		})
	}
}

func TestVerifierRefusesUnknownCanonicalizationProfileLabels(t *testing.T) {
	for _, label := range []string{"actenon-jcs-sha256-v1", "JCS"} {
		t.Run(label, func(t *testing.T) {
			intentRaw, _ := json.Marshal(loadProfileVector(t, "action_intent.json"))
			pccbRaw := relabelAndResign(t, loadProfileVector(t, "pccb.json"), label)
			_, err := NewVerifier(BuildLocalProofVerifier()).VerifyJSON(intentRaw, pccbRaw, profileContext(t))
			var verificationErr *VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("expected refusal for label %s, got %v", label, err)
			}
		})
	}
}

// Fractional-second timestamps under ACTENON-JCS-STRICT-1: timestamps must be
// re-serialised exactly as the Python reference does (six-digit microseconds)
// and time windows compared at microsecond precision.
func TestSharedFractionalSecondTimestampVectors(t *testing.T) {
	manifest := loadProfileVector(t, "timestamp_cases.json")
	skew := time.Duration(manifest["clock_skew_tolerance_ms"].(float64)) * time.Millisecond
	for _, raw := range manifest["cases"].([]any) {
		vector := raw.(map[string]any)
		t.Run(vector["id"].(string), func(t *testing.T) {
			intentRaw, _ := json.Marshal(loadProfileVector(t, vector["intent"].(string)))
			pccbRaw, _ := json.Marshal(loadProfileVector(t, vector["pccb"].(string)))
			contextRaw := vector["context"].(map[string]any)
			now, err := time.Parse(time.RFC3339Nano, contextRaw["now"].(string))
			if err != nil {
				t.Fatalf("invalid context time: %v", err)
			}
			audience := contextRaw["audience"].(map[string]any)
			var capabilities []string
			for _, value := range contextRaw["scope_capabilities"].([]any) {
				capabilities = append(capabilities, value.(string))
			}
			context := VerificationContext{
				RequestID:         contextRaw["request_id"].(string),
				Audience:          AudienceRef{Type: audience["type"].(string), ID: audience["id"].(string)},
				Now:               now,
				ScopeCapabilities: capabilities,
			}
			expected := vector["expected"].(map[string]any)
			verified, err := NewVerifier(BuildLocalProofVerifier(), WithClockSkewTolerance(skew)).VerifyJSON(intentRaw, pccbRaw, context)
			if expected["outcome"] == "verified" {
				if err != nil {
					t.Fatalf("expected verification, got %v", err)
				}
				if verified.PCCB.ActionHash.Canonicalization != "ACTENON-JCS-STRICT-1" {
					t.Fatalf("unexpected label %s", verified.PCCB.ActionHash.Canonicalization)
				}
				return
			}
			var verificationErr *VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("expected refusal, got %v", err)
			}
			if string(verificationErr.Code) != expected["reason_code"] || verificationErr.Message != expected["message"] {
				t.Fatalf("expected %v %q, got %s %q", expected["reason_code"], expected["message"], verificationErr.Code, verificationErr.Message)
			}
		})
	}
}
