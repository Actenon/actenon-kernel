package verifier_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/actenon/sdk-go/verifier"
)

func fixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "fixtures", "portable-local-proof")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixturesDir(t), name))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return raw
}

func buildContext() verifier.VerificationContext {
	return verifier.VerificationContext{
		RequestID:         "req_go_conformance_001",
		Audience:          verifier.AudienceRef{Type: "service", ID: "portable-hello-world-endpoint"},
		Now:               time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		ScopeCapabilities: []string{"protected_resource.read"},
		ParameterConstraints: map[string]any{
			"exact_message": "portable hello world",
		},
		ResourceSelectors: []map[string]any{
			{"resource_id": "hello_resource_demo_001"},
		},
	}
}

func buildVerifier() *verifier.Verifier {
	localVerifier := verifier.BuildLocalProofVerifier()
	return verifier.NewVerifier(localVerifier)
}

func TestVerifierAcceptsValidLocalProof(t *testing.T) {
	sdk := buildVerifier()
	intent, err := verifier.ParseActionIntentJSON(loadFixture(t, "action_intent.json"))
	if err != nil {
		t.Fatalf("failed to parse intent: %v", err)
	}
	pccb, err := verifier.ParsePCCBJSON(loadFixture(t, "pccb.json"))
	if err != nil {
		t.Fatalf("failed to parse pccb: %v", err)
	}

	verified, err := sdk.Verify(intent, pccb, buildContext())
	if err != nil {
		t.Fatalf("expected valid proof, got error: %v", err)
	}
	if verified.Intent.Action.Name != "hello_world.read" {
		t.Fatalf("unexpected action name: %s", verified.Intent.Action.Name)
	}
	if verified.PCCB.PCCBID != "pccb_portable_hello_world_001" {
		t.Fatalf("unexpected pccb id: %s", verified.PCCB.PCCBID)
	}
}

func TestVerifierRefusesAudienceMismatch(t *testing.T) {
	sdk := buildVerifier()
	intent, err := verifier.ParseActionIntentJSON(loadFixture(t, "action_intent.json"))
	if err != nil {
		t.Fatalf("failed to parse intent: %v", err)
	}
	pccb, err := verifier.ParsePCCBJSON(loadFixture(t, "pccb.json"))
	if err != nil {
		t.Fatalf("failed to parse pccb: %v", err)
	}

	context := buildContext()
	context.Audience = verifier.AudienceRef{Type: "service", ID: "wrong-endpoint"}

	_, err = sdk.Verify(intent, pccb, context)
	if !verifier.IsVerificationErrorCode(err, verifier.ErrAudienceMismatch) {
		t.Fatalf("expected audience mismatch, got %v", err)
	}
}

func TestVerifierRefusesActionMutation(t *testing.T) {
	sdk := buildVerifier()
	intent, err := verifier.ParseActionIntentJSON(loadFixture(t, "action_intent.json"))
	if err != nil {
		t.Fatalf("failed to parse intent: %v", err)
	}
	pccb, err := verifier.ParsePCCBJSON(loadFixture(t, "pccb.json"))
	if err != nil {
		t.Fatalf("failed to parse pccb: %v", err)
	}

	intent.Action.Parameters["message"] = "tampered hello world"

	_, err = sdk.Verify(intent, pccb, buildContext())
	if !verifier.IsVerificationErrorCode(err, verifier.ErrActionMismatch) {
		t.Fatalf("expected action mismatch, got %v", err)
	}
}

func TestVerifierRefusesExpiredProof(t *testing.T) {
	sdk := buildVerifier()
	intent, err := verifier.ParseActionIntentJSON(loadFixture(t, "action_intent.json"))
	if err != nil {
		t.Fatalf("failed to parse intent: %v", err)
	}
	pccb, err := verifier.ParsePCCBJSON(loadFixture(t, "pccb.json"))
	if err != nil {
		t.Fatalf("failed to parse pccb: %v", err)
	}

	context := buildContext()
	context.Now = time.Date(2026, 1, 1, 12, 6, 0, 0, time.UTC)

	_, err = sdk.Verify(intent, pccb, context)
	if !verifier.IsVerificationErrorCode(err, verifier.ErrProofExpired) {
		t.Fatalf("expected proof expired, got %v", err)
	}
}

func TestVerifierKeepsStrictNotBeforeBehaviorByDefault(t *testing.T) {
	sdk := buildVerifier()
	intent, err := verifier.ParseActionIntentJSON(loadFixture(t, "action_intent.json"))
	if err != nil {
		t.Fatalf("failed to parse intent: %v", err)
	}
	pccb, err := verifier.ParsePCCBJSON(loadFixture(t, "pccb.json"))
	if err != nil {
		t.Fatalf("failed to parse pccb: %v", err)
	}

	context := buildContext()
	context.Now = time.Date(2026, 1, 1, 11, 59, 59, 0, time.UTC)

	_, err = sdk.Verify(intent, pccb, context)
	if !verifier.IsVerificationErrorCode(err, verifier.ErrProofNotYetValid) {
		t.Fatalf("expected proof not yet valid, got %v", err)
	}
}

func TestVerifierAcceptsProofWithinClockSkewTolerance(t *testing.T) {
	localVerifier := verifier.BuildLocalProofVerifier()
	sdk := verifier.NewVerifier(localVerifier, verifier.WithClockSkewTolerance(2*time.Second))
	intent, err := verifier.ParseActionIntentJSON(loadFixture(t, "action_intent.json"))
	if err != nil {
		t.Fatalf("failed to parse intent: %v", err)
	}
	pccb, err := verifier.ParsePCCBJSON(loadFixture(t, "pccb.json"))
	if err != nil {
		t.Fatalf("failed to parse pccb: %v", err)
	}

	earlyContext := buildContext()
	earlyContext.Now = time.Date(2026, 1, 1, 11, 59, 59, 0, time.UTC)
	if _, err := sdk.Verify(intent, pccb, earlyContext); err != nil {
		t.Fatalf("expected early proof within tolerance, got %v", err)
	}

	lateContext := buildContext()
	lateContext.Now = time.Date(2026, 1, 1, 12, 5, 1, 0, time.UTC)
	if _, err := sdk.Verify(intent, pccb, lateContext); err != nil {
		t.Fatalf("expected late proof within tolerance, got %v", err)
	}
}

func TestVerifierRefusesProofBeyondClockSkewTolerance(t *testing.T) {
	localVerifier := verifier.BuildLocalProofVerifier()
	sdk := verifier.NewVerifier(localVerifier, verifier.WithClockSkewTolerance(2*time.Second))
	intent, err := verifier.ParseActionIntentJSON(loadFixture(t, "action_intent.json"))
	if err != nil {
		t.Fatalf("failed to parse intent: %v", err)
	}
	pccb, err := verifier.ParsePCCBJSON(loadFixture(t, "pccb.json"))
	if err != nil {
		t.Fatalf("failed to parse pccb: %v", err)
	}

	earlyContext := buildContext()
	earlyContext.Now = time.Date(2026, 1, 1, 11, 59, 57, 0, time.UTC)
	_, err = sdk.Verify(intent, pccb, earlyContext)
	if !verifier.IsVerificationErrorCode(err, verifier.ErrProofNotYetValid) {
		t.Fatalf("expected proof not yet valid, got %v", err)
	}

	lateContext := buildContext()
	lateContext.Now = time.Date(2026, 1, 1, 12, 5, 3, 0, time.UTC)
	_, err = sdk.Verify(intent, pccb, lateContext)
	if !verifier.IsVerificationErrorCode(err, verifier.ErrProofExpired) {
		t.Fatalf("expected proof expired, got %v", err)
	}
}
