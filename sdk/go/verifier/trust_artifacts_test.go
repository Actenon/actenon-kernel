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

func trustFixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "conformance", "vectors", "trust_artifacts_v1")
}

func loadTrustJSON(t *testing.T, name string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(trustFixturesDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func requireTrustCode(t *testing.T, err error, expected string) {
	t.Helper()
	var target *verifier.TrustArtifactVerificationError
	if !errors.As(err, &target) || target.Code != expected {
		t.Fatalf("expected %s, got %v", expected, err)
	}
}

func TestTrustArtifactsVerifyAndFailClosed(t *testing.T) {
	var issuer verifier.PartyRef
	var good, revoked, stale verifier.IssuerStatusArtifact
	var approval, changed, forged verifier.ApprovalArtifact
	var statusKeys, approvalKeys verifier.TrustedCounterSignatureKeys
	loadTrustJSON(t, "issuer.json", &issuer)
	loadTrustJSON(t, "issuer_status_good.json", &good)
	loadTrustJSON(t, "issuer_status_revoked.json", &revoked)
	loadTrustJSON(t, "issuer_status_stale.json", &stale)
	loadTrustJSON(t, "issuer_status_trusted_keys.json", &statusKeys)
	loadTrustJSON(t, "approval.json", &approval)
	loadTrustJSON(t, "mutations/approval_action_changed.json", &changed)
	loadTrustJSON(t, "mutations/approval_signature_changed.json", &forged)
	loadTrustJSON(t, "approval_trusted_keys.json", &approvalKeys)
	now, _ := time.Parse(time.RFC3339, "2026-06-06T12:05:00Z")

	status, err := verifier.VerifyIssuerStatus(issuer, &good, &statusKeys, now)
	if err != nil || status.Status != "good_standing" {
		t.Fatalf("valid status failed: %v", err)
	}
	verified, err := verifier.VerifyApprovalArtifactForAction(approval, approvalKeys, approval.ActionHash)
	if err != nil || verified.ApprovalType != "finance_approver" {
		t.Fatalf("valid approval failed: %v", err)
	}
	_, err = verifier.VerifyIssuerStatus(issuer, &revoked, &statusKeys, now)
	requireTrustCode(t, err, "ISSUER_REVOKED")
	_, err = verifier.VerifyIssuerStatus(issuer, nil, nil, now)
	requireTrustCode(t, err, "ISSUER_STATUS_REQUIRED")
	_, err = verifier.VerifyIssuerStatus(issuer, &stale, &statusKeys, now)
	requireTrustCode(t, err, "ISSUER_STATUS_STALE")
	_, err = verifier.VerifyApprovalArtifactForAction(changed, approvalKeys, approval.ActionHash)
	requireTrustCode(t, err, "APPROVAL_ACTION_MISMATCH")
	_, err = verifier.VerifyApprovalArtifactForAction(forged, approvalKeys, approval.ActionHash)
	requireTrustCode(t, err, "SIGNATURE_INVALID")
}
