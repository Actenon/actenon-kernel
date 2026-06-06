package verifier_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/actenon/sdk-go/verifier"
)

func countersignatureFixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve counter-signature test file path")
	}
	return filepath.Join(
		filepath.Dir(filename),
		"..",
		"..",
		"..",
		"conformance",
		"vectors",
		"receipt_countersignature_v1",
	)
}

func loadCountersignatureFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(countersignatureFixturesDir(t), name))
	if err != nil {
		t.Fatalf("failed to read counter-signature fixture %s: %v", name, err)
	}
	return raw
}

func loadReceiptFixture(t *testing.T) map[string]any {
	t.Helper()
	var receipt map[string]any
	if err := json.Unmarshal(loadCountersignatureFixture(t, "receipt.json"), &receipt); err != nil {
		t.Fatalf("failed to parse receipt fixture: %v", err)
	}
	return receipt
}

func loadCountersignature(t *testing.T, name string) verifier.ReceiptCountersignature {
	t.Helper()
	artifact, err := verifier.ParseReceiptCountersignatureJSON(
		loadCountersignatureFixture(t, name),
	)
	if err != nil {
		t.Fatalf("failed to parse counter-signature fixture: %v", err)
	}
	return artifact
}

func loadTrustedCountersigningKeys(t *testing.T, name string) verifier.TrustedCounterSignatureKeys {
	t.Helper()
	keys, err := verifier.ParseTrustedCounterSignatureKeysJSON(
		loadCountersignatureFixture(t, name),
	)
	if err != nil {
		t.Fatalf("failed to parse trusted key fixture: %v", err)
	}
	return keys
}

func requireCountersignatureErrorCode(t *testing.T, err error, expected string) {
	t.Helper()
	var verificationError *verifier.CountersignatureVerificationError
	if !errors.As(err, &verificationError) {
		t.Fatalf("expected counter-signature verification error, got %v", err)
	}
	if verificationError.Code != expected {
		t.Fatalf("expected %s, got %s", expected, verificationError.Code)
	}
}

func TestCountersignatureVerifiesHistoricalKeyOffline(t *testing.T) {
	verified, err := verifier.VerifyCountersignature(
		loadReceiptFixture(t),
		loadCountersignature(t, "countersignature.json"),
		loadTrustedCountersigningKeys(t, "trusted_keys.json"),
	)
	if err != nil {
		t.Fatalf("expected valid counter-signature, got %v", err)
	}
	if verified.KeyID != "actenon-countersignature-fixture-2025-11" {
		t.Fatalf("unexpected historical key id: %s", verified.KeyID)
	}
}

func TestCountersignatureAcceptsPinnedDigest(t *testing.T) {
	artifact := loadCountersignature(t, "countersignature.json")
	verified, err := verifier.VerifyCountersignature(
		artifact.ReceiptDigest,
		artifact,
		loadTrustedCountersigningKeys(t, "trusted_keys.json"),
	)
	if err != nil {
		t.Fatalf("expected valid digest counter-signature, got %v", err)
	}
	if verified.Witness.ID != "actenon-countersignature-fixture" {
		t.Fatalf("unexpected witness id: %s", verified.Witness.ID)
	}
}

func TestCountersignatureRejectsUnknownKid(t *testing.T) {
	_, err := verifier.VerifyCountersignature(
		loadReceiptFixture(t),
		loadCountersignature(t, "mutations/countersignature_unknown_kid.json"),
		loadTrustedCountersigningKeys(t, "trusted_keys.json"),
	)
	requireCountersignatureErrorCode(t, err, "UNKNOWN_KEY_ID")
}

func TestCountersignatureRejectsWrongKey(t *testing.T) {
	_, err := verifier.VerifyCountersignature(
		loadReceiptFixture(t),
		loadCountersignature(t, "countersignature.json"),
		loadTrustedCountersigningKeys(t, "mutations/trusted_keys_wrong_key.json"),
	)
	requireCountersignatureErrorCode(t, err, "SIGNATURE_INVALID")
}

func TestCountersignatureRejectsAlteredDigest(t *testing.T) {
	_, err := verifier.VerifyCountersignature(
		loadReceiptFixture(t),
		loadCountersignature(t, "mutations/countersignature_altered_digest.json"),
		loadTrustedCountersigningKeys(t, "trusted_keys.json"),
	)
	requireCountersignatureErrorCode(t, err, "RECEIPT_DIGEST_MISMATCH")
}
