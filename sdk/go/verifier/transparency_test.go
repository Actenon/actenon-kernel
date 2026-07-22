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

func transparencyFixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve transparency test file path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "conformance", "vectors", "transparency_log_v1")
}

func loadTransparencyFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(transparencyFixturesDir(t), name))
	if err != nil {
		t.Fatalf("failed to read transparency fixture %s: %v", name, err)
	}
	return raw
}

func loadCheckpoint(t *testing.T, name string) verifier.TransparencyCheckpoint {
	t.Helper()
	value, err := verifier.ParseTransparencyCheckpointJSON(loadTransparencyFixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func loadInclusionProof(t *testing.T) verifier.TransparencyInclusionProof {
	t.Helper()
	value, err := verifier.ParseTransparencyInclusionProofJSON(loadTransparencyFixture(t, "inclusion_proof.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func loadConsistencyProof(t *testing.T) verifier.TransparencyConsistencyProof {
	t.Helper()
	value, err := verifier.ParseTransparencyConsistencyProofJSON(loadTransparencyFixture(t, "consistency_proof.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func loadTransparencyKeys(t *testing.T) verifier.TrustedCounterSignatureKeys {
	t.Helper()
	keys, err := verifier.ParseTrustedCounterSignatureKeysJSON(loadTransparencyFixture(t, "trusted_keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func loadTransparencyCountersignature(t *testing.T, name string) verifier.ReceiptCountersignature {
	t.Helper()
	value, err := verifier.ParseReceiptCountersignatureJSON(loadTransparencyFixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func requireTransparencyErrorCode(t *testing.T, err error, expected string) {
	t.Helper()
	var verificationError *verifier.TransparencyVerificationError
	if !errors.As(err, &verificationError) {
		t.Fatalf("expected transparency verification error, got %v", err)
	}
	if verificationError.Code != expected {
		t.Fatalf("expected %s, got %s", expected, verificationError.Code)
	}
}

func TestTransparencyProofsAndHistoricalKidsVerifyOffline(t *testing.T) {
	keys := loadTransparencyKeys(t)
	oldCheckpoint := loadCheckpoint(t, "checkpoint_old.json")
	newCheckpoint := loadCheckpoint(t, "checkpoint_new.json")

	oldVerified, err := verifier.VerifyCheckpointSignature(oldCheckpoint, keys)
	if err != nil {
		t.Fatal(err)
	}
	newVerified, err := verifier.VerifyCheckpointSignature(newCheckpoint, keys)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := verifier.VerifyInclusion(loadInclusionProof(t).LeafDigest, loadInclusionProof(t), newCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	consistency, err := verifier.VerifyConsistency(oldCheckpoint, newCheckpoint, loadConsistencyProof(t))
	if err != nil {
		t.Fatal(err)
	}

	if oldVerified.KeyID != "fixture-log-2025" || newVerified.KeyID != "fixture-log-2026" {
		t.Fatalf("unexpected checkpoint kids: %s, %s", oldVerified.KeyID, newVerified.KeyID)
	}
	if inclusion.LeafIndex != 2 || consistency.NewTreeSize != 4 {
		t.Fatal("unexpected proof verification result")
	}
}

func TestMonitorRejectsSignedForkAndRewind(t *testing.T) {
	keys := loadTransparencyKeys(t)
	oldCheckpoint := loadCheckpoint(t, "checkpoint_old.json")
	newCheckpoint := loadCheckpoint(t, "checkpoint_new.json")
	proof := loadConsistencyProof(t)

	if _, err := verifier.VerifyMonitorUpdate(oldCheckpoint, newCheckpoint, proof, keys); err != nil {
		t.Fatal(err)
	}
	sameSizeProof := verifier.TransparencyConsistencyProof{
		Contract:        verifier.Contract{Name: "transparency_consistency_proof", Version: "v1"},
		LogID:           "actenon-transparency-fixture",
		HashAlgorithm:   "sha-256",
		OldTreeSize:     4,
		NewTreeSize:     4,
		ConsistencyPath: []string{},
	}
	_, err := verifier.VerifyMonitorUpdate(
		newCheckpoint,
		loadCheckpoint(t, "mutations/checkpoint_new_forked.json"),
		sameSizeProof,
		keys,
	)
	requireTransparencyErrorCode(t, err, "EQUIVOCATION_DETECTED")

	_, err = verifier.VerifyConsistency(newCheckpoint, oldCheckpoint, proof)
	requireTransparencyErrorCode(t, err, "REWIND_DETECTED")
}

func TestCheckpointRejectsUnknownKid(t *testing.T) {
	_, err := verifier.VerifyCheckpointSignature(
		loadCheckpoint(t, "mutations/checkpoint_unknown_kid.json"),
		loadTransparencyKeys(t),
	)
	requireTransparencyErrorCode(t, err, "UNKNOWN_KEY_ID")
}

func TestOrphanCountersignatureIsRejected(t *testing.T) {
	orphan := loadTransparencyCountersignature(t, "mutations/countersignature_orphan.json")
	keys := loadTransparencyKeys(t)
	if _, err := verifier.VerifyCountersignature(orphan.ReceiptDigest, orphan, keys); err != nil {
		t.Fatalf("orphan fixture must have a valid counter-signature: %v", err)
	}
	_, err := verifier.VerifyCountersignatureInclusion(
		orphan,
		loadInclusionProof(t),
		loadCheckpoint(t, "checkpoint_new.json"),
		keys,
	)
	requireTransparencyErrorCode(t, err, "ORPHAN_COUNTERSIGNATURE")
}

func TestTransparencyFixturesAreJSON(t *testing.T) {
	var value any
	if err := json.Unmarshal(loadTransparencyFixture(t, "checkpoint_new.json"), &value); err != nil {
		t.Fatal(err)
	}
}
