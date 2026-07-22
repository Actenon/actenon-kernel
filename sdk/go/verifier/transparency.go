package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

const (
	TransparencyCheckpointContext = "actenon.transparency-checkpoint.v1"
	TransparencyCheckpointKeyUse  = "transparency_checkpoint"
)

type TransparencyVerificationError struct {
	Code    string
	Message string
}

func (e *TransparencyVerificationError) Error() string {
	return e.Code + ": " + e.Message
}

type TreeHash struct {
	Algorithm string `json:"algorithm"`
	Encoding  string `json:"encoding"`
	Value     string `json:"value"`
}

type TransparencyCheckpoint struct {
	Contract  Contract      `json:"contract"`
	Log       PartyRef      `json:"log"`
	TreeSize  uint64        `json:"tree_size"`
	RootHash  TreeHash      `json:"root_hash"`
	IssuedAt  string        `json:"issued_at"`
	Signature SignatureSpec `json:"signature"`
}

type TransparencyInclusionProof struct {
	Contract      Contract      `json:"contract"`
	LogID         string        `json:"log_id"`
	HashAlgorithm string        `json:"hash_algorithm"`
	TreeSize      uint64        `json:"tree_size"`
	LeafIndex     uint64        `json:"leaf_index"`
	LeafDigest    ReceiptDigest `json:"leaf_digest"`
	AuditPath     []string      `json:"audit_path"`
}

type TransparencyConsistencyProof struct {
	Contract        Contract `json:"contract"`
	LogID           string   `json:"log_id"`
	HashAlgorithm   string   `json:"hash_algorithm"`
	OldTreeSize     uint64   `json:"old_tree_size"`
	NewTreeSize     uint64   `json:"new_tree_size"`
	ConsistencyPath []string `json:"consistency_path"`
}

type VerifiedCheckpoint struct {
	Log      PartyRef
	TreeSize uint64
	RootHash string
	IssuedAt time.Time
	KeyID    string
}

type VerifiedInclusion struct {
	LogID      string
	TreeSize   uint64
	LeafIndex  uint64
	LeafDigest ReceiptDigest
	Checkpoint *VerifiedCheckpoint
}

type VerifiedConsistency struct {
	LogID       string
	OldTreeSize uint64
	NewTreeSize uint64
}

type VerifiedMonitorUpdate struct {
	Previous    VerifiedCheckpoint
	Current     VerifiedCheckpoint
	Consistency VerifiedConsistency
}

func transparencyError(code string, message string) error {
	return &TransparencyVerificationError{Code: code, Message: message}
}

func ParseTransparencyCheckpointJSON(raw []byte) (TransparencyCheckpoint, error) {
	var checkpoint TransparencyCheckpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return TransparencyCheckpoint{}, transparencyError("INVALID_CHECKPOINT", "checkpoint must be valid JSON")
	}
	return checkpoint, nil
}

func ParseTransparencyInclusionProofJSON(raw []byte) (TransparencyInclusionProof, error) {
	var proof TransparencyInclusionProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		return TransparencyInclusionProof{}, transparencyError("INVALID_INCLUSION_PROOF", "inclusion proof must be valid JSON")
	}
	return proof, nil
}

func ParseTransparencyConsistencyProofJSON(raw []byte) (TransparencyConsistencyProof, error) {
	var proof TransparencyConsistencyProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		return TransparencyConsistencyProof{}, transparencyError("INVALID_CONSISTENCY_PROOF", "consistency proof must be valid JSON")
	}
	return proof, nil
}

func VerifyCheckpointSignature(
	checkpoint TransparencyCheckpoint,
	trustedKeys TrustedCounterSignatureKeys,
) (VerifiedCheckpoint, error) {
	rootHash, issuedAt, err := validateCheckpoint(checkpoint)
	if err != nil {
		return VerifiedCheckpoint{}, err
	}
	if checkpoint.Signature.Algorithm != "EdDSA" || checkpoint.Signature.Encoding != "base64url" {
		return VerifiedCheckpoint{}, transparencyError("UNSUPPORTED_ALGORITHM", "transparency checkpoint v1 supports EdDSA/Ed25519 with base64url encoding")
	}
	if trustedKeys.Contract.Name != "key_discovery" || trustedKeys.Contract.Version != "v1" || len(trustedKeys.Keys) == 0 {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", "trusted key set must declare key_discovery v1 with at least one key")
	}
	if trustedKeys.Issuer.Type != checkpoint.Log.Type || trustedKeys.Issuer.ID != checkpoint.Log.ID {
		return VerifiedCheckpoint{}, transparencyError("LOG_IDENTITY_MISMATCH", "checkpoint log identity does not match the trusted key-set issuer")
	}
	matches := make([]TrustedCountersigningKey, 0, 1)
	for _, key := range trustedKeys.Keys {
		if key.KeyID == checkpoint.Signature.KeyID {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return VerifiedCheckpoint{}, transparencyError("UNKNOWN_KEY_ID", fmt.Sprintf("no trusted checkpoint key matched key_id %q", checkpoint.Signature.KeyID))
	}
	if len(matches) != 1 {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", fmt.Sprintf("trusted key set contains duplicate key_id %q", checkpoint.Signature.KeyID))
	}
	key := matches[0]
	if key.Algorithm != checkpoint.Signature.Algorithm {
		return VerifiedCheckpoint{}, transparencyError("SIGNATURE_INVALID", "trusted key algorithm does not match the checkpoint signature")
	}
	uses, err := normalizeCountersignatureUses(key.Use)
	if err != nil {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", "trusted key use must be a non-empty string or array")
	}
	if !containsString(uses, TransparencyCheckpointKeyUse) {
		return VerifiedCheckpoint{}, transparencyError("KEY_PURPOSE_MISMATCH", "trusted key is not authorized for transparency checkpoints")
	}
	if key.Status != "active" && key.Status != "retired" {
		return VerifiedCheckpoint{}, transparencyError("KEY_NOT_VALID", "trusted checkpoint key is not active or retired")
	}
	if err := validateTransparencyKeyTime(key, issuedAt); err != nil {
		return VerifiedCheckpoint{}, err
	}
	if key.PublicKeyJWK["kty"] != "OKP" || key.PublicKeyJWK["crv"] != "Ed25519" {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", "checkpoint key must be an Ed25519 OKP JWK")
	}
	if kid, ok := key.PublicKeyJWK["kid"].(string); ok && kid != checkpoint.Signature.KeyID {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", "public_key_jwk.kid does not match signature.key_id")
	}
	if algorithm, ok := key.PublicKeyJWK["alg"].(string); ok && algorithm != "EdDSA" {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", "public_key_jwk.alg must be EdDSA")
	}
	x, ok := key.PublicKeyJWK["x"].(string)
	if !ok || x == "" {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", "public_key_jwk.x must be a base64url string")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return VerifiedCheckpoint{}, transparencyError("TRUSTED_KEYS_INVALID", "public_key_jwk.x must encode a 32-byte Ed25519 public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedCheckpoint{}, transparencyError("SIGNATURE_INVALID", "checkpoint signature must encode a 64-byte Ed25519 signature")
	}
	statement := map[string]any{
		"context":   TransparencyCheckpointContext,
		"log":       partyRefMap(checkpoint.Log),
		"tree_size": checkpoint.TreeSize,
		"root_hash": map[string]any{
			"algorithm": "sha-256",
			"encoding":  "hex",
			"value":     hex.EncodeToString(rootHash[:]),
		},
		"issued_at": checkpoint.IssuedAt,
	}
	payload, err := canonicalizeBytes(statement)
	if err != nil {
		return VerifiedCheckpoint{}, transparencyError("INVALID_CHECKPOINT", "checkpoint statement could not be canonicalized")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return VerifiedCheckpoint{}, transparencyError("SIGNATURE_INVALID", "transparency checkpoint signature could not be verified")
	}
	return VerifiedCheckpoint{
		Log:      checkpoint.Log,
		TreeSize: checkpoint.TreeSize,
		RootHash: hex.EncodeToString(rootHash[:]),
		IssuedAt: issuedAt,
		KeyID:    checkpoint.Signature.KeyID,
	}, nil
}

func VerifyInclusion(
	digest ReceiptDigest,
	proof TransparencyInclusionProof,
	checkpoint TransparencyCheckpoint,
) (VerifiedInclusion, error) {
	if err := validateTransparencyDigest(digest); err != nil {
		return VerifiedInclusion{}, err
	}
	if proof.Contract.Name != "transparency_inclusion_proof" || proof.Contract.Version != "v1" {
		return VerifiedInclusion{}, transparencyError("INVALID_INCLUSION_PROOF", "proof contract must declare transparency_inclusion_proof v1")
	}
	if proof.HashAlgorithm != "sha-256" {
		return VerifiedInclusion{}, transparencyError("INVALID_INCLUSION_PROOF", "inclusion proof hash_algorithm must be sha-256")
	}
	if err := validateTransparencyDigest(proof.LeafDigest); err != nil {
		return VerifiedInclusion{}, err
	}
	if proof.LeafDigest != digest {
		return VerifiedInclusion{}, transparencyError("LEAF_DIGEST_MISMATCH", "inclusion proof leaf digest does not match the supplied digest")
	}
	if proof.LogID == "" || proof.TreeSize == 0 || proof.LeafIndex >= proof.TreeSize {
		return VerifiedInclusion{}, transparencyError("INVALID_INCLUSION_PROOF", "inclusion proof log and leaf bounds are invalid")
	}
	rootHash, _, err := validateCheckpoint(checkpoint)
	if err != nil {
		return VerifiedInclusion{}, err
	}
	if checkpoint.Log.ID != proof.LogID || checkpoint.TreeSize != proof.TreeSize {
		return VerifiedInclusion{}, transparencyError("CHECKPOINT_MISMATCH", "inclusion proof log or tree size does not match the checkpoint")
	}
	path, err := decodeTransparencyPath(proof.AuditPath, "INVALID_INCLUSION_PROOF")
	if err != nil {
		return VerifiedInclusion{}, err
	}
	node, err := transparencyLeafHash(digest)
	if err != nil {
		return VerifiedInclusion{}, err
	}
	fn := proof.LeafIndex
	sn := proof.TreeSize - 1
	for _, sibling := range path {
		if fn&1 == 1 || fn == sn {
			node = transparencyNodeHash(sibling, node)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			node = transparencyNodeHash(node, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || node != rootHash {
		return VerifiedInclusion{}, transparencyError("INCLUSION_PROOF_INVALID", "digest is not included in the supplied checkpoint")
	}
	return VerifiedInclusion{
		LogID:      proof.LogID,
		TreeSize:   proof.TreeSize,
		LeafIndex:  proof.LeafIndex,
		LeafDigest: digest,
	}, nil
}

func VerifyConsistency(
	oldCheckpoint TransparencyCheckpoint,
	newCheckpoint TransparencyCheckpoint,
	proof TransparencyConsistencyProof,
) (VerifiedConsistency, error) {
	oldRoot, _, err := validateCheckpoint(oldCheckpoint)
	if err != nil {
		return VerifiedConsistency{}, err
	}
	newRoot, _, err := validateCheckpoint(newCheckpoint)
	if err != nil {
		return VerifiedConsistency{}, err
	}
	if oldCheckpoint.Log.Type != newCheckpoint.Log.Type || oldCheckpoint.Log.ID != newCheckpoint.Log.ID {
		return VerifiedConsistency{}, transparencyError("LOG_IDENTITY_MISMATCH", "consistency checkpoints identify different logs")
	}
	if newCheckpoint.TreeSize < oldCheckpoint.TreeSize {
		return VerifiedConsistency{}, transparencyError("REWIND_DETECTED", "new checkpoint tree size is smaller than the previous checkpoint")
	}
	if proof.Contract.Name != "transparency_consistency_proof" || proof.Contract.Version != "v1" || proof.HashAlgorithm != "sha-256" {
		return VerifiedConsistency{}, transparencyError("INVALID_CONSISTENCY_PROOF", "proof must declare transparency_consistency_proof v1 with sha-256")
	}
	if proof.LogID != oldCheckpoint.Log.ID || proof.OldTreeSize != oldCheckpoint.TreeSize || proof.NewTreeSize != newCheckpoint.TreeSize {
		return VerifiedConsistency{}, transparencyError("CHECKPOINT_MISMATCH", "consistency proof does not match the supplied checkpoints")
	}
	path, err := decodeTransparencyPath(proof.ConsistencyPath, "INVALID_CONSISTENCY_PROOF")
	if err != nil {
		return VerifiedConsistency{}, err
	}
	oldSize := oldCheckpoint.TreeSize
	newSize := newCheckpoint.TreeSize
	switch {
	case oldSize == 0:
		if len(path) != 0 {
			return VerifiedConsistency{}, transparencyError("CONSISTENCY_PROOF_INVALID", "empty-tree consistency proof must have an empty path")
		}
	case oldSize == newSize:
		if len(path) != 0 || oldRoot != newRoot {
			return VerifiedConsistency{}, transparencyError("EQUIVOCATION_DETECTED", "same-size checkpoints have different roots or a non-empty proof")
		}
	default:
		fn := oldSize - 1
		sn := newSize - 1
		for fn&1 == 1 {
			fn >>= 1
			sn >>= 1
		}
		var first [32]byte
		var second [32]byte
		proofIndex := 0
		if fn == 0 {
			first = oldRoot
			second = oldRoot
		} else {
			if len(path) == 0 {
				return VerifiedConsistency{}, transparencyError("CONSISTENCY_PROOF_INVALID", "consistency proof path is incomplete")
			}
			first = path[0]
			second = path[0]
			proofIndex = 1
		}
		for proofIndex < len(path) {
			if sn == 0 {
				return VerifiedConsistency{}, transparencyError("CONSISTENCY_PROOF_INVALID", "consistency proof path contains extra hashes")
			}
			sibling := path[proofIndex]
			if fn&1 == 1 || fn == sn {
				first = transparencyNodeHash(sibling, first)
				second = transparencyNodeHash(sibling, second)
				for fn != 0 && fn&1 == 0 {
					fn >>= 1
					sn >>= 1
				}
			} else {
				second = transparencyNodeHash(second, sibling)
			}
			fn >>= 1
			sn >>= 1
			proofIndex++
		}
		if sn != 0 || first != oldRoot || second != newRoot {
			return VerifiedConsistency{}, transparencyError("CONSISTENCY_PROOF_INVALID", "checkpoints are not append-only consistent")
		}
	}
	return VerifiedConsistency{
		LogID:       proof.LogID,
		OldTreeSize: oldSize,
		NewTreeSize: newSize,
	}, nil
}

func VerifyCountersignatureInclusion(
	countersignature ReceiptCountersignature,
	proof TransparencyInclusionProof,
	checkpoint TransparencyCheckpoint,
	trustedKeys TrustedCounterSignatureKeys,
) (VerifiedInclusion, error) {
	if countersignature.Contract.Name != "receipt_countersignature" || countersignature.Contract.Version != "v1" {
		return VerifiedInclusion{}, transparencyError("INVALID_COUNTERSIGNATURE", "contract must declare receipt_countersignature v1")
	}
	if countersignature.AnchorReference == nil || countersignature.AnchorReference["type"] != "transparency_log" {
		return VerifiedInclusion{}, transparencyError("ORPHAN_COUNTERSIGNATURE", "counter-signature is not anchored to a transparency log")
	}
	anchorLogID, ok := countersignature.AnchorReference["id"].(string)
	if !ok || anchorLogID == "" {
		return VerifiedInclusion{}, transparencyError("ORPHAN_COUNTERSIGNATURE", "counter-signature anchor id is invalid")
	}
	anchorLeafIndex, ok := nonnegativeJSONInteger(countersignature.AnchorReference["leaf_index"])
	if !ok {
		return VerifiedInclusion{}, transparencyError("ORPHAN_COUNTERSIGNATURE", "counter-signature anchor leaf_index is invalid")
	}
	verifiedCheckpoint, err := VerifyCheckpointSignature(checkpoint, trustedKeys)
	if err != nil {
		return VerifiedInclusion{}, err
	}
	if countersignature.ReceiptDigest != proof.LeafDigest {
		return VerifiedInclusion{}, transparencyError("ORPHAN_COUNTERSIGNATURE", "counter-signature digest is not the digest proven at the declared log leaf")
	}
	inclusion, err := VerifyInclusion(countersignature.ReceiptDigest, proof, checkpoint)
	if err != nil {
		return VerifiedInclusion{}, err
	}
	if anchorLogID != inclusion.LogID || anchorLeafIndex != inclusion.LeafIndex {
		return VerifiedInclusion{}, transparencyError("ORPHAN_COUNTERSIGNATURE", "counter-signature anchor does not match the verified inclusion proof")
	}
	inclusion.Checkpoint = &verifiedCheckpoint
	return inclusion, nil
}

func VerifyMonitorUpdate(
	previousCheckpoint TransparencyCheckpoint,
	currentCheckpoint TransparencyCheckpoint,
	proof TransparencyConsistencyProof,
	trustedKeys TrustedCounterSignatureKeys,
) (VerifiedMonitorUpdate, error) {
	previous, err := VerifyCheckpointSignature(previousCheckpoint, trustedKeys)
	if err != nil {
		return VerifiedMonitorUpdate{}, err
	}
	current, err := VerifyCheckpointSignature(currentCheckpoint, trustedKeys)
	if err != nil {
		return VerifiedMonitorUpdate{}, err
	}
	consistency, err := VerifyConsistency(previousCheckpoint, currentCheckpoint, proof)
	if err != nil {
		return VerifiedMonitorUpdate{}, err
	}
	return VerifiedMonitorUpdate{
		Previous:    previous,
		Current:     current,
		Consistency: consistency,
	}, nil
}

func validateCheckpoint(checkpoint TransparencyCheckpoint) ([32]byte, time.Time, error) {
	if checkpoint.Contract.Name != "transparency_checkpoint" || checkpoint.Contract.Version != "v1" {
		return [32]byte{}, time.Time{}, transparencyError("INVALID_CHECKPOINT", "checkpoint contract must declare transparency_checkpoint v1")
	}
	if checkpoint.Log.Type == "" || checkpoint.Log.ID == "" {
		return [32]byte{}, time.Time{}, transparencyError("INVALID_CHECKPOINT", "checkpoint log must include type and id")
	}
	if checkpoint.RootHash.Algorithm != "sha-256" || checkpoint.RootHash.Encoding != "hex" || !sha256HexPattern.MatchString(checkpoint.RootHash.Value) {
		return [32]byte{}, time.Time{}, transparencyError("INVALID_CHECKPOINT", "checkpoint root_hash must declare sha-256 with a lowercase hex value")
	}
	rootBytes, _ := hex.DecodeString(checkpoint.RootHash.Value)
	var root [32]byte
	copy(root[:], rootBytes)
	issuedAt, err := time.Parse(time.RFC3339, checkpoint.IssuedAt)
	if err != nil {
		return [32]byte{}, time.Time{}, transparencyError("INVALID_CHECKPOINT", "checkpoint issued_at must be RFC3339")
	}
	if checkpoint.Signature.Algorithm == "" || checkpoint.Signature.KeyID == "" || checkpoint.Signature.Encoding == "" || checkpoint.Signature.Value == "" {
		return [32]byte{}, time.Time{}, transparencyError("INVALID_CHECKPOINT", "checkpoint signature is incomplete")
	}
	return root, issuedAt, nil
}

func validateTransparencyDigest(digest ReceiptDigest) error {
	if digest.Algorithm != "sha-256" || digest.Canonicalization != "RFC8785-JCS" || !sha256HexPattern.MatchString(digest.Value) {
		return transparencyError("INVALID_LEAF_DIGEST", "leaf digest must declare sha-256, RFC8785-JCS, and a lowercase 64-character hex value")
	}
	return nil
}

func validateTransparencyKeyTime(key TrustedCountersigningKey, issuedAt time.Time) error {
	for _, check := range []struct {
		raw       string
		inclusive bool
		message   string
	}{
		{key.NotBefore, false, "trusted checkpoint key was not valid at signing time"},
		{key.ExpiresAt, true, "trusted checkpoint key was expired at signing time"},
		{key.RevokedAt, true, "trusted checkpoint key was revoked at signing time"},
	} {
		if check.raw == "" {
			continue
		}
		bound, err := time.Parse(time.RFC3339, check.raw)
		if err != nil {
			return transparencyError("TRUSTED_KEYS_INVALID", "checkpoint key validity bounds must be RFC3339")
		}
		if (!check.inclusive && issuedAt.Before(bound)) || (check.inclusive && !issuedAt.Before(bound)) {
			return transparencyError("KEY_NOT_VALID", check.message)
		}
	}
	return nil
}

func decodeTransparencyPath(values []string, code string) ([][32]byte, error) {
	path := make([][32]byte, len(values))
	for index, value := range values {
		if !sha256HexPattern.MatchString(value) {
			return nil, transparencyError(code, "proof path entries must be lowercase 64-character SHA-256 hex values")
		}
		decoded, _ := hex.DecodeString(value)
		copy(path[index][:], decoded)
	}
	return path, nil
}

func transparencyLeafHash(digest ReceiptDigest) ([32]byte, error) {
	decoded, err := hex.DecodeString(digest.Value)
	if err != nil || len(decoded) != sha256.Size {
		return [32]byte{}, transparencyError("INVALID_LEAF_DIGEST", "leaf digest value is invalid")
	}
	payload := append([]byte{0}, decoded...)
	return sha256.Sum256(payload), nil
}

func transparencyNodeHash(left [32]byte, right [32]byte) [32]byte {
	payload := make([]byte, 1, 1+sha256.Size*2)
	payload[0] = 1
	payload = append(payload, left[:]...)
	payload = append(payload, right[:]...)
	return sha256.Sum256(payload)
}

func nonnegativeJSONInteger(value any) (uint64, bool) {
	switch number := value.(type) {
	case json.Number:
		parsed, err := number.Int64()
		if err != nil || parsed < 0 {
			return 0, false
		}
		return uint64(parsed), true
	case float64:
		if number < 0 || number > math.MaxUint64 || math.Trunc(number) != number {
			return 0, false
		}
		return uint64(number), true
	case uint64:
		return number, true
	case int:
		if number < 0 {
			return 0, false
		}
		return uint64(number), true
	default:
		return 0, false
	}
}
