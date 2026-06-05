package verifier

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
)

func ParseActionIntentJSON(raw []byte) (ActionIntent, error) {
	var intent ActionIntent
	if err := decodeJSON(raw, &intent, ErrInvalidIntent, "action intent"); err != nil {
		return ActionIntent{}, err
	}
	return normalizeActionIntent(intent)
}

func ParsePCCBJSON(raw []byte) (PCCB, error) {
	var pccb PCCB
	if err := decodeJSON(raw, &pccb, ErrInvalidPCCB, "pccb"); err != nil {
		return PCCB{}, err
	}
	return normalizePCCB(pccb)
}

func decodeJSON(raw []byte, target any, code VerificationErrorCode, artifactName string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return newVerificationError(code, "failed to decode "+artifactName+" JSON payload.", map[string]any{"error": err.Error()})
	}
	if err := ensureNoTrailingJSON(decoder, code, artifactName); err != nil {
		return err
	}
	return nil
}

func ensureNoTrailingJSON(decoder *json.Decoder, code VerificationErrorCode, artifactName string) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return newVerificationError(code, "failed while checking trailing "+artifactName+" JSON content.", map[string]any{"error": err.Error()})
	}
	return newVerificationError(code, artifactName+" JSON payload must contain a single top-level object.", nil)
}

func parseTimestamp(raw string, fieldName string, code VerificationErrorCode) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, newVerificationError(code, fieldName+" must be an RFC3339 timestamp string.", nil)
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, newVerificationError(ErrInvalidTimestamp, fieldName+" must be an RFC3339 timestamp string.", map[string]any{"error": err.Error()})
	}
	return parsed.UTC(), nil
}

func normalizeTimestamp(raw string, fieldName string, code VerificationErrorCode) (string, error) {
	parsed, err := parseTimestamp(raw, fieldName, code)
	if err != nil {
		return "", err
	}
	return parsed.Format(time.RFC3339), nil
}

func normalizeActionIntent(intent ActionIntent) (ActionIntent, error) {
	if intent.Contract.Name != "action_intent" || intent.Contract.Version != "v1" {
		return ActionIntent{}, newVerificationError(ErrInvalidIntent, "contract must declare action_intent v1.", nil)
	}
	if strings.TrimSpace(intent.IntentID) == "" {
		return ActionIntent{}, newVerificationError(ErrInvalidIntent, "action_intent.intent_id must be a non-empty string.", nil)
	}
	issuedAt, err := normalizeTimestamp(intent.IssuedAt, "action_intent.issued_at", ErrInvalidIntent)
	if err != nil {
		return ActionIntent{}, err
	}
	expiresAt, err := normalizeTimestamp(intent.ExpiresAt, "action_intent.expires_at", ErrInvalidIntent)
	if err != nil {
		return ActionIntent{}, err
	}
	tenant, err := normalizeTenantRef(intent.Tenant, "action_intent.tenant", ErrInvalidIntent)
	if err != nil {
		return ActionIntent{}, err
	}
	requester, err := normalizePartyRef(intent.Requester, "action_intent.requester", ErrInvalidIntent)
	if err != nil {
		return ActionIntent{}, err
	}
	action, err := normalizeActionSpec(intent.Action, "action_intent.action", ErrInvalidIntent)
	if err != nil {
		return ActionIntent{}, err
	}
	target, err := normalizeTargetRef(intent.Target, "action_intent.target", ErrInvalidIntent)
	if err != nil {
		return ActionIntent{}, err
	}
	normalized := ActionIntent{
		Contract:       Contract{Name: "action_intent", Version: "v1"},
		IntentID:       intent.IntentID,
		IdempotencyKey: intent.IdempotencyKey,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
		Tenant:         tenant,
		Requester:      requester,
		Action:         action,
		Target:         target,
		Justification:  intent.Justification,
		Context:        cloneJSONObject(intent.Context),
		EvidenceRefs:   cloneJSONObjects(intent.EvidenceRefs),
		Metadata:       cloneJSONObject(intent.Metadata),
		Extensions:     cloneJSONObject(intent.Extensions),
	}
	return normalized, nil
}

func normalizePCCB(pccb PCCB) (PCCB, error) {
	if pccb.Contract.Name != "pccb" || pccb.Contract.Version != "v1" {
		return PCCB{}, newVerificationError(ErrInvalidPCCB, "contract must declare pccb v1.", nil)
	}
	if strings.TrimSpace(pccb.PCCBID) == "" {
		return PCCB{}, newVerificationError(ErrInvalidPCCB, "pccb.pccb_id must be a non-empty string.", nil)
	}
	issuedAt, err := normalizeTimestamp(pccb.IssuedAt, "pccb.issued_at", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	notBefore, err := normalizeTimestamp(pccb.NotBefore, "pccb.not_before", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	expiresAt, err := normalizeTimestamp(pccb.ExpiresAt, "pccb.expires_at", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	issuer, err := normalizePartyRef(pccb.Issuer, "pccb.issuer", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	subject, err := normalizePartyRef(pccb.Subject, "pccb.subject", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	tenant, err := normalizeTenantRef(pccb.Tenant, "pccb.tenant", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	audience, err := normalizeAudienceRef(pccb.Audience, "pccb.audience", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	action, err := normalizeActionSpec(pccb.Action, "pccb.action", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	target, err := normalizeTargetRef(pccb.Target, "pccb.target", ErrInvalidPCCB)
	if err != nil {
		return PCCB{}, err
	}
	scope, err := normalizeScopeSpec(pccb.Scope, "pccb.scope")
	if err != nil {
		return PCCB{}, err
	}
	actionHash, err := normalizeActionHashSpec(pccb.ActionHash, "pccb.action_hash")
	if err != nil {
		return PCCB{}, err
	}
	signature, err := normalizeSignatureSpec(pccb.Signature, "pccb.signature")
	if err != nil {
		return PCCB{}, err
	}
	if strings.TrimSpace(pccb.Nonce) == "" {
		return PCCB{}, newVerificationError(ErrInvalidPCCB, "pccb.nonce must be a non-empty string.", nil)
	}

	normalized := PCCB{
		Contract:        Contract{Name: "pccb", Version: "v1"},
		PCCBID:          pccb.PCCBID,
		IntentID:        pccb.IntentID,
		IssuedAt:        issuedAt,
		NotBefore:       notBefore,
		ExpiresAt:       expiresAt,
		Issuer:          issuer,
		Subject:         subject,
		Tenant:          tenant,
		Audience:        audience,
		Action:          action,
		Target:          target,
		Scope:           scope,
		Nonce:           pccb.Nonce,
		ActionHash:      actionHash,
		Signature:       signature,
		Extensions:      cloneJSONObject(pccb.Extensions),
		EscrowReference: normalizeEscrowReference(pccb.EscrowReference),
	}
	return normalized, nil
}

func normalizeVerificationContext(context VerificationContext) (VerificationContext, error) {
	if strings.TrimSpace(context.RequestID) == "" {
		return VerificationContext{}, newVerificationError(ErrInvalidContext, "context.request_id must be a non-empty string.", nil)
	}
	audience, err := normalizeAudienceRef(context.Audience, "context.audience", ErrInvalidContext)
	if err != nil {
		return VerificationContext{}, err
	}
	if context.Now.IsZero() {
		return VerificationContext{}, newVerificationError(ErrInvalidContext, "context.now must be set.", nil)
	}
	capabilities := cloneStringSlice(context.ScopeCapabilities)
	if len(capabilities) == 0 {
		return VerificationContext{}, newVerificationError(ErrInvalidContext, "context.scope_capabilities must contain at least one capability.", nil)
	}
	return VerificationContext{
		RequestID:            context.RequestID,
		Audience:             audience,
		Now:                  context.Now.UTC(),
		ScopeCapabilities:    capabilities,
		ParameterConstraints: cloneJSONObject(context.ParameterConstraints),
		ResourceSelectors:    cloneJSONObjects(context.ResourceSelectors),
	}, nil
}

func normalizeTenantRef(ref TenantRef, fieldName string, code VerificationErrorCode) (TenantRef, error) {
	if strings.TrimSpace(ref.TenantID) == "" {
		return TenantRef{}, newVerificationError(code, fieldName+".tenant_id must be a non-empty string.", nil)
	}
	return TenantRef{
		TenantID:   ref.TenantID,
		Attributes: cloneJSONObject(ref.Attributes),
	}, nil
}

func normalizePartyRef(ref PartyRef, fieldName string, code VerificationErrorCode) (PartyRef, error) {
	if strings.TrimSpace(ref.Type) == "" {
		return PartyRef{}, newVerificationError(code, fieldName+".type must be a non-empty string.", nil)
	}
	if strings.TrimSpace(ref.ID) == "" {
		return PartyRef{}, newVerificationError(code, fieldName+".id must be a non-empty string.", nil)
	}
	return PartyRef{
		Type:        ref.Type,
		ID:          ref.ID,
		DisplayName: ref.DisplayName,
		Attributes:  cloneJSONObject(ref.Attributes),
	}, nil
}

func normalizeAudienceRef(ref AudienceRef, fieldName string, code VerificationErrorCode) (AudienceRef, error) {
	if strings.TrimSpace(ref.Type) == "" {
		return AudienceRef{}, newVerificationError(code, fieldName+".type must be a non-empty string.", nil)
	}
	if strings.TrimSpace(ref.ID) == "" {
		return AudienceRef{}, newVerificationError(code, fieldName+".id must be a non-empty string.", nil)
	}
	return AudienceRef{
		Type: ref.Type,
		ID:   ref.ID,
		URI:  ref.URI,
	}, nil
}

func normalizeActionSpec(spec ActionSpec, fieldName string, code VerificationErrorCode) (ActionSpec, error) {
	if strings.TrimSpace(spec.Name) == "" {
		return ActionSpec{}, newVerificationError(code, fieldName+".name must be a non-empty string.", nil)
	}
	if strings.TrimSpace(spec.Capability) == "" {
		return ActionSpec{}, newVerificationError(code, fieldName+".capability must be a non-empty string.", nil)
	}
	if spec.Parameters == nil {
		return ActionSpec{}, newVerificationError(code, fieldName+".parameters must be an object.", nil)
	}
	return ActionSpec{
		Name:        spec.Name,
		Capability:  spec.Capability,
		Parameters:  cloneJSONObject(spec.Parameters),
		Constraints: cloneJSONObject(spec.Constraints),
		Scope:       cloneJSONObject(spec.Scope),
	}, nil
}

func normalizeTargetRef(ref TargetRef, fieldName string, code VerificationErrorCode) (TargetRef, error) {
	if strings.TrimSpace(ref.ResourceType) == "" {
		return TargetRef{}, newVerificationError(code, fieldName+".resource_type must be a non-empty string.", nil)
	}
	if strings.TrimSpace(ref.ResourceID) == "" {
		return TargetRef{}, newVerificationError(code, fieldName+".resource_id must be a non-empty string.", nil)
	}
	return TargetRef{
		ResourceType: ref.ResourceType,
		ResourceID:   ref.ResourceID,
		URI:          ref.URI,
		Selectors:    cloneJSONObject(ref.Selectors),
	}, nil
}

func normalizeScopeSpec(scope ScopeSpec, fieldName string) (ScopeSpec, error) {
	if scope.Mode != "exact" {
		return ScopeSpec{}, newVerificationError(ErrInvalidPCCB, fieldName+".mode must be 'exact'.", nil)
	}
	capabilities := cloneStringSlice(scope.Capabilities)
	if len(capabilities) == 0 {
		return ScopeSpec{}, newVerificationError(ErrInvalidPCCB, fieldName+".capabilities must contain at least one capability.", nil)
	}
	return ScopeSpec{
		Mode:                 scope.Mode,
		Capabilities:         capabilities,
		SingleUse:            scope.SingleUse,
		ResourceSelectors:    cloneJSONObjects(scope.ResourceSelectors),
		ParameterConstraints: cloneJSONObject(scope.ParameterConstraints),
	}, nil
}

func normalizeActionHashSpec(ref ActionHashSpec, fieldName string) (ActionHashSpec, error) {
	if strings.TrimSpace(ref.Algorithm) == "" || strings.TrimSpace(ref.Canonicalization) == "" || strings.TrimSpace(ref.Value) == "" {
		return ActionHashSpec{}, newVerificationError(ErrInvalidPCCB, fieldName+" must be fully populated.", nil)
	}
	return ref, nil
}

func normalizeSignatureSpec(ref SignatureSpec, fieldName string) (SignatureSpec, error) {
	if strings.TrimSpace(ref.Algorithm) == "" || strings.TrimSpace(ref.KeyID) == "" || strings.TrimSpace(ref.Encoding) == "" || strings.TrimSpace(ref.Value) == "" {
		return SignatureSpec{}, newVerificationError(ErrInvalidPCCB, fieldName+" must be fully populated.", nil)
	}
	return ref, nil
}

func normalizeEscrowReference(reference *EscrowReference) *EscrowReference {
	if reference == nil || strings.TrimSpace(reference.EscrowID) == "" {
		return nil
	}
	return &EscrowReference{
		EscrowID:  reference.EscrowID,
		SingleUse: reference.SingleUse,
	}
}

func cloneJSONObject(source map[string]any) map[string]any {
	if len(source) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func cloneJSONObjects(source []map[string]any) []map[string]any {
	if len(source) == 0 {
		return []map[string]any{}
	}
	cloned := make([]map[string]any, 0, len(source))
	for _, item := range source {
		cloned = append(cloned, cloneJSONObject(item))
	}
	return cloned
}

func cloneStringSlice(source []string) []string {
	if len(source) == 0 {
		return []string{}
	}
	cloned := append([]string(nil), source...)
	sort.Strings(cloned)
	return cloned
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func normalizedIntentActionHashInput(intent ActionIntent) map[string]any {
	return map[string]any{
		"intent_id":  intent.IntentID,
		"tenant":     tenantRefToMap(intent.Tenant),
		"requester":  partyRefToMap(intent.Requester),
		"action":     actionSpecToMap(intent.Action),
		"target":     targetRefToMap(intent.Target),
		"issued_at":  intent.IssuedAt,
		"expires_at": intent.ExpiresAt,
	}
}

func normalizedUnsignedPCCBPayload(pccb PCCB) map[string]any {
	payload := map[string]any{
		"contract":    map[string]any{"name": "pccb", "version": "v1"},
		"pccb_id":     pccb.PCCBID,
		"issued_at":   pccb.IssuedAt,
		"not_before":  pccb.NotBefore,
		"expires_at":  pccb.ExpiresAt,
		"issuer":      partyRefToMap(pccb.Issuer),
		"subject":     partyRefToMap(pccb.Subject),
		"tenant":      tenantRefToMap(pccb.Tenant),
		"audience":    audienceRefToMap(pccb.Audience),
		"action":      actionSpecToMap(pccb.Action),
		"target":      targetRefToMap(pccb.Target),
		"scope":       scopeSpecToMap(pccb.Scope),
		"nonce":       pccb.Nonce,
		"action_hash": actionHashToMap(pccb.ActionHash),
	}
	if strings.TrimSpace(pccb.IntentID) != "" {
		payload["intent_id"] = pccb.IntentID
	}
	if pccb.EscrowReference != nil {
		payload["escrow_reference"] = map[string]any{
			"escrow_id":  pccb.EscrowReference.EscrowID,
			"single_use": pccb.Scope.SingleUse,
		}
	}
	if len(pccb.Extensions) > 0 {
		payload["extensions"] = cloneJSONObject(pccb.Extensions)
	}
	return payload
}

func tenantRefToMap(ref TenantRef) map[string]any {
	payload := map[string]any{
		"tenant_id": ref.TenantID,
	}
	if len(ref.Attributes) > 0 {
		payload["attributes"] = cloneJSONObject(ref.Attributes)
	}
	return payload
}

func partyRefToMap(ref PartyRef) map[string]any {
	payload := map[string]any{
		"type": ref.Type,
		"id":   ref.ID,
	}
	if ref.DisplayName != "" {
		payload["display_name"] = ref.DisplayName
	}
	if len(ref.Attributes) > 0 {
		payload["attributes"] = cloneJSONObject(ref.Attributes)
	}
	return payload
}

func audienceRefToMap(ref AudienceRef) map[string]any {
	payload := map[string]any{
		"type": ref.Type,
		"id":   ref.ID,
	}
	if ref.URI != "" {
		payload["uri"] = ref.URI
	}
	return payload
}

func actionSpecToMap(spec ActionSpec) map[string]any {
	payload := map[string]any{
		"name":       spec.Name,
		"capability": spec.Capability,
		"parameters": cloneJSONObject(spec.Parameters),
	}
	if len(spec.Constraints) > 0 {
		payload["constraints"] = cloneJSONObject(spec.Constraints)
	}
	if len(spec.Scope) > 0 {
		payload["scope"] = cloneJSONObject(spec.Scope)
	}
	return payload
}

func targetRefToMap(ref TargetRef) map[string]any {
	payload := map[string]any{
		"resource_type": ref.ResourceType,
		"resource_id":   ref.ResourceID,
	}
	if ref.URI != "" {
		payload["uri"] = ref.URI
	}
	if len(ref.Selectors) > 0 {
		payload["selectors"] = cloneJSONObject(ref.Selectors)
	}
	return payload
}

func scopeSpecToMap(scope ScopeSpec) map[string]any {
	payload := map[string]any{
		"mode":        scope.Mode,
		"capabilities": cloneStringSlice(scope.Capabilities),
		"single_use":  scope.SingleUse,
	}
	if len(scope.ResourceSelectors) > 0 {
		payload["resource_selectors"] = cloneJSONObjects(scope.ResourceSelectors)
	}
	if len(scope.ParameterConstraints) > 0 {
		payload["parameter_constraints"] = cloneJSONObject(scope.ParameterConstraints)
	}
	return payload
}

func actionHashToMap(ref ActionHashSpec) map[string]any {
	return map[string]any{
		"algorithm":        ref.Algorithm,
		"canonicalization": ref.Canonicalization,
		"value":            ref.Value,
	}
}

func normalizedEqual(left any, right any) bool {
	return reflect.DeepEqual(left, right)
}
