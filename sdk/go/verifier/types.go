package verifier

import "time"

type Contract struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type TenantRef struct {
	TenantID   string         `json:"tenant_id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

type PartyRef struct {
	Type        string         `json:"type"`
	ID          string         `json:"id"`
	DisplayName string         `json:"display_name,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty"`
}

type AudienceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	URI  string `json:"uri,omitempty"`
}

type ActionSpec struct {
	Name       string         `json:"name"`
	Capability string         `json:"capability"`
	Parameters map[string]any `json:"parameters"`
	Constraints map[string]any `json:"constraints,omitempty"`
	Scope      map[string]any `json:"scope,omitempty"`
}

type TargetRef struct {
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	URI          string         `json:"uri,omitempty"`
	Selectors    map[string]any `json:"selectors,omitempty"`
}

type ScopeSpec struct {
	Mode                 string           `json:"mode"`
	Capabilities         []string         `json:"capabilities"`
	SingleUse            bool             `json:"single_use"`
	ResourceSelectors    []map[string]any `json:"resource_selectors,omitempty"`
	ParameterConstraints map[string]any   `json:"parameter_constraints,omitempty"`
}

type ActionHashSpec struct {
	Algorithm        string `json:"algorithm"`
	Canonicalization string `json:"canonicalization"`
	Value            string `json:"value"`
}

type EscrowReference struct {
	EscrowID  string `json:"escrow_id"`
	SingleUse bool   `json:"single_use,omitempty"`
}

type SignatureSpec struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Encoding  string `json:"encoding"`
	Value     string `json:"value"`
}

type ActionIntent struct {
	Contract       Contract         `json:"contract"`
	IntentID       string           `json:"intent_id"`
	IdempotencyKey string           `json:"idempotency_key,omitempty"`
	IssuedAt       string           `json:"issued_at"`
	ExpiresAt      string           `json:"expires_at"`
	Tenant         TenantRef        `json:"tenant"`
	Requester      PartyRef         `json:"requester"`
	Action         ActionSpec       `json:"action"`
	Target         TargetRef        `json:"target"`
	Justification  string           `json:"justification,omitempty"`
	Context        map[string]any   `json:"context,omitempty"`
	EvidenceRefs   []map[string]any `json:"evidence_refs,omitempty"`
	Metadata       map[string]any   `json:"metadata,omitempty"`
	Extensions     map[string]any   `json:"extensions,omitempty"`
}

type PCCB struct {
	Contract        Contract         `json:"contract"`
	PCCBID          string           `json:"pccb_id"`
	IntentID        string           `json:"intent_id,omitempty"`
	IssuedAt        string           `json:"issued_at"`
	NotBefore       string           `json:"not_before"`
	ExpiresAt       string           `json:"expires_at"`
	Issuer          PartyRef         `json:"issuer"`
	Subject         PartyRef         `json:"subject"`
	Tenant          TenantRef        `json:"tenant"`
	Audience        AudienceRef      `json:"audience"`
	Action          ActionSpec       `json:"action"`
	Target          TargetRef        `json:"target"`
	Scope           ScopeSpec        `json:"scope"`
	Nonce           string           `json:"nonce"`
	ActionHash      ActionHashSpec   `json:"action_hash"`
	EscrowReference *EscrowReference `json:"escrow_reference,omitempty"`
	Signature       SignatureSpec    `json:"signature"`
	Extensions      map[string]any   `json:"extensions,omitempty"`
}

type VerificationContext struct {
	RequestID            string
	Audience             AudienceRef
	Now                  time.Time
	ScopeCapabilities    []string
	ParameterConstraints map[string]any
	ResourceSelectors    []map[string]any
}

type VerifiedProtectedRequest struct {
	Intent  ActionIntent
	PCCB    PCCB
	Context VerificationContext
}
