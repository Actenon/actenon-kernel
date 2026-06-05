export type JsonScalar = string | number | boolean | null;
export type JsonValue = JsonScalar | JsonValue[] | { [key: string]: JsonValue };

export interface ContractRef {
  name: string;
  version: string;
}

export interface TenantRef {
  tenant_id: string;
  attributes?: Record<string, JsonValue>;
}

export interface PartyRef {
  type: string;
  id: string;
  display_name?: string;
  attributes?: Record<string, JsonValue>;
}

export interface AudienceRef {
  type: string;
  id: string;
  uri?: string;
}

export interface ActionSpec {
  name: string;
  capability: string;
  parameters: Record<string, JsonValue>;
  constraints?: Record<string, JsonValue>;
  scope?: Record<string, JsonValue>;
}

export interface TargetRef {
  resource_type: string;
  resource_id: string;
  uri?: string;
  selectors?: Record<string, JsonValue>;
}

export interface ScopeSpec {
  mode: "exact";
  capabilities: string[];
  single_use: boolean;
  resource_selectors?: Array<Record<string, JsonValue>>;
  parameter_constraints?: Record<string, JsonValue>;
}

export interface ActionHashSpec {
  algorithm: "sha-256";
  canonicalization: "RFC8785-JCS";
  value: string;
}

export interface SignatureSpec {
  algorithm: string;
  key_id: string;
  encoding: string;
  value: string;
}

export interface EscrowReference {
  escrow_id: string;
  single_use?: boolean;
}

export interface ActionIntent {
  contract: ContractRef;
  intent_id: string;
  idempotency_key?: string;
  issued_at: string;
  expires_at: string;
  tenant: TenantRef;
  requester: PartyRef;
  action: ActionSpec;
  target: TargetRef;
  justification?: string;
  context?: Record<string, JsonValue>;
  evidence_refs?: Array<Record<string, JsonValue>>;
  metadata?: Record<string, JsonValue>;
  extensions?: Record<string, JsonValue>;
}

export interface PCCB {
  contract: ContractRef;
  pccb_id: string;
  intent_id?: string;
  issued_at: string;
  not_before: string;
  expires_at: string;
  issuer: PartyRef;
  subject: PartyRef;
  tenant: TenantRef;
  audience: AudienceRef;
  action: ActionSpec;
  target: TargetRef;
  scope: ScopeSpec;
  nonce: string;
  action_hash: ActionHashSpec;
  escrow_reference?: EscrowReference;
  signature: SignatureSpec;
  extensions?: Record<string, JsonValue>;
}

export interface VerificationContext {
  request_id: string;
  audience: AudienceRef;
  now: Date | string;
  scope_capabilities: string[];
  parameter_constraints?: Record<string, JsonValue>;
  resource_selectors?: Array<Record<string, JsonValue>>;
}

export interface VerifiedProtectedRequest {
  intent: ActionIntent;
  pccb: PCCB;
  context: VerificationContext;
}
