import { isDeepStrictEqual } from "node:util";

import { canonicalizeBytes, sha256Hex } from "./canonical.js";
import { VerificationError } from "./errors.js";
import type {
  ActionIntent,
  ActionSpec,
  AudienceRef,
  JsonValue,
  PCCB,
  PartyRef,
  ScopeSpec,
  SignatureSpec,
  TargetRef,
  TenantRef,
  VerificationContext,
  VerifiedProtectedRequest,
} from "./types.js";
import type { SignatureVerifier } from "./signers.js";

function requireRecord(value: unknown, fieldName: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new VerificationError("INVALID_CONTEXT", `${fieldName} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB" | "INVALID_CONTEXT"): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new VerificationError(code, `${fieldName} must be a non-empty string.`);
  }
  return value;
}

function requireBoolean(value: unknown, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB"): boolean {
  if (typeof value !== "boolean") {
    throw new VerificationError(code, `${fieldName} must be a boolean.`);
  }
  return value;
}

function requireStringArray(value: unknown, fieldName: string, code: "INVALID_PCCB" | "INVALID_CONTEXT"): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new VerificationError(code, `${fieldName} must be an array of non-empty strings.`);
  }
  return [...value];
}

function requireRecordArray(value: unknown, fieldName: string, code: "INVALID_PCCB" | "INVALID_CONTEXT"): Array<Record<string, JsonValue>> {
  if (!Array.isArray(value)) {
    throw new VerificationError(code, `${fieldName} must be an array of objects.`);
  }
  return value.map((item, index) => requireRecord(item, `${fieldName}[${index}]`) as Record<string, JsonValue>);
}

function parseTimestamp(raw: unknown, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB" | "INVALID_CONTEXT"): Date {
  if (typeof raw !== "string") {
    throw new VerificationError(code, `${fieldName} must be an RFC3339 timestamp string.`);
  }
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    throw new VerificationError("INVALID_TIMESTAMP", `${fieldName} must be an RFC3339 timestamp string.`);
  }
  return parsed;
}

function formatTimestamp(date: Date): string {
  return date.toISOString().replace(".000Z", "Z");
}

function normalizeTimestamp(raw: string, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB"): string {
  return formatTimestamp(parseTimestamp(raw, fieldName, code));
}

function parseTenantRef(raw: unknown, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB"): TenantRef {
  const data = requireRecord(raw, fieldName);
  const tenant_id = requireString(data.tenant_id, `${fieldName}.tenant_id`, code);
  const tenant: TenantRef = { tenant_id };
  if (data.attributes !== undefined) {
    tenant.attributes = requireRecord(data.attributes, `${fieldName}.attributes`) as Record<string, JsonValue>;
  }
  return tenant;
}

function parsePartyRef(raw: unknown, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB"): PartyRef {
  const data = requireRecord(raw, fieldName);
  const party: PartyRef = {
    type: requireString(data.type, `${fieldName}.type`, code),
    id: requireString(data.id, `${fieldName}.id`, code),
  };
  if (data.display_name !== undefined) {
    party.display_name = requireString(data.display_name, `${fieldName}.display_name`, code);
  }
  if (data.attributes !== undefined) {
    party.attributes = requireRecord(data.attributes, `${fieldName}.attributes`) as Record<string, JsonValue>;
  }
  return party;
}

function parseAudienceRef(raw: unknown, fieldName: string, code: "INVALID_PCCB" | "INVALID_CONTEXT"): AudienceRef {
  const data = requireRecord(raw, fieldName);
  const audience: AudienceRef = {
    type: requireString(data.type, `${fieldName}.type`, code),
    id: requireString(data.id, `${fieldName}.id`, code),
  };
  if (data.uri !== undefined) {
    audience.uri = requireString(data.uri, `${fieldName}.uri`, code);
  }
  return audience;
}

function parseActionSpec(raw: unknown, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB"): ActionSpec {
  const data = requireRecord(raw, fieldName);
  const action: ActionSpec = {
    name: requireString(data.name, `${fieldName}.name`, code),
    capability: requireString(data.capability, `${fieldName}.capability`, code),
    parameters: requireRecord(data.parameters, `${fieldName}.parameters`) as Record<string, JsonValue>,
  };
  if (data.constraints !== undefined) {
    action.constraints = requireRecord(data.constraints, `${fieldName}.constraints`) as Record<string, JsonValue>;
  }
  if (data.scope !== undefined) {
    action.scope = requireRecord(data.scope, `${fieldName}.scope`) as Record<string, JsonValue>;
  }
  return action;
}

function parseTargetRef(raw: unknown, fieldName: string, code: "INVALID_INTENT" | "INVALID_PCCB"): TargetRef {
  const data = requireRecord(raw, fieldName);
  const target: TargetRef = {
    resource_type: requireString(data.resource_type, `${fieldName}.resource_type`, code),
    resource_id: requireString(data.resource_id, `${fieldName}.resource_id`, code),
  };
  if (data.uri !== undefined) {
    target.uri = requireString(data.uri, `${fieldName}.uri`, code);
  }
  if (data.selectors !== undefined) {
    target.selectors = requireRecord(data.selectors, `${fieldName}.selectors`) as Record<string, JsonValue>;
  }
  return target;
}

function parseScopeSpec(raw: unknown, fieldName: string): ScopeSpec {
  const data = requireRecord(raw, fieldName);
  const mode = data.mode;
  if (mode !== "exact") {
    throw new VerificationError("INVALID_PCCB", `${fieldName}.mode must be 'exact'.`);
  }
  const scope: ScopeSpec = {
    mode,
    capabilities: requireStringArray(data.capabilities, `${fieldName}.capabilities`, "INVALID_PCCB"),
    single_use: requireBoolean(data.single_use, `${fieldName}.single_use`, "INVALID_PCCB"),
  };
  if (data.resource_selectors !== undefined) {
    scope.resource_selectors = requireRecordArray(data.resource_selectors, `${fieldName}.resource_selectors`, "INVALID_PCCB");
  }
  if (data.parameter_constraints !== undefined) {
    scope.parameter_constraints = requireRecord(
      data.parameter_constraints,
      `${fieldName}.parameter_constraints`,
    ) as Record<string, JsonValue>;
  }
  return scope;
}

function parseSignatureSpec(raw: unknown, fieldName: string): SignatureSpec {
  const data = requireRecord(raw, fieldName);
  return {
    algorithm: requireString(data.algorithm, `${fieldName}.algorithm`, "INVALID_PCCB"),
    key_id: requireString(data.key_id, `${fieldName}.key_id`, "INVALID_PCCB"),
    encoding: requireString(data.encoding, `${fieldName}.encoding`, "INVALID_PCCB"),
    value: requireString(data.value, `${fieldName}.value`, "INVALID_PCCB"),
  };
}

function parseActionHashSpec(raw: unknown, fieldName: string): PCCB["action_hash"] {
  const data = requireRecord(raw, fieldName);
  const algorithm = requireString(data.algorithm, `${fieldName}.algorithm`, "INVALID_PCCB");
  const canonicalization = requireString(data.canonicalization, `${fieldName}.canonicalization`, "INVALID_PCCB");
  const value = requireString(data.value, `${fieldName}.value`, "INVALID_PCCB");
  if (algorithm !== "sha-256" || canonicalization !== "RFC8785-JCS") {
    throw new VerificationError("INVALID_PCCB", `${fieldName} must declare sha-256 and RFC8785-JCS.`);
  }
  return {
    algorithm,
    canonicalization,
    value,
  };
}

function buildActionHashInput(intent: ActionIntent): Record<string, unknown> {
  return {
    intent_id: intent.intent_id,
    tenant: intent.tenant,
    requester: intent.requester,
    action: intent.action,
    target: intent.target,
    issued_at: normalizeTimestamp(intent.issued_at, "issued_at", "INVALID_INTENT"),
    expires_at: normalizeTimestamp(intent.expires_at, "expires_at", "INVALID_INTENT"),
  };
}

function buildUnsignedPccbPayload(pccb: PCCB): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    contract: { name: "pccb", version: "v1" },
    pccb_id: pccb.pccb_id,
    issued_at: normalizeTimestamp(pccb.issued_at, "issued_at", "INVALID_PCCB"),
    not_before: normalizeTimestamp(pccb.not_before, "not_before", "INVALID_PCCB"),
    expires_at: normalizeTimestamp(pccb.expires_at, "expires_at", "INVALID_PCCB"),
    issuer: pccb.issuer,
    subject: pccb.subject,
    tenant: pccb.tenant,
    audience: pccb.audience,
    action: pccb.action,
    target: pccb.target,
    scope: pccb.scope,
    nonce: pccb.nonce,
    action_hash: pccb.action_hash,
  };
  if (pccb.intent_id !== undefined) {
    payload.intent_id = pccb.intent_id;
  }
  if (pccb.escrow_reference !== undefined) {
    payload.escrow_reference = {
      escrow_id: pccb.escrow_reference.escrow_id,
      single_use: pccb.scope.single_use,
    };
  }
  if (pccb.extensions !== undefined) {
    payload.extensions = pccb.extensions;
  }
  return payload;
}

export interface VerifyInput {
  intent: ActionIntent | unknown;
  pccb: PCCB | unknown;
  context: VerificationContext;
}

export interface VerifyPayloadsInput {
  request_id: string;
  audience: AudienceRef;
  now: Date | string;
  scope_capabilities: string[];
  parameter_constraints?: Record<string, JsonValue>;
  resource_selectors?: Array<Record<string, JsonValue>>;
}

interface BuildContextInput {
  request_id: string;
  audience: AudienceRef;
  now: Date | string;
  scope_capabilities: string[];
  parameter_constraints?: Record<string, JsonValue>;
  resource_selectors?: Array<Record<string, JsonValue>>;
}

export interface VerifierSDKOptions {
  clockSkewToleranceMs?: number;
}

export const DEFAULT_CLOCK_SKEW_TOLERANCE_MS = 0;

export class VerifierSDK {
  private readonly signatureVerifier: SignatureVerifier;
  private readonly clockSkewToleranceMs: number;

  constructor(signatureVerifier: SignatureVerifier, options: VerifierSDKOptions = {}) {
    const clockSkewToleranceMs =
      options.clockSkewToleranceMs ?? DEFAULT_CLOCK_SKEW_TOLERANCE_MS;
    if (!Number.isFinite(clockSkewToleranceMs) || clockSkewToleranceMs < 0) {
      throw new VerificationError("INVALID_CONTEXT", "clockSkewToleranceMs must be a non-negative number.");
    }
    this.signatureVerifier = signatureVerifier;
    this.clockSkewToleranceMs = clockSkewToleranceMs;
  }

  parseIntent(payload: unknown): ActionIntent {
    const data = requireRecord(payload, "action_intent");
    const contract = requireRecord(data.contract, "action_intent.contract");
    if (contract.name !== "action_intent" || contract.version !== "v1") {
      throw new VerificationError("INVALID_INTENT", "contract must declare action_intent v1.");
    }
    requireString(data.intent_id, "action_intent.intent_id", "INVALID_INTENT");
    parseTimestamp(data.issued_at, "action_intent.issued_at", "INVALID_INTENT");
    parseTimestamp(data.expires_at, "action_intent.expires_at", "INVALID_INTENT");
    parseTenantRef(data.tenant, "action_intent.tenant", "INVALID_INTENT");
    parsePartyRef(data.requester, "action_intent.requester", "INVALID_INTENT");
    parseActionSpec(data.action, "action_intent.action", "INVALID_INTENT");
    parseTargetRef(data.target, "action_intent.target", "INVALID_INTENT");
    const intent: ActionIntent = {
      contract: { name: "action_intent", version: "v1" },
      intent_id: requireString(data.intent_id, "action_intent.intent_id", "INVALID_INTENT"),
      issued_at: normalizeTimestamp(String(data.issued_at), "action_intent.issued_at", "INVALID_INTENT"),
      expires_at: normalizeTimestamp(String(data.expires_at), "action_intent.expires_at", "INVALID_INTENT"),
      tenant: parseTenantRef(data.tenant, "action_intent.tenant", "INVALID_INTENT"),
      requester: parsePartyRef(data.requester, "action_intent.requester", "INVALID_INTENT"),
      action: parseActionSpec(data.action, "action_intent.action", "INVALID_INTENT"),
      target: parseTargetRef(data.target, "action_intent.target", "INVALID_INTENT"),
    };
    if (data.idempotency_key !== undefined) {
      intent.idempotency_key = requireString(data.idempotency_key, "action_intent.idempotency_key", "INVALID_INTENT");
    }
    if (data.justification !== undefined) {
      intent.justification = requireString(data.justification, "action_intent.justification", "INVALID_INTENT");
    }
    if (data.context !== undefined) {
      intent.context = requireRecord(data.context, "action_intent.context") as Record<string, JsonValue>;
    }
    if (data.evidence_refs !== undefined) {
      if (!Array.isArray(data.evidence_refs)) {
        throw new VerificationError("INVALID_INTENT", "action_intent.evidence_refs must be an array.");
      }
      intent.evidence_refs = data.evidence_refs.map((item, index) =>
        requireRecord(item, `action_intent.evidence_refs[${index}]`) as Record<string, JsonValue>,
      );
    }
    if (data.metadata !== undefined) {
      intent.metadata = requireRecord(data.metadata, "action_intent.metadata") as Record<string, JsonValue>;
    }
    if (data.extensions !== undefined) {
      intent.extensions = requireRecord(data.extensions, "action_intent.extensions") as Record<string, JsonValue>;
    }
    return intent;
  }

  parsePccb(payload: unknown): PCCB {
    const data = requireRecord(payload, "pccb");
    const contract = requireRecord(data.contract, "pccb.contract");
    if (contract.name !== "pccb" || contract.version !== "v1") {
      throw new VerificationError("INVALID_PCCB", "contract must declare pccb v1.");
    }
    requireString(data.pccb_id, "pccb.pccb_id", "INVALID_PCCB");
    parseTimestamp(data.issued_at, "pccb.issued_at", "INVALID_PCCB");
    parseTimestamp(data.not_before, "pccb.not_before", "INVALID_PCCB");
    parseTimestamp(data.expires_at, "pccb.expires_at", "INVALID_PCCB");
    parsePartyRef(data.issuer, "pccb.issuer", "INVALID_PCCB");
    parsePartyRef(data.subject, "pccb.subject", "INVALID_PCCB");
    parseTenantRef(data.tenant, "pccb.tenant", "INVALID_PCCB");
    parseAudienceRef(data.audience, "pccb.audience", "INVALID_PCCB");
    parseActionSpec(data.action, "pccb.action", "INVALID_PCCB");
    parseTargetRef(data.target, "pccb.target", "INVALID_PCCB");
    parseScopeSpec(data.scope, "pccb.scope");
    requireString(data.nonce, "pccb.nonce", "INVALID_PCCB");
    parseSignatureSpec(data.signature, "pccb.signature");
    const pccb: PCCB = {
      contract: { name: "pccb", version: "v1" },
      pccb_id: requireString(data.pccb_id, "pccb.pccb_id", "INVALID_PCCB"),
      issued_at: normalizeTimestamp(String(data.issued_at), "pccb.issued_at", "INVALID_PCCB"),
      not_before: normalizeTimestamp(String(data.not_before), "pccb.not_before", "INVALID_PCCB"),
      expires_at: normalizeTimestamp(String(data.expires_at), "pccb.expires_at", "INVALID_PCCB"),
      issuer: parsePartyRef(data.issuer, "pccb.issuer", "INVALID_PCCB"),
      subject: parsePartyRef(data.subject, "pccb.subject", "INVALID_PCCB"),
      tenant: parseTenantRef(data.tenant, "pccb.tenant", "INVALID_PCCB"),
      audience: parseAudienceRef(data.audience, "pccb.audience", "INVALID_PCCB"),
      action: parseActionSpec(data.action, "pccb.action", "INVALID_PCCB"),
      target: parseTargetRef(data.target, "pccb.target", "INVALID_PCCB"),
      scope: parseScopeSpec(data.scope, "pccb.scope"),
      nonce: requireString(data.nonce, "pccb.nonce", "INVALID_PCCB"),
      action_hash: parseActionHashSpec(data.action_hash, "pccb.action_hash"),
      signature: parseSignatureSpec(data.signature, "pccb.signature"),
    };
    if (data.intent_id !== undefined) {
      pccb.intent_id = requireString(data.intent_id, "pccb.intent_id", "INVALID_PCCB");
    }
    if (data.escrow_reference !== undefined) {
      const escrow = requireRecord(data.escrow_reference, "pccb.escrow_reference");
      pccb.escrow_reference = {
        escrow_id: requireString(escrow.escrow_id, "pccb.escrow_reference.escrow_id", "INVALID_PCCB"),
      };
      if (escrow.single_use !== undefined) {
        pccb.escrow_reference.single_use = requireBoolean(
          escrow.single_use,
          "pccb.escrow_reference.single_use",
          "INVALID_PCCB",
        );
      }
    }
    if (data.extensions !== undefined) {
      pccb.extensions = requireRecord(data.extensions, "pccb.extensions") as Record<string, JsonValue>;
    }
    return pccb;
  }

  buildContext(input: BuildContextInput): VerificationContext {
    requireString(input.request_id, "context.request_id", "INVALID_CONTEXT");
    const audience = parseAudienceRef(input.audience, "context.audience", "INVALID_CONTEXT");
    parseTimestamp(typeof input.now === "string" ? input.now : input.now.toISOString(), "context.now", "INVALID_CONTEXT");
    const scope_capabilities = requireStringArray(
      input.scope_capabilities,
      "context.scope_capabilities",
      "INVALID_CONTEXT",
    );
    if (input.parameter_constraints !== undefined) {
      requireRecord(input.parameter_constraints, "context.parameter_constraints");
    }
    if (input.resource_selectors !== undefined) {
      requireRecordArray(input.resource_selectors, "context.resource_selectors", "INVALID_CONTEXT");
    }
    const context: VerificationContext = {
      request_id: input.request_id,
      audience,
      now: input.now,
      scope_capabilities,
    };
    if (input.parameter_constraints !== undefined) {
      context.parameter_constraints = input.parameter_constraints;
    }
    if (input.resource_selectors !== undefined) {
      context.resource_selectors = input.resource_selectors;
    }
    return context;
  }

  verify(input: VerifyInput): VerifiedProtectedRequest {
    const intent = this.parseIntent(input.intent);
    const pccb = this.parsePccb(input.pccb);
    const contextInput: BuildContextInput = {
      request_id: input.context.request_id,
      audience: input.context.audience,
      now: input.context.now,
      scope_capabilities: input.context.scope_capabilities,
    };
    if (input.context.parameter_constraints !== undefined) {
      contextInput.parameter_constraints = input.context.parameter_constraints;
    }
    if (input.context.resource_selectors !== undefined) {
      contextInput.resource_selectors = input.context.resource_selectors;
    }
    const context = this.buildContext(contextInput);
    const now = parseTimestamp(typeof context.now === "string" ? context.now : context.now.toISOString(), "context.now", "INVALID_CONTEXT");
    const notBefore = parseTimestamp(pccb.not_before, "pccb.not_before", "INVALID_PCCB");
    const expiresAt = parseTimestamp(pccb.expires_at, "pccb.expires_at", "INVALID_PCCB");

    if (now.getTime() + this.clockSkewToleranceMs < notBefore.getTime()) {
      throw new VerificationError("PROOF_NOT_YET_VALID", "The proof is not yet valid.");
    }
    if (now.getTime() - this.clockSkewToleranceMs > expiresAt.getTime()) {
      throw new VerificationError("PROOF_EXPIRED", "The proof has expired.");
    }
    if (!isDeepStrictEqual(pccb.audience, context.audience)) {
      throw new VerificationError("AUDIENCE_MISMATCH", "The proof audience does not match this endpoint.");
    }
    if (pccb.scope.mode !== "exact") {
      throw new VerificationError("SCOPE_MODE_INVALID", "The proof scope mode is not supported.");
    }
    if (!pccb.scope.capabilities.includes(intent.action.capability)) {
      throw new VerificationError("SCOPE_CAPABILITY_MISMATCH", "The proof scope does not allow this capability.");
    }
    if (pccb.intent_id !== undefined && pccb.intent_id !== intent.intent_id) {
      throw new VerificationError("INTENT_MISMATCH", "The proof does not match the supplied action intent.");
    }
    if (!isDeepStrictEqual(pccb.tenant, intent.tenant)) {
      throw new VerificationError("TENANT_MISMATCH", "The proof tenant does not match the action intent.");
    }
    if (!isDeepStrictEqual(pccb.subject, intent.requester)) {
      throw new VerificationError("SUBJECT_MISMATCH", "The proof subject does not match the action intent.");
    }
    if (!isDeepStrictEqual(pccb.action, intent.action)) {
      throw new VerificationError("ACTION_MISMATCH", "The proof action does not exactly match the action intent.");
    }
    if (!isDeepStrictEqual(pccb.target, intent.target)) {
      throw new VerificationError("TARGET_MISMATCH", "The proof target does not exactly match the action intent.");
    }
    if (pccb.action_hash.algorithm !== "sha-256" || pccb.action_hash.canonicalization !== "RFC8785-JCS") {
      throw new VerificationError(
        "ACTION_HASH_ALGORITHM_INVALID",
        "The proof action hash metadata is invalid.",
      );
    }
    const expectedHash = sha256Hex(buildActionHashInput(intent) as Record<string, JsonValue>);
    if (pccb.action_hash.value !== expectedHash) {
      throw new VerificationError("ACTION_HASH_MISMATCH", "The proof action hash does not match the action intent.");
    }
    const unsignedPayload = canonicalizeBytes(buildUnsignedPccbPayload(pccb) as Record<string, JsonValue>);
    if (!this.signatureVerifier.verify(unsignedPayload, pccb.signature)) {
      throw new VerificationError("SIGNATURE_INVALID", "The proof signature could not be verified.");
    }
    return { intent, pccb, context };
  }

  verifyPayloads(input: VerifyPayloadsInput & { intent_payload: unknown; pccb_payload: unknown }): VerifiedProtectedRequest {
    const context = this.buildContext(input);
    return this.verify({
      intent: input.intent_payload,
      pccb: input.pccb_payload,
      context,
    });
  }
}
