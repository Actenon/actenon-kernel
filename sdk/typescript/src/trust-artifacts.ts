import {
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
} from "node:crypto";

import { canonicalizeBytes, type CanonicalValue } from "./canonical.js";
import type { PartyRef, SignatureSpec } from "./types.js";

export type TrustArtifactVerificationErrorCode =
  | "INVALID_ISSUER_STATUS"
  | "ISSUER_STATUS_REQUIRED"
  | "ISSUER_MISMATCH"
  | "ISSUER_STATUS_NOT_YET_VALID"
  | "ISSUER_STATUS_EXPIRED"
  | "ISSUER_STATUS_STALE"
  | "ISSUER_REVOKED"
  | "ISSUER_SUSPENDED"
  | "INVALID_APPROVAL_ARTIFACT"
  | "APPROVAL_NOT_GRANTED"
  | "APPROVAL_ACTION_MISMATCH"
  | "TRUSTED_KEYS_INVALID"
  | "SIGNER_MISMATCH"
  | "UNKNOWN_KEY_ID"
  | "KEY_PURPOSE_MISMATCH"
  | "KEY_NOT_VALID"
  | "UNSUPPORTED_ALGORITHM"
  | "SIGNATURE_INVALID";

export class TrustArtifactVerificationError extends Error {
  readonly code: TrustArtifactVerificationErrorCode;

  constructor(code: TrustArtifactVerificationErrorCode, message: string) {
    super(message);
    this.name = "TrustArtifactVerificationError";
    this.code = code;
  }
}

export interface ActionHash {
  algorithm: "sha-256";
  canonicalization: "RFC8785-JCS";
  value: string;
}

export interface VerifiedIssuerStatus {
  issuer: PartyRef;
  authority: PartyRef;
  status: "good_standing";
  issued_at: string;
  expires_at: string;
  key_id: string;
  status_reference?: string;
}

export interface VerifiedApprovalArtifact {
  approval_id: string;
  approver: PartyRef;
  approval_type: string;
  decision: "approved";
  action_hash: ActionHash;
  issued_at: string;
  key_id: string;
}

export interface IssuerStatusOptions {
  maxAgeSeconds?: number;
  statusPolicy?: "required" | "disabled";
}

const ISSUER_STATUS_CONTEXT = "actenon.issuer-status.v1";
const APPROVAL_CONTEXT = "actenon.approval-artifact.v1";
const HEX_256 = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function failure(
  code: TrustArtifactVerificationErrorCode,
  message: string,
): TrustArtifactVerificationError {
  return new TrustArtifactVerificationError(code, message);
}

function record(
  value: unknown,
  field: string,
  code: TrustArtifactVerificationErrorCode,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw failure(code, `${field} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function text(
  value: unknown,
  field: string,
  code: TrustArtifactVerificationErrorCode,
): string {
  if (typeof value !== "string" || value.length === 0) {
    throw failure(code, `${field} must be a non-empty string.`);
  }
  return value;
}

function party(
  value: unknown,
  field: string,
  code: TrustArtifactVerificationErrorCode,
): PartyRef {
  const data = record(value, field, code);
  return {
    type: text(data.type, `${field}.type`, code),
    id: text(data.id, `${field}.id`, code),
    ...(data.display_name === undefined
      ? {}
      : { display_name: text(data.display_name, `${field}.display_name`, code) }),
  };
}

function timestamp(
  value: unknown,
  field: string,
  code: TrustArtifactVerificationErrorCode,
): string {
  const raw = text(value, field, code);
  if (!RFC3339.test(raw) || Number.isNaN(Date.parse(raw))) {
    throw failure(code, `${field} must be an RFC3339 timestamp.`);
  }
  return raw;
}

function signature(
  value: unknown,
  field: string,
  code: TrustArtifactVerificationErrorCode,
): SignatureSpec {
  const data = record(value, field, code);
  return {
    algorithm: text(data.algorithm, `${field}.algorithm`, code),
    key_id: text(data.key_id, `${field}.key_id`, code),
    encoding: text(data.encoding, `${field}.encoding`, code),
    value: text(data.value, `${field}.value`, code),
  };
}

function actionHash(value: unknown): ActionHash {
  const data = record(value, "approval.action_hash", "INVALID_APPROVAL_ARTIFACT");
  const parsed = {
    algorithm: text(
      data.algorithm,
      "approval.action_hash.algorithm",
      "INVALID_APPROVAL_ARTIFACT",
    ),
    canonicalization: text(
      data.canonicalization,
      "approval.action_hash.canonicalization",
      "INVALID_APPROVAL_ARTIFACT",
    ),
    value: text(
      data.value,
      "approval.action_hash.value",
      "INVALID_APPROVAL_ARTIFACT",
    ),
  };
  if (
    parsed.algorithm !== "sha-256" ||
    parsed.canonicalization !== "RFC8785-JCS" ||
    !HEX_256.test(parsed.value)
  ) {
    throw failure(
      "INVALID_APPROVAL_ARTIFACT",
      "Approval action_hash must declare sha-256, RFC8785-JCS, and lowercase hex.",
    );
  }
  return parsed as ActionHash;
}

function uses(value: unknown): string[] {
  const parsed = typeof value === "string" ? [value] : value;
  if (
    !Array.isArray(parsed) ||
    parsed.length === 0 ||
    parsed.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw failure(
      "TRUSTED_KEYS_INVALID",
      "Trusted key use must be a non-empty string or array.",
    );
  }
  return parsed as string[];
}

function decodeBase64Url(
  value: string,
  field: string,
  code: TrustArtifactVerificationErrorCode,
): Buffer {
  if (!BASE64URL.test(value) || value.includes("=")) {
    throw failure(code, `${field} must be unpadded base64url.`);
  }
  return Buffer.from(value, "base64url");
}

function selectKey(
  trustedKeys: unknown,
  signer: PartyRef,
  artifactSignature: SignatureSpec,
  signedAt: string,
  requiredUse: string,
): Record<string, unknown> {
  const keySet = record(trustedKeys, "trusted_keys", "TRUSTED_KEYS_INVALID");
  const contract = record(
    keySet.contract,
    "trusted_keys.contract",
    "TRUSTED_KEYS_INVALID",
  );
  if (contract.name !== "key_discovery" || contract.version !== "v1") {
    throw failure(
      "TRUSTED_KEYS_INVALID",
      "Trusted key set must declare key_discovery v1.",
    );
  }
  const keyIssuer = party(
    keySet.issuer,
    "trusted_keys.issuer",
    "TRUSTED_KEYS_INVALID",
  );
  if (keyIssuer.type !== signer.type || keyIssuer.id !== signer.id) {
    throw failure(
      "SIGNER_MISMATCH",
      "Artifact signer does not match the trusted key-set issuer.",
    );
  }
  if (!Array.isArray(keySet.keys) || keySet.keys.length === 0) {
    throw failure(
      "TRUSTED_KEYS_INVALID",
      "Trusted key set must contain keys.",
    );
  }
  const matches = keySet.keys.filter(
    (item) =>
      typeof item === "object" &&
      item !== null &&
      !Array.isArray(item) &&
      (item as Record<string, unknown>).key_id === artifactSignature.key_id,
  ) as Array<Record<string, unknown>>;
  if (matches.length === 0) {
    throw failure("UNKNOWN_KEY_ID", "No trusted key matched the artifact kid.");
  }
  if (matches.length !== 1) {
    throw failure("TRUSTED_KEYS_INVALID", "Trusted key kid is duplicated.");
  }
  const key = matches[0] as Record<string, unknown>;
  if (key.algorithm !== artifactSignature.algorithm) {
    throw failure("SIGNATURE_INVALID", "Trusted key algorithm does not match.");
  }
  if (!uses(key.use).includes(requiredUse)) {
    throw failure("KEY_PURPOSE_MISMATCH", `Key is not authorized for ${requiredUse}.`);
  }
  if (key.status !== "active" && key.status !== "retired") {
    throw failure("KEY_NOT_VALID", "Trusted key is not active or retired.");
  }
  const signedAtMs = Date.parse(signedAt);
  for (const [field, inclusive] of [
    ["not_before", false],
    ["expires_at", true],
    ["revoked_at", true],
  ] as const) {
    if (key[field] === undefined) continue;
    const bound = Date.parse(timestamp(key[field], `keys[].${field}`, "TRUSTED_KEYS_INVALID"));
    if ((!inclusive && signedAtMs < bound) || (inclusive && signedAtMs >= bound)) {
      throw failure("KEY_NOT_VALID", "Trusted key was not valid at signing time.");
    }
  }
  return key;
}

function verifyEd25519(
  statement: Record<string, unknown>,
  artifactSignature: SignatureSpec,
  key: Record<string, unknown>,
): void {
  if (
    artifactSignature.algorithm !== "EdDSA" ||
    artifactSignature.encoding !== "base64url"
  ) {
    throw failure(
      "UNSUPPORTED_ALGORITHM",
      "Trust artifact v1 supports EdDSA/Ed25519.",
    );
  }
  const jwk = record(
    key.public_key_jwk,
    "keys[].public_key_jwk",
    "TRUSTED_KEYS_INVALID",
  );
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    (jwk.kid !== undefined && jwk.kid !== artifactSignature.key_id) ||
    (jwk.alg !== undefined && jwk.alg !== "EdDSA")
  ) {
    throw failure("TRUSTED_KEYS_INVALID", "Trusted key must be an Ed25519 JWK.");
  }
  const rawSignature = decodeBase64Url(
    artifactSignature.value,
    "signature.value",
    "SIGNATURE_INVALID",
  );
  if (rawSignature.length !== 64) {
    throw failure("SIGNATURE_INVALID", "Signature must be 64-byte Ed25519.");
  }
  let publicKey;
  try {
    publicKey = createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
  } catch {
    throw failure("TRUSTED_KEYS_INVALID", "Trusted JWK could not be loaded.");
  }
  if (
    !verifySignature(
      null,
      canonicalizeBytes(statement as CanonicalValue),
      publicKey,
      rawSignature,
    )
  ) {
    throw failure("SIGNATURE_INVALID", "Artifact signature could not be verified.");
  }
}

export function verifyIssuerStatus(
  issuerValue: unknown,
  statusArtifact: unknown,
  trustedKeys: unknown,
  now: Date,
  options: IssuerStatusOptions = {},
): VerifiedIssuerStatus | undefined {
  const policy = options.statusPolicy ?? "required";
  if (policy === "disabled") {
    console.warn(
      "Actenon: issuer-status verification DISABLED — revoked or stale issuers may be accepted.",
    );
    return undefined;
  }
  if (statusArtifact === undefined || statusArtifact === null || trustedKeys == null) {
    throw failure(
      "ISSUER_STATUS_REQUIRED",
      "High-assurance verification requires signed issuer status.",
    );
  }
  const maxAgeSeconds = options.maxAgeSeconds ?? 3600;
  if (maxAgeSeconds <= 0) throw new RangeError("maxAgeSeconds must be positive");
  const expectedIssuer = party(issuerValue, "issuer", "INVALID_ISSUER_STATUS");
  const artifact = record(statusArtifact, "status_artifact", "INVALID_ISSUER_STATUS");
  const contract = record(
    artifact.contract,
    "status_artifact.contract",
    "INVALID_ISSUER_STATUS",
  );
  if (contract.name !== "issuer_status" || contract.version !== "v1") {
    throw failure("INVALID_ISSUER_STATUS", "Contract must declare issuer_status v1.");
  }
  const observedIssuer = party(
    artifact.issuer,
    "status_artifact.issuer",
    "INVALID_ISSUER_STATUS",
  );
  if (
    observedIssuer.type !== expectedIssuer.type ||
    observedIssuer.id !== expectedIssuer.id
  ) {
    throw failure("ISSUER_MISMATCH", "Status describes a different issuer.");
  }
  const authority = party(
    artifact.authority,
    "status_artifact.authority",
    "INVALID_ISSUER_STATUS",
  );
  const status = text(
    artifact.status,
    "status_artifact.status",
    "INVALID_ISSUER_STATUS",
  );
  if (!["good_standing", "suspended", "revoked"].includes(status)) {
    throw failure("INVALID_ISSUER_STATUS", "Issuer status token is invalid.");
  }
  const issuedAt = timestamp(
    artifact.issued_at,
    "status_artifact.issued_at",
    "INVALID_ISSUER_STATUS",
  );
  const expiresAt = timestamp(
    artifact.expires_at,
    "status_artifact.expires_at",
    "INVALID_ISSUER_STATUS",
  );
  const nowMs = now.getTime();
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw failure(
      "INVALID_ISSUER_STATUS",
      "Issuer status expiry must be after issuance.",
    );
  }
  if (nowMs < Date.parse(issuedAt)) {
    throw failure("ISSUER_STATUS_NOT_YET_VALID", "Issuer status is not yet valid.");
  }
  if (nowMs >= Date.parse(expiresAt)) {
    throw failure("ISSUER_STATUS_EXPIRED", "Issuer status has expired.");
  }
  if (nowMs - Date.parse(issuedAt) > maxAgeSeconds * 1000) {
    throw failure("ISSUER_STATUS_STALE", "Issuer status is stale.");
  }
  const statusReference =
    artifact.status_reference === undefined
      ? undefined
      : text(
          artifact.status_reference,
          "status_artifact.status_reference",
          "INVALID_ISSUER_STATUS",
        );
  const artifactSignature = signature(
    artifact.signature,
    "status_artifact.signature",
    "INVALID_ISSUER_STATUS",
  );
  const key = selectKey(
    trustedKeys,
    authority,
    artifactSignature,
    issuedAt,
    "issuer_status",
  );
  const statement: Record<string, unknown> = {
    context: ISSUER_STATUS_CONTEXT,
    issuer: observedIssuer,
    authority,
    status,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  if (statusReference !== undefined) statement.status_reference = statusReference;
  verifyEd25519(statement, artifactSignature, key);
  if (status === "revoked") throw failure("ISSUER_REVOKED", "Issuer is revoked.");
  if (status === "suspended") throw failure("ISSUER_SUSPENDED", "Issuer is suspended.");
  return {
    issuer: observedIssuer,
    authority,
    status: "good_standing",
    issued_at: issuedAt,
    expires_at: expiresAt,
    key_id: artifactSignature.key_id,
    ...(statusReference === undefined ? {} : { status_reference: statusReference }),
  };
}

export function verifyApprovalArtifact(
  approvalValue: unknown,
  trustedKeys: unknown,
  expectedActionHash?: ActionHash,
): VerifiedApprovalArtifact {
  const artifact = record(
    approvalValue,
    "approval",
    "INVALID_APPROVAL_ARTIFACT",
  );
  const contract = record(
    artifact.contract,
    "approval.contract",
    "INVALID_APPROVAL_ARTIFACT",
  );
  if (contract.name !== "approval_artifact" || contract.version !== "v1") {
    throw failure(
      "INVALID_APPROVAL_ARTIFACT",
      "Contract must declare approval_artifact v1.",
    );
  }
  const approvalId = text(
    artifact.approval_id,
    "approval.approval_id",
    "INVALID_APPROVAL_ARTIFACT",
  );
  const approver = party(
    artifact.approver,
    "approval.approver",
    "INVALID_APPROVAL_ARTIFACT",
  );
  const approvalType = text(
    artifact.approval_type,
    "approval.approval_type",
    "INVALID_APPROVAL_ARTIFACT",
  );
  const decision = text(
    artifact.decision,
    "approval.decision",
    "INVALID_APPROVAL_ARTIFACT",
  );
  if (decision !== "approved") {
    throw failure("APPROVAL_NOT_GRANTED", "Approval decision is not approved.");
  }
  const parsedActionHash = actionHash(artifact.action_hash);
  if (
    expectedActionHash !== undefined &&
    (parsedActionHash.algorithm !== expectedActionHash.algorithm ||
      parsedActionHash.canonicalization !== expectedActionHash.canonicalization ||
      parsedActionHash.value !== expectedActionHash.value)
  ) {
    throw failure(
      "APPROVAL_ACTION_MISMATCH",
      "Approval is not bound to the expected action.",
    );
  }
  const issuedAt = timestamp(
    artifact.issued_at,
    "approval.issued_at",
    "INVALID_APPROVAL_ARTIFACT",
  );
  const artifactSignature = signature(
    artifact.signature,
    "approval.signature",
    "INVALID_APPROVAL_ARTIFACT",
  );
  const key = selectKey(
    trustedKeys,
    approver,
    artifactSignature,
    issuedAt,
    "approval_artifact",
  );
  verifyEd25519(
    {
      context: APPROVAL_CONTEXT,
      approval_id: approvalId,
      approver,
      approval_type: approvalType,
      decision,
      action_hash: parsedActionHash,
      issued_at: issuedAt,
    },
    artifactSignature,
    key,
  );
  return {
    approval_id: approvalId,
    approver,
    approval_type: approvalType,
    decision: "approved",
    action_hash: parsedActionHash,
    issued_at: issuedAt,
    key_id: artifactSignature.key_id,
  };
}

export const verify_issuer_status = verifyIssuerStatus;
export const verify_approval_artifact = verifyApprovalArtifact;
