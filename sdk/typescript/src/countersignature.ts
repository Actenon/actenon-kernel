import {
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
} from "node:crypto";

import { canonicalizeBytes, sha256Hex, type CanonicalValue } from "./canonical.js";
import type { PartyRef, SignatureSpec } from "./types.js";

export type CounterSignatureVerificationErrorCode =
  | "INVALID_COUNTERSIGNATURE"
  | "INVALID_RECEIPT_DIGEST"
  | "RECEIPT_DIGEST_MISMATCH"
  | "TRUSTED_KEYS_INVALID"
  | "UNKNOWN_KEY_ID"
  | "WITNESS_MISMATCH"
  | "KEY_PURPOSE_MISMATCH"
  | "KEY_NOT_VALID"
  | "UNSUPPORTED_ALGORITHM"
  | "SIGNATURE_INVALID";

export class CounterSignatureVerificationError extends Error {
  readonly code: CounterSignatureVerificationErrorCode;

  constructor(code: CounterSignatureVerificationErrorCode, message: string) {
    super(message);
    this.name = "CounterSignatureVerificationError";
    this.code = code;
  }
}

export interface ReceiptDigest {
  algorithm: "sha-256";
  canonicalization: "RFC8785-JCS";
  value: string;
}

export interface VerifiedCounterSignature {
  receipt_digest: ReceiptDigest;
  witness: PartyRef;
  signed_at: string;
  key_id: string;
  anchor_reference?: Record<string, unknown>;
}

const CONTEXT = "actenon.receipt-countersignature.v1";
const KEY_USE = "receipt_countersignature";
const HEX_256 = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function requireRecord(value: unknown, fieldName: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new CounterSignatureVerificationError(
      "INVALID_COUNTERSIGNATURE",
      `${fieldName} must be a JSON object.`,
    );
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new CounterSignatureVerificationError(
      "INVALID_COUNTERSIGNATURE",
      `${fieldName} must be a non-empty string.`,
    );
  }
  return value;
}

function parseDigest(value: unknown, fieldName: string): ReceiptDigest {
  const data = requireRecord(value, fieldName);
  const algorithm = requireString(data.algorithm, `${fieldName}.algorithm`);
  const canonicalization = requireString(data.canonicalization, `${fieldName}.canonicalization`);
  const digestValue = requireString(data.value, `${fieldName}.value`);
  if (
    algorithm !== "sha-256" ||
    canonicalization !== "RFC8785-JCS" ||
    !HEX_256.test(digestValue)
  ) {
    throw new CounterSignatureVerificationError(
      "INVALID_RECEIPT_DIGEST",
      "Receipt digest must declare sha-256, RFC8785-JCS, and a lowercase 64-character hex value.",
    );
  }
  return {
    algorithm,
    canonicalization,
    value: digestValue,
  };
}

function resolveReceiptDigest(receiptOrDigest: unknown): ReceiptDigest {
  const data = requireRecord(receiptOrDigest, "receipt_or_digest");
  if ("algorithm" in data && "canonicalization" in data && "value" in data) {
    return parseDigest(data, "receipt_or_digest");
  }
  const contract = requireRecord(data.contract, "receipt_or_digest.contract");
  if (contract.name !== "receipt" || contract.version !== "v1") {
    throw new CounterSignatureVerificationError(
      "INVALID_RECEIPT_DIGEST",
      "receipt_or_digest must be a Receipt v1 artifact or a complete digest object.",
    );
  }
  return {
    algorithm: "sha-256",
    canonicalization: "RFC8785-JCS",
    value: sha256Hex(data as CanonicalValue),
  };
}

function parseParty(value: unknown, fieldName: string): PartyRef {
  const data = requireRecord(value, fieldName);
  const party: PartyRef = {
    type: requireString(data.type, `${fieldName}.type`),
    id: requireString(data.id, `${fieldName}.id`),
  };
  if (data.display_name !== undefined) {
    party.display_name = requireString(data.display_name, `${fieldName}.display_name`);
  }
  return party;
}

function parseSignature(value: unknown): SignatureSpec {
  const data = requireRecord(value, "countersignature.signature");
  return {
    algorithm: requireString(data.algorithm, "countersignature.signature.algorithm"),
    key_id: requireString(data.key_id, "countersignature.signature.key_id"),
    encoding: requireString(data.encoding, "countersignature.signature.encoding"),
    value: requireString(data.value, "countersignature.signature.value"),
  };
}

function parseTimestamp(value: unknown, fieldName: string): string {
  const raw = requireString(value, fieldName);
  if (!RFC3339.test(raw) || Number.isNaN(Date.parse(raw))) {
    throw new CounterSignatureVerificationError(
      "INVALID_COUNTERSIGNATURE",
      `${fieldName} must be an RFC3339 timestamp.`,
    );
  }
  return raw;
}

function parseUses(value: unknown): string[] {
  const uses = typeof value === "string" ? [value] : value;
  if (
    !Array.isArray(uses) ||
    uses.length === 0 ||
    uses.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new CounterSignatureVerificationError(
      "TRUSTED_KEYS_INVALID",
      "Trusted key use must be a non-empty string or array of strings.",
    );
  }
  return uses as string[];
}

function decodeBase64Url(value: string, fieldName: string): Buffer {
  if (!BASE64URL.test(value) || value.includes("=")) {
    throw new CounterSignatureVerificationError(
      "TRUSTED_KEYS_INVALID",
      `${fieldName} must be unpadded base64url.`,
    );
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized + "=".repeat((4 - (normalized.length % 4)) % 4), "base64");
}

function signedStatement(
  digest: ReceiptDigest,
  witness: PartyRef,
  signedAt: string,
  anchorReference: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const statement: Record<string, unknown> = {
    context: CONTEXT,
    receipt_digest: digest,
    witness,
    signed_at: signedAt,
  };
  if (anchorReference !== undefined) {
    statement.anchor_reference = anchorReference;
  }
  return statement;
}

export function verifyCountersignature(
  receiptOrDigest: unknown,
  countersignature: unknown,
  trustedKeys: unknown,
): VerifiedCounterSignature {
  const expectedDigest = resolveReceiptDigest(receiptOrDigest);
  const artifact = requireRecord(countersignature, "countersignature");
  const contract = requireRecord(artifact.contract, "countersignature.contract");
  if (contract.name !== "receipt_countersignature" || contract.version !== "v1") {
    throw new CounterSignatureVerificationError(
      "INVALID_COUNTERSIGNATURE",
      "Contract must declare receipt_countersignature v1.",
    );
  }
  const observedDigest = parseDigest(artifact.receipt_digest, "countersignature.receipt_digest");
  if (observedDigest.value !== expectedDigest.value) {
    throw new CounterSignatureVerificationError(
      "RECEIPT_DIGEST_MISMATCH",
      "Counter-signature receipt digest does not match the supplied receipt or digest.",
    );
  }
  const witness = parseParty(artifact.witness, "countersignature.witness");
  const signedAt = parseTimestamp(artifact.signed_at, "countersignature.signed_at");
  const signature = parseSignature(artifact.signature);
  const anchorReference =
    artifact.anchor_reference === undefined
      ? undefined
      : requireRecord(artifact.anchor_reference, "countersignature.anchor_reference");

  const keySet = requireRecord(trustedKeys, "trusted_keys");
  const keyContract = requireRecord(keySet.contract, "trusted_keys.contract");
  if (keyContract.name !== "key_discovery" || keyContract.version !== "v1") {
    throw new CounterSignatureVerificationError(
      "TRUSTED_KEYS_INVALID",
      "Trusted key set must declare key_discovery v1.",
    );
  }
  const issuer = parseParty(keySet.issuer, "trusted_keys.issuer");
  if (issuer.type !== witness.type || issuer.id !== witness.id) {
    throw new CounterSignatureVerificationError(
      "WITNESS_MISMATCH",
      "Counter-signature witness does not match the trusted key-set issuer.",
    );
  }
  if (!Array.isArray(keySet.keys) || keySet.keys.length === 0) {
    throw new CounterSignatureVerificationError(
      "TRUSTED_KEYS_INVALID",
      "Trusted key set must contain a non-empty keys array.",
    );
  }
  const matches = keySet.keys.filter(
    (item) =>
      typeof item === "object" &&
      item !== null &&
      !Array.isArray(item) &&
      (item as Record<string, unknown>).key_id === signature.key_id,
  ) as Array<Record<string, unknown>>;
  if (matches.length === 0) {
    throw new CounterSignatureVerificationError(
      "UNKNOWN_KEY_ID",
      `No trusted counter-signing key matched key_id ${JSON.stringify(signature.key_id)}.`,
    );
  }
  if (matches.length !== 1) {
    throw new CounterSignatureVerificationError(
      "TRUSTED_KEYS_INVALID",
      `Trusted key set contains duplicate key_id ${JSON.stringify(signature.key_id)}.`,
    );
  }
  const key = matches[0] as Record<string, unknown>;
  if (key.algorithm !== signature.algorithm) {
    throw new CounterSignatureVerificationError(
      "SIGNATURE_INVALID",
      "Trusted key algorithm does not match the counter-signature.",
    );
  }
  if (!parseUses(key.use).includes(KEY_USE)) {
    throw new CounterSignatureVerificationError(
      "KEY_PURPOSE_MISMATCH",
      "Trusted key is not authorized for receipt counter-signatures.",
    );
  }
  if (key.status !== "active" && key.status !== "retired") {
    throw new CounterSignatureVerificationError(
      "KEY_NOT_VALID",
      "Trusted counter-signing key is not active or retired.",
    );
  }
  const signedAtMs = Date.parse(signedAt);
  if (key.not_before !== undefined && signedAtMs < Date.parse(parseTimestamp(key.not_before, "keys[].not_before"))) {
    throw new CounterSignatureVerificationError("KEY_NOT_VALID", "Key was not valid at signing time.");
  }
  if (key.expires_at !== undefined && signedAtMs >= Date.parse(parseTimestamp(key.expires_at, "keys[].expires_at"))) {
    throw new CounterSignatureVerificationError("KEY_NOT_VALID", "Key was expired at signing time.");
  }
  if (key.revoked_at !== undefined && signedAtMs >= Date.parse(parseTimestamp(key.revoked_at, "keys[].revoked_at"))) {
    throw new CounterSignatureVerificationError("KEY_NOT_VALID", "Key was revoked at signing time.");
  }
  if (signature.algorithm !== "EdDSA" || signature.encoding !== "base64url") {
    throw new CounterSignatureVerificationError(
      "UNSUPPORTED_ALGORITHM",
      "Receipt counter-signature v1 supports EdDSA/Ed25519 with base64url encoding.",
    );
  }
  const jwk = requireRecord(key.public_key_jwk, "keys[].public_key_jwk");
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    (jwk.kid !== undefined && jwk.kid !== signature.key_id) ||
    (jwk.alg !== undefined && jwk.alg !== "EdDSA")
  ) {
    throw new CounterSignatureVerificationError(
      "TRUSTED_KEYS_INVALID",
      "Counter-signing key must be an Ed25519 OKP JWK matching signature.key_id.",
    );
  }
  const publicKeyBytes = decodeBase64Url(requireString(jwk.x, "public_key_jwk.x"), "public_key_jwk.x");
  const signatureBytes = decodeBase64Url(signature.value, "signature.value");
  if (publicKeyBytes.length !== 32 || signatureBytes.length !== 64) {
    throw new CounterSignatureVerificationError(
      "SIGNATURE_INVALID",
      "Counter-signature key or signature has an invalid Ed25519 length.",
    );
  }
  const statement = signedStatement(observedDigest, witness, signedAt, anchorReference);
  let valid = false;
  try {
    valid = verifySignature(
      null,
      canonicalizeBytes(statement as CanonicalValue),
      createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }),
      signatureBytes,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new CounterSignatureVerificationError(
      "SIGNATURE_INVALID",
      "Receipt counter-signature could not be verified.",
    );
  }
  const verified: VerifiedCounterSignature = {
    receipt_digest: observedDigest,
    witness,
    signed_at: signedAt,
    key_id: signature.key_id,
  };
  if (anchorReference !== undefined) {
    verified.anchor_reference = anchorReference;
  }
  return verified;
}

export const verify_countersignature = verifyCountersignature;
