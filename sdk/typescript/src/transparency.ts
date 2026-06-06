import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
} from "node:crypto";

import { canonicalizeBytes, type CanonicalValue } from "./canonical.js";
import type { ReceiptDigest } from "./countersignature.js";
import type { PartyRef } from "./types.js";

export const CHECKPOINT_CONTEXT = "actenon.transparency-checkpoint.v1";
export const CHECKPOINT_KEY_USE = "transparency_checkpoint";

export type TransparencyVerificationErrorCode =
  | "INVALID_CHECKPOINT"
  | "INVALID_LEAF_DIGEST"
  | "INVALID_INCLUSION_PROOF"
  | "INVALID_CONSISTENCY_PROOF"
  | "CHECKPOINT_MISMATCH"
  | "LEAF_DIGEST_MISMATCH"
  | "INCLUSION_PROOF_INVALID"
  | "CONSISTENCY_PROOF_INVALID"
  | "EQUIVOCATION_DETECTED"
  | "REWIND_DETECTED"
  | "LOG_IDENTITY_MISMATCH"
  | "TRUSTED_KEYS_INVALID"
  | "UNKNOWN_KEY_ID"
  | "KEY_PURPOSE_MISMATCH"
  | "KEY_NOT_VALID"
  | "UNSUPPORTED_ALGORITHM"
  | "SIGNATURE_INVALID"
  | "INVALID_COUNTERSIGNATURE"
  | "ORPHAN_COUNTERSIGNATURE";

export class TransparencyVerificationError extends Error {
  readonly code: TransparencyVerificationErrorCode;

  constructor(code: TransparencyVerificationErrorCode, message: string) {
    super(message);
    this.name = "TransparencyVerificationError";
    this.code = code;
  }
}

export interface VerifiedCheckpoint {
  log: PartyRef;
  tree_size: number;
  root_hash: string;
  issued_at: string;
  key_id: string;
}

export interface VerifiedInclusion {
  log_id: string;
  tree_size: number;
  leaf_index: number;
  leaf_digest: ReceiptDigest;
  checkpoint?: VerifiedCheckpoint;
}

export interface VerifiedConsistency {
  log_id: string;
  old_tree_size: number;
  new_tree_size: number;
}

export interface VerifiedMonitorUpdate {
  previous: VerifiedCheckpoint;
  current: VerifiedCheckpoint;
  consistency: VerifiedConsistency;
}

interface ParsedCheckpoint {
  log: PartyRef;
  logRaw: Record<string, unknown>;
  treeSize: number;
  rootHash: Buffer;
  issuedAt: string;
  signature: {
    algorithm: string;
    key_id: string;
    encoding: string;
    value: string;
  };
}

const HEX_256 = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function fail(
  code: TransparencyVerificationErrorCode,
  message: string,
): never {
  throw new TransparencyVerificationError(code, message);
}

function requireRecord(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(code, `${fieldName} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function requireString(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(code, `${fieldName} must be a non-empty string.`);
  }
  return value;
}

function requireInteger(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(code, `${fieldName} must be a non-negative safe integer.`);
  }
  return value as number;
}

function parseTimestamp(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): string {
  const raw = requireString(value, fieldName, code);
  if (!RFC3339.test(raw) || Number.isNaN(Date.parse(raw))) {
    fail(code, `${fieldName} must be an RFC3339 timestamp.`);
  }
  return raw;
}

function parseParty(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): { party: PartyRef; raw: Record<string, unknown> } {
  const raw = requireRecord(value, fieldName, code);
  const party: PartyRef = {
    type: requireString(raw.type, `${fieldName}.type`, code),
    id: requireString(raw.id, `${fieldName}.id`, code),
  };
  if (raw.display_name !== undefined) {
    party.display_name = requireString(
      raw.display_name,
      `${fieldName}.display_name`,
      code,
    );
  }
  if (raw.attributes !== undefined) {
    party.attributes = requireRecord(
      raw.attributes,
      `${fieldName}.attributes`,
      code,
    ) as NonNullable<PartyRef["attributes"]>;
  }
  return { party, raw };
}

function parseDigest(value: unknown, fieldName: string): ReceiptDigest {
  const data = requireRecord(value, fieldName, "INVALID_LEAF_DIGEST");
  const algorithm = requireString(
    data.algorithm,
    `${fieldName}.algorithm`,
    "INVALID_LEAF_DIGEST",
  );
  const canonicalization = requireString(
    data.canonicalization,
    `${fieldName}.canonicalization`,
    "INVALID_LEAF_DIGEST",
  );
  const digestValue = requireString(
    data.value,
    `${fieldName}.value`,
    "INVALID_LEAF_DIGEST",
  );
  if (
    algorithm !== "sha-256" ||
    canonicalization !== "RFC8785-JCS" ||
    !HEX_256.test(digestValue)
  ) {
    fail(
      "INVALID_LEAF_DIGEST",
      "Leaf digest must declare sha-256, RFC8785-JCS, and a lowercase 64-character hex value.",
    );
  }
  return {
    algorithm,
    canonicalization,
    value: digestValue,
  };
}

function parseHexHash(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): Buffer {
  const raw = requireString(value, fieldName, code);
  if (!HEX_256.test(raw)) {
    fail(code, `${fieldName} must be a lowercase 64-character SHA-256 hex value.`);
  }
  return Buffer.from(raw, "hex");
}

function parseHashSpec(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): Buffer {
  const data = requireRecord(value, fieldName, code);
  if (data.algorithm !== "sha-256" || data.encoding !== "hex") {
    fail(code, `${fieldName} must declare sha-256 with hex encoding.`);
  }
  return parseHexHash(data.value, `${fieldName}.value`, code);
}

function parseHashPath(
  value: unknown,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): Buffer[] {
  if (!Array.isArray(value)) {
    fail(code, `${fieldName} must be an array.`);
  }
  return value.map((item, index) =>
    parseHexHash(item, `${fieldName}[${index}]`, code),
  );
}

function decodeBase64Url(
  value: string,
  fieldName: string,
  code: TransparencyVerificationErrorCode,
): Buffer {
  if (!BASE64URL.test(value) || value.includes("=")) {
    fail(code, `${fieldName} must be unpadded base64url.`);
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4),
    "base64",
  );
}

function parseCheckpoint(value: unknown): ParsedCheckpoint {
  const checkpoint = requireRecord(value, "checkpoint", "INVALID_CHECKPOINT");
  const contract = requireRecord(
    checkpoint.contract,
    "checkpoint.contract",
    "INVALID_CHECKPOINT",
  );
  if (
    contract.name !== "transparency_checkpoint" ||
    contract.version !== "v1"
  ) {
    fail(
      "INVALID_CHECKPOINT",
      "Checkpoint contract must declare transparency_checkpoint v1.",
    );
  }
  const { party: log, raw: logRaw } = parseParty(
    checkpoint.log,
    "checkpoint.log",
    "INVALID_CHECKPOINT",
  );
  const signature = requireRecord(
    checkpoint.signature,
    "checkpoint.signature",
    "INVALID_CHECKPOINT",
  );
  return {
    log,
    logRaw,
    treeSize: requireInteger(
      checkpoint.tree_size,
      "checkpoint.tree_size",
      "INVALID_CHECKPOINT",
    ),
    rootHash: parseHashSpec(
      checkpoint.root_hash,
      "checkpoint.root_hash",
      "INVALID_CHECKPOINT",
    ),
    issuedAt: parseTimestamp(
      checkpoint.issued_at,
      "checkpoint.issued_at",
      "INVALID_CHECKPOINT",
    ),
    signature: {
      algorithm: requireString(
        signature.algorithm,
        "checkpoint.signature.algorithm",
        "INVALID_CHECKPOINT",
      ),
      key_id: requireString(
        signature.key_id,
        "checkpoint.signature.key_id",
        "INVALID_CHECKPOINT",
      ),
      encoding: requireString(
        signature.encoding,
        "checkpoint.signature.encoding",
        "INVALID_CHECKPOINT",
      ),
      value: requireString(
        signature.value,
        "checkpoint.signature.value",
        "INVALID_CHECKPOINT",
      ),
    },
  };
}

function parseUses(value: unknown): string[] {
  const uses = typeof value === "string" ? [value] : value;
  if (
    !Array.isArray(uses) ||
    uses.length === 0 ||
    uses.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    fail(
      "TRUSTED_KEYS_INVALID",
      "Trusted key use must be a non-empty string or array of strings.",
    );
  }
  return uses as string[];
}

function leafHash(digest: ReceiptDigest): Buffer {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from([0]), Buffer.from(digest.value, "hex")]))
    .digest();
}

function nodeHash(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from([1]), left, right]))
    .digest();
}

export function verifyCheckpointSignature(
  checkpointValue: unknown,
  trustedKeysValue: unknown,
): VerifiedCheckpoint {
  const checkpoint = parseCheckpoint(checkpointValue);
  if (
    checkpoint.signature.algorithm !== "EdDSA" ||
    checkpoint.signature.encoding !== "base64url"
  ) {
    fail(
      "UNSUPPORTED_ALGORITHM",
      "Transparency checkpoint v1 supports EdDSA/Ed25519 with base64url encoding.",
    );
  }
  const trustedKeys = requireRecord(
    trustedKeysValue,
    "trusted_keys",
    "TRUSTED_KEYS_INVALID",
  );
  const keyContract = requireRecord(
    trustedKeys.contract,
    "trusted_keys.contract",
    "TRUSTED_KEYS_INVALID",
  );
  if (
    keyContract.name !== "key_discovery" ||
    keyContract.version !== "v1"
  ) {
    fail(
      "TRUSTED_KEYS_INVALID",
      "Trusted key set must declare key_discovery v1.",
    );
  }
  const { party: issuer } = parseParty(
    trustedKeys.issuer,
    "trusted_keys.issuer",
    "TRUSTED_KEYS_INVALID",
  );
  if (
    issuer.type !== checkpoint.log.type ||
    issuer.id !== checkpoint.log.id
  ) {
    fail(
      "LOG_IDENTITY_MISMATCH",
      "Checkpoint log identity does not match the trusted key-set issuer.",
    );
  }
  if (!Array.isArray(trustedKeys.keys) || trustedKeys.keys.length === 0) {
    fail(
      "TRUSTED_KEYS_INVALID",
      "Trusted key set must contain a non-empty keys array.",
    );
  }
  const matches = trustedKeys.keys.filter(
    (item) =>
      typeof item === "object" &&
      item !== null &&
      !Array.isArray(item) &&
      (item as Record<string, unknown>).key_id === checkpoint.signature.key_id,
  ) as Array<Record<string, unknown>>;
  if (matches.length === 0) {
    fail(
      "UNKNOWN_KEY_ID",
      `No trusted checkpoint key matched key_id ${JSON.stringify(checkpoint.signature.key_id)}.`,
    );
  }
  if (matches.length !== 1) {
    fail(
      "TRUSTED_KEYS_INVALID",
      `Trusted key set contains duplicate key_id ${JSON.stringify(checkpoint.signature.key_id)}.`,
    );
  }
  const key = matches[0] as Record<string, unknown>;
  if (key.algorithm !== checkpoint.signature.algorithm) {
    fail(
      "SIGNATURE_INVALID",
      "Trusted key algorithm does not match the checkpoint signature.",
    );
  }
  if (!parseUses(key.use).includes(CHECKPOINT_KEY_USE)) {
    fail(
      "KEY_PURPOSE_MISMATCH",
      "Trusted key is not authorized for transparency checkpoints.",
    );
  }
  if (key.status !== "active" && key.status !== "retired") {
    fail(
      "KEY_NOT_VALID",
      "Trusted checkpoint key is not active or retired.",
    );
  }
  const issuedAtMs = Date.parse(checkpoint.issuedAt);
  if (
    key.not_before !== undefined &&
    issuedAtMs <
      Date.parse(
        parseTimestamp(
          key.not_before,
          "keys[].not_before",
          "TRUSTED_KEYS_INVALID",
        ),
      )
  ) {
    fail("KEY_NOT_VALID", "Checkpoint key was not valid at signing time.");
  }
  if (
    key.expires_at !== undefined &&
    issuedAtMs >=
      Date.parse(
        parseTimestamp(
          key.expires_at,
          "keys[].expires_at",
          "TRUSTED_KEYS_INVALID",
        ),
      )
  ) {
    fail("KEY_NOT_VALID", "Checkpoint key was expired at signing time.");
  }
  if (
    key.revoked_at !== undefined &&
    issuedAtMs >=
      Date.parse(
        parseTimestamp(
          key.revoked_at,
          "keys[].revoked_at",
          "TRUSTED_KEYS_INVALID",
        ),
      )
  ) {
    fail("KEY_NOT_VALID", "Checkpoint key was revoked at signing time.");
  }
  const jwk = requireRecord(
    key.public_key_jwk,
    "keys[].public_key_jwk",
    "TRUSTED_KEYS_INVALID",
  );
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    (jwk.kid !== undefined && jwk.kid !== checkpoint.signature.key_id) ||
    (jwk.alg !== undefined && jwk.alg !== "EdDSA")
  ) {
    fail(
      "TRUSTED_KEYS_INVALID",
      "Checkpoint key must be an Ed25519 OKP JWK matching signature.key_id.",
    );
  }
  const publicKey = decodeBase64Url(
    requireString(
      jwk.x,
      "public_key_jwk.x",
      "TRUSTED_KEYS_INVALID",
    ),
    "public_key_jwk.x",
    "TRUSTED_KEYS_INVALID",
  );
  const signature = decodeBase64Url(
    checkpoint.signature.value,
    "checkpoint.signature.value",
    "SIGNATURE_INVALID",
  );
  if (publicKey.length !== 32 || signature.length !== 64) {
    fail(
      "SIGNATURE_INVALID",
      "Checkpoint key or signature has an invalid Ed25519 length.",
    );
  }
  const statement = {
    context: CHECKPOINT_CONTEXT,
    log: checkpoint.logRaw,
    tree_size: checkpoint.treeSize,
    root_hash: {
      algorithm: "sha-256",
      encoding: "hex",
      value: checkpoint.rootHash.toString("hex"),
    },
    issued_at: checkpoint.issuedAt,
  };
  let valid = false;
  try {
    valid = verifySignature(
      null,
      canonicalizeBytes(statement as CanonicalValue),
      createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }),
      signature,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    fail(
      "SIGNATURE_INVALID",
      "Transparency checkpoint signature could not be verified.",
    );
  }
  return {
    log: checkpoint.log,
    tree_size: checkpoint.treeSize,
    root_hash: checkpoint.rootHash.toString("hex"),
    issued_at: checkpoint.issuedAt,
    key_id: checkpoint.signature.key_id,
  };
}

export function verifyInclusion(
  digestValue: unknown,
  inclusionProofValue: unknown,
  checkpointValue: unknown,
): VerifiedInclusion {
  const expectedDigest = parseDigest(digestValue, "digest");
  const proof = requireRecord(
    inclusionProofValue,
    "inclusion_proof",
    "INVALID_INCLUSION_PROOF",
  );
  const contract = requireRecord(
    proof.contract,
    "inclusion_proof.contract",
    "INVALID_INCLUSION_PROOF",
  );
  if (
    contract.name !== "transparency_inclusion_proof" ||
    contract.version !== "v1"
  ) {
    fail(
      "INVALID_INCLUSION_PROOF",
      "Proof contract must declare transparency_inclusion_proof v1.",
    );
  }
  if (proof.hash_algorithm !== "sha-256") {
    fail(
      "INVALID_INCLUSION_PROOF",
      "Inclusion proof hash_algorithm must be sha-256.",
    );
  }
  const observedDigest = parseDigest(
    proof.leaf_digest,
    "inclusion_proof.leaf_digest",
  );
  if (observedDigest.value !== expectedDigest.value) {
    fail(
      "LEAF_DIGEST_MISMATCH",
      "Inclusion proof leaf digest does not match the supplied digest.",
    );
  }
  const logId = requireString(
    proof.log_id,
    "inclusion_proof.log_id",
    "INVALID_INCLUSION_PROOF",
  );
  const treeSize = requireInteger(
    proof.tree_size,
    "inclusion_proof.tree_size",
    "INVALID_INCLUSION_PROOF",
  );
  const leafIndex = requireInteger(
    proof.leaf_index,
    "inclusion_proof.leaf_index",
    "INVALID_INCLUSION_PROOF",
  );
  if (treeSize === 0 || leafIndex >= treeSize) {
    fail(
      "INVALID_INCLUSION_PROOF",
      "leaf_index must identify a leaf within the non-empty proof tree.",
    );
  }
  const auditPath = parseHashPath(
    proof.audit_path,
    "inclusion_proof.audit_path",
    "INVALID_INCLUSION_PROOF",
  );
  const checkpoint = parseCheckpoint(checkpointValue);
  if (checkpoint.log.id !== logId || checkpoint.treeSize !== treeSize) {
    fail(
      "CHECKPOINT_MISMATCH",
      "Inclusion proof log or tree size does not match the checkpoint.",
    );
  }
  let node = leafHash(expectedDigest);
  let fn = leafIndex;
  let sn = treeSize - 1;
  for (const sibling of auditPath) {
    if (fn % 2 === 1 || fn === sn) {
      node = nodeHash(sibling, node);
      while (fn !== 0 && fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      node = nodeHash(node, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0 || !node.equals(checkpoint.rootHash)) {
    fail(
      "INCLUSION_PROOF_INVALID",
      "Digest is not included in the supplied checkpoint.",
    );
  }
  return {
    log_id: logId,
    tree_size: treeSize,
    leaf_index: leafIndex,
    leaf_digest: expectedDigest,
  };
}

export function verifyConsistency(
  oldCheckpointValue: unknown,
  newCheckpointValue: unknown,
  consistencyProofValue: unknown,
): VerifiedConsistency {
  const oldCheckpoint = parseCheckpoint(oldCheckpointValue);
  const newCheckpoint = parseCheckpoint(newCheckpointValue);
  if (
    oldCheckpoint.log.type !== newCheckpoint.log.type ||
    oldCheckpoint.log.id !== newCheckpoint.log.id
  ) {
    fail(
      "LOG_IDENTITY_MISMATCH",
      "Consistency checkpoints identify different logs.",
    );
  }
  if (newCheckpoint.treeSize < oldCheckpoint.treeSize) {
    fail(
      "REWIND_DETECTED",
      "New checkpoint tree size is smaller than the previous checkpoint.",
    );
  }
  const proof = requireRecord(
    consistencyProofValue,
    "consistency_proof",
    "INVALID_CONSISTENCY_PROOF",
  );
  const contract = requireRecord(
    proof.contract,
    "consistency_proof.contract",
    "INVALID_CONSISTENCY_PROOF",
  );
  if (
    contract.name !== "transparency_consistency_proof" ||
    contract.version !== "v1"
  ) {
    fail(
      "INVALID_CONSISTENCY_PROOF",
      "Proof contract must declare transparency_consistency_proof v1.",
    );
  }
  if (proof.hash_algorithm !== "sha-256") {
    fail(
      "INVALID_CONSISTENCY_PROOF",
      "Consistency proof hash_algorithm must be sha-256.",
    );
  }
  const logId = requireString(
    proof.log_id,
    "consistency_proof.log_id",
    "INVALID_CONSISTENCY_PROOF",
  );
  const oldSize = requireInteger(
    proof.old_tree_size,
    "consistency_proof.old_tree_size",
    "INVALID_CONSISTENCY_PROOF",
  );
  const newSize = requireInteger(
    proof.new_tree_size,
    "consistency_proof.new_tree_size",
    "INVALID_CONSISTENCY_PROOF",
  );
  if (
    logId !== oldCheckpoint.log.id ||
    oldSize !== oldCheckpoint.treeSize ||
    newSize !== newCheckpoint.treeSize
  ) {
    fail(
      "CHECKPOINT_MISMATCH",
      "Consistency proof does not match the supplied checkpoints.",
    );
  }
  const path = parseHashPath(
    proof.consistency_path,
    "consistency_proof.consistency_path",
    "INVALID_CONSISTENCY_PROOF",
  );
  if (oldSize === 0) {
    if (path.length !== 0) {
      fail(
        "CONSISTENCY_PROOF_INVALID",
        "Empty-tree consistency proof must have an empty path.",
      );
    }
  } else if (oldSize === newSize) {
    if (
      path.length !== 0 ||
      !oldCheckpoint.rootHash.equals(newCheckpoint.rootHash)
    ) {
      fail(
        "EQUIVOCATION_DETECTED",
        "Same-size checkpoints have different roots or a non-empty proof.",
      );
    }
  } else {
    let fn = oldSize - 1;
    let sn = newSize - 1;
    while (fn % 2 === 1) {
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    let first: Buffer;
    let second: Buffer;
    let proofIndex: number;
    if (fn === 0) {
      first = oldCheckpoint.rootHash;
      second = oldCheckpoint.rootHash;
      proofIndex = 0;
    } else {
      const initial = path[0];
      if (initial === undefined) {
        fail(
          "CONSISTENCY_PROOF_INVALID",
          "Consistency proof path is incomplete.",
        );
      }
      first = initial;
      second = initial;
      proofIndex = 1;
    }
    while (proofIndex < path.length) {
      const sibling = path[proofIndex];
      if (sibling === undefined || sn === 0) {
        fail(
          "CONSISTENCY_PROOF_INVALID",
          "Consistency proof path contains extra hashes.",
        );
      }
      if (fn % 2 === 1 || fn === sn) {
        first = nodeHash(sibling, first);
        second = nodeHash(sibling, second);
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      } else {
        second = nodeHash(second, sibling);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
      proofIndex += 1;
    }
    if (
      sn !== 0 ||
      !first.equals(oldCheckpoint.rootHash) ||
      !second.equals(newCheckpoint.rootHash)
    ) {
      fail(
        "CONSISTENCY_PROOF_INVALID",
        "Checkpoints are not append-only consistent.",
      );
    }
  }
  return {
    log_id: logId,
    old_tree_size: oldSize,
    new_tree_size: newSize,
  };
}

export function verifyCountersignatureInclusion(
  countersignatureValue: unknown,
  inclusionProofValue: unknown,
  checkpointValue: unknown,
  trustedKeysValue: unknown,
): VerifiedInclusion {
  const countersignature = requireRecord(
    countersignatureValue,
    "countersignature",
    "INVALID_COUNTERSIGNATURE",
  );
  const contract = requireRecord(
    countersignature.contract,
    "countersignature.contract",
    "INVALID_COUNTERSIGNATURE",
  );
  if (
    contract.name !== "receipt_countersignature" ||
    contract.version !== "v1"
  ) {
    fail(
      "INVALID_COUNTERSIGNATURE",
      "Contract must declare receipt_countersignature v1.",
    );
  }
  const digest = parseDigest(
    countersignature.receipt_digest,
    "countersignature.receipt_digest",
  );
  const anchor = requireRecord(
    countersignature.anchor_reference,
    "countersignature.anchor_reference",
    "ORPHAN_COUNTERSIGNATURE",
  );
  if (anchor.type !== "transparency_log") {
    fail(
      "ORPHAN_COUNTERSIGNATURE",
      "Counter-signature is not anchored to a transparency log.",
    );
  }
  const anchorLogId = requireString(
    anchor.id,
    "countersignature.anchor_reference.id",
    "ORPHAN_COUNTERSIGNATURE",
  );
  const anchorLeafIndex = requireInteger(
    anchor.leaf_index,
    "countersignature.anchor_reference.leaf_index",
    "ORPHAN_COUNTERSIGNATURE",
  );
  const checkpoint = verifyCheckpointSignature(
    checkpointValue,
    trustedKeysValue,
  );
  let inclusion: VerifiedInclusion;
  try {
    inclusion = verifyInclusion(
      digest,
      inclusionProofValue,
      checkpointValue,
    );
  } catch (error) {
    if (
      error instanceof TransparencyVerificationError &&
      error.code === "LEAF_DIGEST_MISMATCH"
    ) {
      fail(
        "ORPHAN_COUNTERSIGNATURE",
        "Counter-signature digest is not the digest proven at the declared log leaf.",
      );
    }
    throw error;
  }
  if (
    anchorLogId !== inclusion.log_id ||
    anchorLeafIndex !== inclusion.leaf_index
  ) {
    fail(
      "ORPHAN_COUNTERSIGNATURE",
      "Counter-signature anchor does not match the verified inclusion proof.",
    );
  }
  return { ...inclusion, checkpoint };
}

export function verifyMonitorUpdate(
  previousCheckpoint: unknown,
  currentCheckpoint: unknown,
  consistencyProof: unknown,
  trustedKeys: unknown,
): VerifiedMonitorUpdate {
  const previous = verifyCheckpointSignature(previousCheckpoint, trustedKeys);
  const current = verifyCheckpointSignature(currentCheckpoint, trustedKeys);
  const consistency = verifyConsistency(
    previousCheckpoint,
    currentCheckpoint,
    consistencyProof,
  );
  return { previous, current, consistency };
}

export const verify_checkpoint_signature = verifyCheckpointSignature;
export const verify_inclusion = verifyInclusion;
export const verify_consistency = verifyConsistency;
export const verify_countersignature_inclusion =
  verifyCountersignatureInclusion;
export const verify_monitor_update = verifyMonitorUpdate;
