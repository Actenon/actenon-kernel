import { createHash } from "node:crypto";

export type CanonicalValue =
  | null
  | boolean
  | string
  | number
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

function canonicalizeString(value: string): string {
  return JSON.stringify(value);
}

// Protocol ACTENON-JCS-STRICT-1: root depth 0, maximum depth 32.
const MAX_CANONICAL_DEPTH = 32;

function canonicalizeJsonAtDepth(value: CanonicalValue, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) throw new TypeError("canonical JSON depth exceeds 32");
  if (value === null) {
    return "null";
  }
  if (value === true) {
    return "true";
  }
  if (value === false) {
    return "false";
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("floating-point values are not supported in canonical action hashing");
    }
    return String(value);
  }
  if (typeof value === "string") {
    return canonicalizeString(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJsonAtDepth(item, depth + 1)).join(",")}]`;
  }
  const entries = Object.keys(value)
    .sort((left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")))
    .map((key) => `${canonicalizeString(key)}:${canonicalizeJsonAtDepth(value[key] as CanonicalValue, depth + 1)}`);
  return `{${entries.join(",")}}`;
}

export function canonicalizeJson(value: CanonicalValue): string {
  return canonicalizeJsonAtDepth(value, 0);
}

export function canonicalizeBytes(value: CanonicalValue): Uint8Array {
  return Buffer.from(canonicalizeJson(value), "utf-8");
}

export function sha256Hex(value: CanonicalValue): string {
  return createHash("sha256").update(canonicalizeBytes(value)).digest("hex");
}
