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

export function canonicalizeJson(value: CanonicalValue): string {
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
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  const entries = Object.keys(value)
    .sort()
    .map((key) => `${canonicalizeString(key)}:${canonicalizeJson(value[key] as CanonicalValue)}`);
  return `{${entries.join(",")}}`;
}

export function canonicalizeBytes(value: CanonicalValue): Uint8Array {
  return Buffer.from(canonicalizeJson(value), "utf-8");
}

export function sha256Hex(value: CanonicalValue): string {
  return createHash("sha256").update(canonicalizeBytes(value)).digest("hex");
}
