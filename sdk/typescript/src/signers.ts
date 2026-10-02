import { createHmac, timingSafeEqual } from "node:crypto";

import type { SignatureSpec } from "./types.js";

export interface SignatureVerifier {
  verify(payload: Uint8Array, signature: SignatureSpec): boolean;
}

export const LOCAL_PROOF_KEY_ID = "local-proof-v1";
export const LOCAL_PROOF_SECRET = "actenon-local-proof-secret-v1";

// Canonical unpadded base64url only. Buffer.from(..., "base64") skips
// whitespace and unknown characters and ignores non-zero trailing bits, so a
// lenient decode would accept many spellings of one signature.
function base64UrlDecode(value: string): Buffer | null {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    return null;
  }
  const decoded = Buffer.from(value, "base64url");
  return decoded.toString("base64url") === value ? decoded : null;
}

export class HmacSha256Verifier implements SignatureVerifier {
  readonly algorithm: string;
  readonly keyId: string;
  readonly secret: Buffer;

  constructor(options: { secret: string | Uint8Array; keyId: string; algorithm?: string }) {
    this.secret = Buffer.isBuffer(options.secret) ? options.secret : Buffer.from(options.secret);
    this.keyId = options.keyId;
    this.algorithm = options.algorithm ?? "HS256";
  }

  verify(payload: Uint8Array, signature: SignatureSpec): boolean {
    if (
      signature.algorithm !== this.algorithm ||
      signature.key_id !== this.keyId ||
      signature.encoding !== "base64url"
    ) {
      return false;
    }
    const expected = createHmac("sha256", this.secret).update(payload).digest();
    const provided = base64UrlDecode(signature.value);
    if (provided === null || expected.length !== provided.length) {
      return false;
    }
    return timingSafeEqual(expected, provided);
  }
}

export function buildLocalProofVerifier(): HmacSha256Verifier {
  return new HmacSha256Verifier({
    secret: LOCAL_PROOF_SECRET,
    keyId: LOCAL_PROOF_KEY_ID,
  });
}
