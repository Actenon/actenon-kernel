import { createHmac, timingSafeEqual } from "node:crypto";

import type { SignatureSpec } from "./types.js";

export interface SignatureVerifier {
  verify(payload: Uint8Array, signature: SignatureSpec): boolean;
}

export const LOCAL_PROOF_KEY_ID = "local-proof-v1";
export const LOCAL_PROOF_SECRET = "actenon-local-proof-secret-v1";

function base64UrlDecode(value: string): Buffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(normalized + padding, "base64");
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
    if (expected.length !== provided.length) {
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
