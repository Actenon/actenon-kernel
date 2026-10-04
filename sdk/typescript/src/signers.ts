import { createHmac, createPublicKey, timingSafeEqual, verify as cryptoVerify, type KeyObject } from "node:crypto";

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

export interface Ed25519PublicJwk {
  kty?: unknown;
  crv?: unknown;
  kid?: unknown;
  x?: unknown;
  d?: unknown;
  alg?: unknown;
  [member: string]: unknown;
}

// Ed25519 group order: signatures with S >= L are malleable and refused.
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

/**
 * EdDSA (Ed25519) verifier over pinned issuer public keys published as
 * OKP/Ed25519 JWKs, selected by the signature's key_id. This is the
 * algorithm actenon-permit mints production proofs with.
 */
export class Ed25519Verifier implements SignatureVerifier {
  readonly algorithm = "EdDSA";
  private readonly keys = new Map<string, KeyObject>();

  constructor(jwks: Ed25519PublicJwk[]) {
    for (const jwk of jwks) {
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") throw new Error("only OKP/Ed25519 JWKs are supported");
      if (jwk.d !== undefined) throw new Error("JWK carries private key material; pin public keys only");
      if (typeof jwk.kid !== "string" || jwk.kid === "") throw new Error("an Ed25519 JWK needs a non-empty kid");
      if (typeof jwk.x !== "string" || base64UrlDecode(jwk.x)?.length !== 32) {
        throw new Error("an Ed25519 JWK needs a 32-byte base64url x");
      }
      if (this.keys.has(jwk.kid)) throw new Error("duplicate Ed25519 key ID");
      this.keys.set(jwk.kid, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }));
    }
    if (this.keys.size === 0) throw new Error("no trusted Ed25519 public keys");
  }

  verify(payload: Uint8Array, signature: SignatureSpec): boolean {
    if (signature.algorithm !== this.algorithm || signature.encoding !== "base64url") return false;
    const key = this.keys.get(signature.key_id);
    if (key === undefined) return false;
    const raw = base64UrlDecode(signature.value);
    if (raw === null || raw.length !== 64) return false;
    let s = 0n;
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(raw[32 + i] as number);
    if (s >= ED25519_L) return false;
    try {
      return cryptoVerify(null, payload, key, raw);
    } catch {
      return false;
    }
  }
}
