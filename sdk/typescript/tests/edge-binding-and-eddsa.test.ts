import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as sdkModule from "../src/index.js";
import {
  buildLocalProofVerifier,
  canonicalizeBytes,
  Ed25519Verifier,
  VerificationError,
  VerifierSDK,
  type VerificationContext,
} from "../src/index.js";
import type { CanonicalValue } from "../src/canonical.js";

const vectorRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../actenon/conformance/vectors/verifier_sdk_v1",
);

const raw = (name: string) => readFile(path.join(vectorRoot, name));

function setPath(document: Record<string, unknown>, segments: string[], value: unknown): void {
  let current = document;
  for (const segment of segments.slice(0, -1)) current = current[segment] as Record<string, unknown>;
  current[segments.at(-1) as string] = value;
}

// protocol/13-edge-binding.md E1-E4, through the strict raw-byte path.
test("edge-binding vectors (E1-E4)", async (t) => {
  const manifest = JSON.parse((await raw("edge_binding_cases.json")).toString("utf8"));
  const intent = await raw(manifest.base.intent);
  for (const vector of manifest.cases) {
    await t.test(vector.id, async () => {
      const pccb = await raw(vector.pccb ?? manifest.base.pccb);
      const context = structuredClone(manifest.base.context) as Record<string, unknown>;
      if (vector.context_mutation) setPath(context, vector.context_mutation.path, vector.context_mutation.value);
      const sdk = new VerifierSDK(buildLocalProofVerifier(), { clockSkewToleranceMs: vector.clock_skew_tolerance_ms });
      const run = () => sdk.verifyJSON({ intent, pccb, context: context as unknown as VerificationContext });
      if (vector.expected.outcome === "verified") {
        run();
        return;
      }
      assert.throws(run, (error: unknown) => {
        assert.ok(error instanceof VerificationError);
        assert.equal(error.code, vector.expected.reason_code);
        assert.equal(error.message, vector.expected.message);
        return true;
      });
    });
  }
});

// Untrusted input must take the strict raw-byte path: the parsed-object
// entry points are not part of the public surface.
test("the parsed-object verify entry points are not exposed", () => {
  const sdk = new VerifierSDK(buildLocalProofVerifier()) as unknown as Record<string, unknown>;
  assert.equal(typeof sdk.verify, "undefined");
  assert.equal(typeof sdk.verifyPayloads, "undefined");
  assert.equal(typeof sdk.verifyJSON, "function");
});

// EdDSA: the algorithm actenon-permit mints production proofs with.
test("Ed25519 JWK verifier verifies an EdDSA proof and refuses tampering", async () => {
  const manifest = JSON.parse((await raw("cases.json")).toString("utf8"));
  const intent = await raw(manifest.base.intent);
  const basePccb = JSON.parse((await raw(manifest.base.pccb)).toString("utf8"));
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "issuer-ed25519-1", alg: "EdDSA" };
  const { signature: _hmac, ...unsigned } = basePccb;
  const value = cryptoSign(null, canonicalizeBytes(unsigned as CanonicalValue), privateKey).toString("base64url");
  const pccb = { ...unsigned, signature: { algorithm: "EdDSA", encoding: "base64url", key_id: "issuer-ed25519-1", value } };

  const sdk = new VerifierSDK(new Ed25519Verifier([jwk]));
  const context = manifest.base.context as VerificationContext;
  const verified = sdk.verifyJSON({ intent, pccb: JSON.stringify(pccb), context });
  assert.equal(verified.pccb.signature.algorithm, "EdDSA");

  const refused = (p: unknown) =>
    assert.throws(
      () => sdk.verifyJSON({ intent, pccb: JSON.stringify(p), context }),
      (error: unknown) => error instanceof VerificationError && error.code === "SIGNATURE_INVALID",
    );
  refused({ ...pccb, nonce: "tampered" });
  refused({ ...pccb, signature: { ...pccb.signature, key_id: "other" } });
  refused({ ...pccb, signature: { ...pccb.signature, algorithm: "HS256" } });
  const sig = Buffer.from(value, "base64url");
  refused({ ...pccb, signature: { ...pccb.signature, value: Buffer.concat([sig, Buffer.from([0])]).toString("base64url") } });
  // Non-canonical S (S + L) must be refused (RFC 8032 requires S < L).
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i]);
  let sl = s + L;
  const sBytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) { sBytes[i] = Number(sl & 0xffn); sl >>= 8n; }
  refused({ ...pccb, signature: { ...pccb.signature, value: Buffer.concat([sig.subarray(0, 32), sBytes]).toString("base64url") } });

  // An HMAC verifier never accepts the EdDSA proof and vice versa.
  assert.throws(
    () => new VerifierSDK(buildLocalProofVerifier()).verifyJSON({ intent, pccb: JSON.stringify(pccb), context }),
    (error: unknown) => error instanceof VerificationError && error.code === "SIGNATURE_INVALID",
  );
});

test("Ed25519 verifier refuses unusable keys", () => {
  assert.throws(() => new Ed25519Verifier([]));
  assert.throws(() => new Ed25519Verifier([{ kty: "OKP", crv: "Ed25519", x: "AAAA" }]));
  const { privateKey } = generateKeyPairSync("ed25519");
  assert.throws(() => new Ed25519Verifier([{ ...privateKey.export({ format: "jwk" }), kid: "k" }]), /private/);
  assert.ok(typeof (sdkModule as Record<string, unknown>).Ed25519Verifier === "function");
});
