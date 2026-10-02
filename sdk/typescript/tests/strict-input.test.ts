import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildLocalProofVerifier, VerificationError, VerifierSDK, type VerificationContext } from "../src/index.js";

// Untrusted request bodies must reach the verifier as raw bytes. JSON.parse
// keeps the last of duplicate members and turns 2500.0 into 2500, so a proof
// the Python reference refuses would verify. verifyJSON parses strictly.

const vectorRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../actenon/conformance/vectors/verifier_sdk_v1",
);

async function materials() {
  const manifest = JSON.parse(await readFile(path.join(vectorRoot, "cases.json"), "utf-8"));
  const intent = (await readFile(path.join(vectorRoot, manifest.base.intent), "utf-8")).trim();
  const pccb = (await readFile(path.join(vectorRoot, manifest.base.pccb), "utf-8")).trim();
  return { intent, pccb, context: manifest.base.context as VerificationContext };
}

function refusedWith(fn: () => unknown, code: string): void {
  assert.throws(fn, (error: unknown) => error instanceof VerificationError && error.code === code);
}

const sdk = new VerifierSDK(buildLocalProofVerifier());

test("verifyJSON accepts the raw shared vector", async () => {
  const { intent, pccb, context } = await materials();
  const verified = sdk.verifyJSON({ intent, pccb, context });
  assert.equal(verified.pccb.pccb_id, "pccb_portable_hello_world_001");
  sdk.verifyJSON({ intent: Buffer.from(intent), pccb: new TextEncoder().encode(pccb), context });
});

test("verifyJSON refuses duplicate object members in the intent and the proof", async () => {
  const { intent, pccb, context } = await materials();
  const dupIntent = intent.replace('"message": "portable hello world"', '"message": "tampered", "message": "portable hello world"');
  assert.notEqual(dupIntent, intent);
  refusedWith(() => sdk.verifyJSON({ intent: dupIntent, pccb, context }), "INVALID_INTENT");
  const dupPccb = pccb.replace('"nonce":', '"nonce": "x", "nonce":');
  assert.notEqual(dupPccb, pccb);
  refusedWith(() => sdk.verifyJSON({ intent, pccb: dupPccb, context }), "INVALID_PCCB");
});

test("verifyJSON refuses non-integer number lexemes that JSON.parse would collapse", async () => {
  const { pccb, context } = await materials();
  for (const lexeme of ["1.0", "1e0", "10e-1", "1E0"]) {
    const intent = JSON.stringify({ n: 1 }).replace("1", lexeme);
    refusedWith(() => sdk.verifyJSON({ intent, pccb, context }), "INVALID_INTENT");
  }
});

test("verifyJSON refuses malformed and non-JSON-text input", async () => {
  const { intent, pccb, context } = await materials();
  for (const bad of [intent + "}", intent + " {}", "﻿" + intent, "{/*c*/}", "[1,]", "{'a':1}", "NaN", ""]) {
    refusedWith(() => sdk.verifyJSON({ intent: bad, pccb, context }), "INVALID_INTENT");
  }
  refusedWith(() => sdk.verifyJSON({ intent: new Uint8Array([0x7b, 0xff, 0x7d]), pccb, context }), "INVALID_INTENT");
  refusedWith(() => sdk.verifyJSON({ intent: '{"a":"\\ud800"}', pccb, context }), "INVALID_INTENT");
  refusedWith(() => sdk.verifyJSON({ intent: "[".repeat(200) + "]".repeat(200), pccb, context }), "INVALID_INTENT");
});

test("signature values must be canonical unpadded base64url", async () => {
  const { intent, pccb, context } = await materials();
  const value = JSON.parse(pccb).signature.value as string;
  for (const variant of [value.slice(0, 10) + " " + value.slice(10), value + "=", value.replace(/-/g, "+").replace(/_/g, "/") + (/[-_]/.test(value) ? "" : "+")]) {
    const mutated = pccb.replace(value, variant);
    refusedWith(() => sdk.verifyJSON({ intent, pccb: mutated, context }), "SIGNATURE_INVALID");
  }
});
