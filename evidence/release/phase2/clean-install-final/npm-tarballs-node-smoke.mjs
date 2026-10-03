// Installed tarballs only (no TypeScript tooling): @actenon/sdk 2.0.0-rc.1 and @actenon/verifier-sdk 0.2.0.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const sdk = await import("@actenon/sdk");
const vsdk = await import("@actenon/verifier-sdk");
const v = JSON.parse(readFileSync("grant_tokens.json", "utf8"));
for (const t of v.valid) assert.equal((await sdk.verifyGrantToken(t.token, v.signing_key)).id, t.grant_id, t.name);
for (const t of v.tampered) await assert.rejects(sdk.verifyGrantToken(t.token, v.signing_key), t.name);
let reencoded = 0;
for (const t of v.valid.filter((x) => x.version === "v2")) {
  assert.equal(sdk.encodeGrantToken(await sdk.verifyGrantToken(t.token, v.signing_key)), t.token, t.name);
  reencoded += 1;
}
assert.equal(reencoded, 4);
assert.equal(typeof new vsdk.VerifierSDK(vsdk.buildLocalProofVerifier()).verify, "undefined");
console.log(`@actenon/sdk ${JSON.parse(readFileSync("node_modules/@actenon/sdk/package.json","utf8")).version}: ${v.valid.length} valid tokens verified, ${v.tampered.length} tampered refused, ${reencoded} v2 re-encoded byte-identically; @actenon/verifier-sdk imports, no parsed-object verify`);
