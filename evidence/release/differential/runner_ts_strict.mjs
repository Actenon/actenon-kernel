// Kernel-bundled TS SDK runner, STRICT raw entry point: raw bytes -> VerifierSDK.verifyJSON.
// argv: corpus out.jsonl label. Imports the INSTALLED package.
import { readFileSync, writeFileSync } from "node:fs";

import path from "node:path";
const sdk = await import("@actenon/verifier-sdk");
const [corpus, outPath, label] = process.argv.slice(2);
const resolved = import.meta.resolve("@actenon/verifier-sdk");
if (!resolved.includes("node_modules")) throw new Error("not an installed package: " + resolved);
const trust = JSON.parse(readFileSync(path.join(corpus, "trust.json"), "utf8"));
const manifest = JSON.parse(readFileSync(path.join(corpus, "manifest.json"), "utf8"));
const hmac = new sdk.HmacSha256Verifier({ secret: trust.hmac.secret_utf8, keyId: trust.hmac.key_id });
const rows = [];
for (const c of manifest.cases) {
  const d = path.join(corpus, c.id);
  const ctx = JSON.parse(readFileSync(path.join(d, "context.json"), "utf8"));
  if (c.alg === "EdDSA") { rows.push({ id: c.id, outcome: "UNSUPPORTED", code: "NO_EDDSA_PCCB_VERIFIER" }); continue; }
  let row;
  try {
    const v = new sdk.VerifierSDK(hmac, { clockSkewToleranceMs: ctx.clock_skew_ms ?? 0 });
    const intent = readFileSync(path.join(d, "intent.json"));
    const pccb = readFileSync(path.join(d, "pccb.json"));
    const { clock_skew_ms, ...context } = ctx;
    v.verifyJSON({ intent, pccb, context });
    row = { id: c.id, outcome: "ACCEPT", code: null };
  } catch (e) {
    row = { id: c.id, outcome: "REFUSE", code: e?.code ?? e?.reasonCode ?? e?.name ?? "Error" };
  }
  rows.push(row);
}
writeFileSync(outPath, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
console.log(`${label}: ${rows.length} cases -> ${outPath} (${resolved})`);
