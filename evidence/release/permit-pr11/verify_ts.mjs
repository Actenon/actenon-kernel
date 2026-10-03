import { readFileSync } from "node:fs";
const sdk = await import("@actenon/sdk");
const key = process.env.ACTENON_SIGNING_KEY;
const runtime = typeof Bun !== "undefined" ? "bun" : "node";
for (const f of process.argv.slice(2)) {
  const d = JSON.parse(readFileSync(f, "utf8"));
  for (const [name, tok] of Object.entries(d.tokens)) {
    let r;
    try { const g = await sdk.verifyGrantToken(tok, key); r = `ACCEPT (${g.agent_id})`; }
    catch (e) { r = `REJECT ${String(e.message).slice(0, 90)}`; }
    console.log(`producer=permit-py ${d.permit_version.padStart(6)} | verifier=@actenon/sdk 1.4.0 (${runtime}) | ${name.padEnd(22)} | ${r}`);
  }
}
