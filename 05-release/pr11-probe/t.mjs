import fs from "node:fs";
import { verifyGrantToken } from "@actenon/sdk";
const toks = JSON.parse(fs.readFileSync("../tokens.json","utf8"));
for (const [k,t] of Object.entries(toks)) {
  try { const g = await verifyGrantToken(t, process.env.ACTENON_SIGNING_KEY); console.log(k, "VERIFIED", g.id); }
  catch (e) { console.log(k, "REJECTED:", e.message); }
}
