// Run THIS checkout's shared verifier vectors (cases.json, edge_binding_cases.json,
// edge_revocation_cases.json) against an INSTALLED @actenon/verifier-sdk (argv[2]: project dir
// containing node_modules/@actenon/verifier-sdk). Exits non-zero on any mismatch or missing API.
import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
const project = process.argv[2];
const pkgDir = path.join(project, "node_modules/@actenon/verifier-sdk");
const pkg = JSON.parse(readFileSync(path.join(pkgDir, "package.json"), "utf8"));
const entry = typeof pkg.exports?.["."] === "object" ? pkg.exports["."].import : pkg.main;
const sdk = await import(pathToFileURL(path.join(pkgDir, entry)).href);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../actenon/conformance/vectors/verifier_sdk_v1");
const raw = (f) => readFileSync(path.join(root, f));
let failures = 0, ran = 0;
const check = (id, fn, expected) => {
  ran += 1;
  try {
    fn();
    if (expected.outcome !== "verified") { failures += 1; console.log(`FAIL ${id}: verified, expected ${expected.reason_code}`); }
  } catch (e) {
    if (expected.outcome === "verified" || e?.code !== expected.reason_code) { failures += 1; console.log(`FAIL ${id}: ${e?.code ?? e}, expected ${expected.reason_code ?? "verified"}`); }
  }
};
for (const api of ["VerifierSDK", "Ed25519Verifier", "buildLocalProofVerifier"]) {
  if (typeof sdk[api] !== "function") { failures += 1; console.log(`FAIL missing export ${api}`); }
}
if (typeof sdk.VerifierSDK === "function" && typeof new sdk.VerifierSDK(sdk.buildLocalProofVerifier()).verify !== "undefined") {
  failures += 1; console.log("FAIL the parsed-object verify entry point is public");
}
const setPath = (doc, segs, value) => { let c = doc; for (const s of segs.slice(0, -1)) c = c[s]; c[segs.at(-1)] = value; };
const sources = { none: undefined, not_revoked: () => true, revoked: () => false, unavailable: () => { throw new Error("down"); } };
for (const file of ["edge_binding_cases.json", "edge_revocation_cases.json"]) {
  let manifest;
  try { manifest = JSON.parse(raw(file).toString("utf8")); } catch { failures += 1; console.log(`FAIL ${file} unreadable`); continue; }
  const intent = raw(manifest.base.intent);
  for (const v of manifest.cases) {
    const ctx = structuredClone(manifest.base.context);
    if (v.context_mutation) setPath(ctx, v.context_mutation.path, v.context_mutation.value);
    check(`${file}:${v.id}`, () => {
      const s = new sdk.VerifierSDK(sdk.buildLocalProofVerifier(), { clockSkewToleranceMs: v.clock_skew_tolerance_ms, revocationChecker: sources[v.revocation_source] });
      s.verifyJSON({ intent, pccb: raw(v.pccb ?? manifest.base.pccb), context: ctx });
    }, v.expected);
  }
}
console.log(`@actenon/verifier-sdk ${pkg.version}: ${ran} vectors, ${failures} failures`);
process.exit(failures ? 1 : 0);
