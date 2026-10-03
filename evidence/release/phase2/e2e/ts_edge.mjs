// Protected edge (verifier only): the BUILT @actenon/verifier-sdk 0.2.0 tarball, installed into an
// empty project, verifying Permit-minted EdDSA proofs through verifyJSON (raw bytes, strict parse).
// usage: node ts_edge.mjs PROOF JWK LABEL [--audience-id ID] [--capabilities a,b] [--mutate-amount N]
//        [--param-constraints JSON] [--resource-selectors JSON] [--revocation-db PATH]
// --revocation-db: Permit's SQLite state store read with node:sqlite, mirroring
// actenon_permit.revocation.StoreRevocationChecker (walk the parent chain; revoked/expired/past
// expires_at => revoked; unknown grant or wrong issuer => throw => AUTHORITY_REVOKED).
// The TS SDK does not enforce single use (README "Out Of Scope: replay enforcement"); this edge
// reports verification outcomes only.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const [proofFile, jwkFile, label, ...rest] = process.argv.slice(2);
const opt = (name, dflt) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : dflt; };
const sdkDir = process.env.TS_SDK_PROJECT;
// The package is ESM-only (exports has an "import" condition only), so resolve its entry point from
// its own package.json rather than with CommonJS require.resolve.
const pkgDir = `${sdkDir}/node_modules/@actenon/verifier-sdk`;
const pkg = JSON.parse(readFileSync(`${pkgDir}/package.json`, "utf8"));
const { VerifierSDK, Ed25519Verifier, VerificationError } = await import(pathToFileURL(`${pkgDir}/${pkg.exports["."].import}`).href);
const d = JSON.parse(readFileSync(proofFile, "utf8"));
const jwk = JSON.parse(readFileSync(jwkFile, "utf8"));
const intent = d.intent;
if (opt("--mutate-amount")) intent.action.parameters.amount_minor = Number(opt("--mutate-amount"));
let revocationChecker;
const db = opt("--revocation-db");
if (db) {
  const { DatabaseSync } = await import("node:sqlite");
  revocationChecker = (pccb) => {
    const authority = pccb.extensions?.authority;
    if (!authority || authority.issuer !== "service:actenon-permit" || typeof authority.grant_id !== "string") {
      throw new Error("not a Permit authority reference");
    }
    const conn = new DatabaseSync(db, { readOnly: true });
    try {
      const seen = new Set();
      let current = authority.grant_id;
      while (current) {
        if (seen.has(current) || seen.size >= 64) throw new Error("grant ancestry cyclic or too deep");
        seen.add(current);
        const row = conn.prepare("SELECT body FROM grants WHERE id = ?").get(current);
        if (!row) throw new Error(`grant ${current} unknown`);
        const grant = JSON.parse(row.body);
        if (grant.status === "revoked" || grant.status === "expired" || Date.parse(grant.expires_at) <= Date.now()) return false;
        current = grant.parent_grant_id;
      }
      return true;
    } finally { conn.close(); }
  };
}
const context = {
  request_id: `req-ts-${label}`,
  audience: { type: "service", id: opt("--audience-id", "actenon-permit-gateway") },
  now: new Date(),
  scope_capabilities: opt("--capabilities", "payments.refund").split(",").filter(Boolean),
  parameter_constraints: JSON.parse(opt("--param-constraints", "{}")),
  resource_selectors: JSON.parse(opt("--resource-selectors", "[]")),
};
const sdk = new VerifierSDK(new Ed25519Verifier([jwk]), { revocationChecker });
try {
  sdk.verifyJSON({ intent: JSON.stringify(intent), pccb: JSON.stringify(d.pccb), context });
  console.log(JSON.stringify({ label, edge: "ts", outcome: "verified" }));
} catch (error) {
  if (!(error instanceof VerificationError)) throw error;
  console.log(JSON.stringify({ label, edge: "ts", outcome: "refused", reason_code: error.code }));
}
