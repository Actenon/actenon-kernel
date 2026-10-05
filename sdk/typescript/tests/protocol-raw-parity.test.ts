import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { test } from "node:test";
import { canonicalizeJson, type CanonicalValue } from "../src/canonical.js";
import { parseStrictJson } from "../src/strict-json.js";

test("frozen Protocol raw corpus: exact decisions and canonical bytes", () => {
  const corpus = JSON.parse(readFileSync(new URL("../../../fixtures/protocol_canonicalisation/raw-corpus.json", import.meta.url), "utf8"));
  const rows: Record<string, unknown>[] = [];
  const failures: string[] = [];
  for (const c of corpus.cases) {
    const row: Record<string, unknown> = { id: c.id, decision: "REFUSE" };
    const raw = Buffer.from(c.raw_base64, "base64");
    assert.equal(createHash("sha256").update(raw).digest("hex"), c.raw_sha256);
    try {
      const canonical = canonicalizeJson(parseStrictJson(raw) as CanonicalValue);
      Object.assign(row, { decision: "ACCEPT", canonical_utf8: canonical, canonical_sha256: createHash("sha256").update(canonical).digest("hex") });
    } catch (error) { row.error = String(error); }
    if (row.decision === "REFUSE" && c.expected_decision === "ACCEPT" && c.safe_rejection_profiles.includes("typescript-safe-integer")) row.classification = "SAFE_REJECT";
    else if (row.decision !== c.expected_decision || (row.decision === "ACCEPT" && (row.canonical_utf8 !== c.canonical_utf8 || row.canonical_sha256 !== c.canonical_sha256))) failures.push(c.id);
    rows.push(row);
  }
  if (process.env.ACTENON_PARITY_RESULTS) writeFileSync(process.env.ACTENON_PARITY_RESULTS, JSON.stringify(rows, null, 2) + "\n");
  assert.deepEqual(failures, []);
});
