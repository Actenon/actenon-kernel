import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildLocalProofVerifier,
  canonicalizeBytes,
  LOCAL_PROOF_SECRET,
  VerificationError,
  VerifierSDK,
  type ActionIntent,
  type PCCB,
  type VerificationContext,
} from "../src/index.js";
import type { CanonicalValue } from "../src/canonical.js";

interface Mutation {
  document: "intent" | "pccb" | "context";
  path: string[];
  value: unknown;
}

interface VectorCase {
  id: string;
  clock_skew_tolerance_ms: number;
  mutation?: Mutation;
  expected: {
    outcome: "verified" | "refused";
    reason_code?: string;
    message?: string;
  };
}

interface VectorManifest {
  base: {
    intent: string;
    pccb: string;
    context: VerificationContext;
  };
  cases: VectorCase[];
}

const vectorRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../actenon/conformance/vectors/verifier_sdk_v1",
);

async function loadJson<T>(name: string): Promise<T> {
  return JSON.parse(await readFile(path.join(vectorRoot, name), "utf-8")) as T;
}

function setPath(document: unknown, segments: string[], value: unknown): void {
  let current = document as Record<string, unknown>;
  for (const segment of segments.slice(0, -1)) {
    const child = current[segment];
    assert.ok(child !== null && typeof child === "object" && !Array.isArray(child));
    current = child as Record<string, unknown>;
  }
  const leaf = segments.at(-1);
  assert.ok(leaf);
  current[leaf] = value;
}

test("shared verifier SDK conformance vectors", async (t) => {
  const manifest = await loadJson<VectorManifest>("cases.json");
  const baseIntent = await loadJson<ActionIntent>(manifest.base.intent);
  const basePccb = await loadJson<PCCB>(manifest.base.pccb);

  for (const vector of manifest.cases) {
    await t.test(vector.id, () => {
      const intent = structuredClone(baseIntent);
      const pccb = structuredClone(basePccb);
      const context = structuredClone(manifest.base.context);
      if (vector.mutation !== undefined) {
        setPath(
          { intent, pccb, context }[vector.mutation.document],
          vector.mutation.path,
          vector.mutation.value,
        );
      }
      const sdk = new VerifierSDK(buildLocalProofVerifier(), {
        clockSkewToleranceMs: vector.clock_skew_tolerance_ms,
      });

      if (vector.expected.outcome === "verified") {
        const verified = sdk.verify({ intent, pccb, context });
        assert.equal(verified.pccb.pccb_id, "pccb_portable_hello_world_001");
        return;
      }

      assert.throws(
        () => sdk.verify({ intent, pccb, context }),
        (error: unknown) => {
          assert.ok(error instanceof VerificationError);
          assert.equal(error.code, vector.expected.reason_code);
          assert.equal(error.message, vector.expected.message);
          return true;
        },
      );
    });
  }
});

// The kernel mints every new PCCB with the ACTENON-JCS-STRICT-1 action-hash
// label (actenon-protocol >= 1.1); RFC8785-JCS is the accepted legacy alias.
// The shared vectors only carry the legacy label, so re-label the base proof,
// re-sign it with the public local development key, and require the same
// verdicts the Python reference gives.
function relabelAndResign(pccb: PCCB, canonicalization: string): PCCB {
  const relabelled = structuredClone(pccb) as unknown as Record<string, unknown>;
  (relabelled.action_hash as Record<string, unknown>).canonicalization = canonicalization;
  const { signature, ...unsigned } = relabelled;
  const value = createHmac("sha256", LOCAL_PROOF_SECRET)
    .update(canonicalizeBytes(unsigned as CanonicalValue))
    .digest("base64url");
  return { ...relabelled, signature: { ...(signature as object), value } } as unknown as PCCB;
}

test("verifier accepts both accepted canonicalization profile labels", async () => {
  const manifest = await loadJson<VectorManifest>("cases.json");
  const intent = await loadJson<ActionIntent>(manifest.base.intent);
  const basePccb = await loadJson<PCCB>(manifest.base.pccb);
  for (const label of ["ACTENON-JCS-STRICT-1", "RFC8785-JCS"]) {
    const sdk = new VerifierSDK(buildLocalProofVerifier());
    const verified = sdk.verify({
      intent: structuredClone(intent),
      pccb: relabelAndResign(basePccb, label),
      context: structuredClone(manifest.base.context),
    });
    assert.equal(verified.pccb.action_hash.canonicalization, label);
  }
});

test("verifier refuses an unknown canonicalization profile label", async () => {
  const manifest = await loadJson<VectorManifest>("cases.json");
  const intent = await loadJson<ActionIntent>(manifest.base.intent);
  const basePccb = await loadJson<PCCB>(manifest.base.pccb);
  for (const label of ["actenon-jcs-sha256-v1", "JCS", ""]) {
    const sdk = new VerifierSDK(buildLocalProofVerifier());
    assert.throws(
      () =>
        sdk.verify({
          intent: structuredClone(intent),
          pccb: relabelAndResign(basePccb, label),
          context: structuredClone(manifest.base.context),
        }),
      (error: unknown) => error instanceof VerificationError,
    );
  }
});

interface TimestampCase {
  id: string;
  intent: string;
  pccb: string;
  context: VerificationContext;
  expected: VectorCase["expected"];
}

// Fractional-second timestamps under ACTENON-JCS-STRICT-1: timestamps must be
// re-serialised exactly as the Python reference does (six-digit microseconds)
// and time windows compared at microsecond precision.
test("shared fractional-second timestamp vectors", async (t) => {
  const manifest = await loadJson<{ clock_skew_tolerance_ms: number; cases: TimestampCase[] }>(
    "timestamp_cases.json",
  );
  for (const vector of manifest.cases) {
    await t.test(vector.id, async () => {
      const intent = await loadJson<ActionIntent>(vector.intent);
      const pccb = await loadJson<PCCB>(vector.pccb);
      const sdk = new VerifierSDK(buildLocalProofVerifier(), {
        clockSkewToleranceMs: manifest.clock_skew_tolerance_ms,
      });
      if (vector.expected.outcome === "verified") {
        const verified = sdk.verify({ intent, pccb, context: vector.context });
        assert.equal(verified.pccb.action_hash.canonicalization, "ACTENON-JCS-STRICT-1");
        return;
      }
      assert.throws(
        () => sdk.verify({ intent, pccb, context: vector.context }),
        (error: unknown) => {
          assert.ok(error instanceof VerificationError);
          assert.equal(error.code, vector.expected.reason_code);
          assert.equal(error.message, vector.expected.message);
          return true;
        },
      );
    });
  }
});
