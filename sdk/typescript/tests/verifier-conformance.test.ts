import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildLocalProofVerifier,
  VerificationError,
  VerifierSDK,
  type ActionIntent,
  type PCCB,
  type VerificationContext,
} from "../src/index.js";

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
