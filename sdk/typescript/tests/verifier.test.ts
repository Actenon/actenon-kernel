import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildLocalProofVerifier, VerificationError, VerifierSDK, type ActionIntent, type PCCB } from "../src/index.js";

// The SDK only verifies raw bytes (verifyJSON). These tests build their
// inputs as objects, so serialise them first.
function verifyObjects(
  sdk: VerifierSDK,
  input: { intent: unknown; pccb: unknown; context: Parameters<VerifierSDK["verifyJSON"]>[0]["context"] },
) {
  return sdk.verifyJSON({ intent: JSON.stringify(input.intent), pccb: JSON.stringify(input.pccb), context: input.context });
}


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.resolve(__dirname, "../fixtures/portable-local-proof");

async function loadFixture<T>(name: string): Promise<T> {
  const raw = await readFile(path.join(fixturesDir, name), "utf-8");
  return JSON.parse(raw) as T;
}

function buildSdk(): VerifierSDK {
  return new VerifierSDK(buildLocalProofVerifier());
}

function buildContext() {
  return {
    request_id: "req_ts_conformance_001",
    audience: { type: "service", id: "portable-hello-world-endpoint" },
    now: "2026-01-01T12:00:00Z",
    scope_capabilities: ["protected_resource.read"],
    parameter_constraints: { exact_message: "portable hello world" },
    resource_selectors: [{ resource_id: "hello_resource_demo_001" }],
  };
}

test("verifier accepts a valid local proof", async () => {
  const sdk = buildSdk();
  const intent = await loadFixture<ActionIntent>("action_intent.json");
  const pccb = await loadFixture<PCCB>("pccb.json");

  const verified = verifyObjects(sdk, { intent, pccb, context: buildContext() });

  assert.equal(verified.intent.action.name, "hello_world.read");
  assert.equal(verified.pccb.pccb_id, "pccb_portable_hello_world_001");
});

test("verifier refuses audience mismatch", async () => {
  const sdk = buildSdk();
  const intent = await loadFixture<ActionIntent>("action_intent.json");
  const pccb = await loadFixture<PCCB>("pccb.json");

  assert.throws(
    () =>
      verifyObjects(sdk, {
        intent,
        pccb,
        context: {
          ...buildContext(),
          audience: { type: "service", id: "wrong-endpoint" },
        },
      }),
    (error: unknown) => {
      assert.ok(error instanceof VerificationError);
      assert.equal(error.code, "AUDIENCE_MISMATCH");
      return true;
    },
  );
});

test("verifier refuses action mutation", async () => {
  const sdk = buildSdk();
  const intent = await loadFixture<ActionIntent>("action_intent.json");
  const pccb = await loadFixture<PCCB>("pccb.json");
  const mutatedIntent: ActionIntent = {
    ...intent,
    action: {
      ...intent.action,
      parameters: {
        ...intent.action.parameters,
        message: "tampered hello world",
      },
    },
  };

  assert.throws(
    () =>
      verifyObjects(sdk, {
        intent: mutatedIntent,
        pccb,
        context: buildContext(),
      }),
    (error: unknown) => {
      assert.ok(error instanceof VerificationError);
      assert.equal(error.code, "ACTION_MISMATCH");
      return true;
    },
  );
});

test("verifier refuses expired proof", async () => {
  const sdk = buildSdk();
  const intent = await loadFixture<ActionIntent>("action_intent.json");
  const pccb = await loadFixture<PCCB>("pccb.json");

  assert.throws(
    () =>
      verifyObjects(sdk, {
        intent,
        pccb,
        context: {
          ...buildContext(),
          now: "2026-01-01T12:06:00Z",
        },
      }),
    (error: unknown) => {
      assert.ok(error instanceof VerificationError);
      assert.equal(error.code, "PROOF_EXPIRED");
      return true;
    },
  );
});

test("verifier keeps strict not-before behavior by default", async () => {
  const sdk = buildSdk();
  const intent = await loadFixture<ActionIntent>("action_intent.json");
  const pccb = await loadFixture<PCCB>("pccb.json");

  assert.throws(
    () =>
      verifyObjects(sdk, {
        intent,
        pccb,
        context: {
          ...buildContext(),
          now: "2026-01-01T11:59:59Z",
        },
      }),
    (error: unknown) => {
      assert.ok(error instanceof VerificationError);
      assert.equal(error.code, "PROOF_NOT_YET_VALID");
      return true;
    },
  );
});

test("verifier accepts proof within configured clock skew tolerance", async () => {
  const sdk = new VerifierSDK(buildLocalProofVerifier(), { clockSkewToleranceMs: 2000 });
  const intent = await loadFixture<ActionIntent>("action_intent.json");
  const pccb = await loadFixture<PCCB>("pccb.json");

  const early = verifyObjects(sdk, {
    intent,
    pccb,
    context: {
      ...buildContext(),
      now: "2026-01-01T11:59:59Z",
    },
  });
  assert.equal(early.pccb.pccb_id, "pccb_portable_hello_world_001");

  const late = verifyObjects(sdk, {
    intent,
    pccb,
    context: {
      ...buildContext(),
      now: "2026-01-01T12:05:01Z",
    },
  });
  assert.equal(late.pccb.pccb_id, "pccb_portable_hello_world_001");
});

test("verifier refuses proof beyond configured clock skew tolerance", async () => {
  const sdk = new VerifierSDK(buildLocalProofVerifier(), { clockSkewToleranceMs: 2000 });
  const intent = await loadFixture<ActionIntent>("action_intent.json");
  const pccb = await loadFixture<PCCB>("pccb.json");

  assert.throws(
    () =>
      verifyObjects(sdk, {
        intent,
        pccb,
        context: {
          ...buildContext(),
          now: "2026-01-01T11:59:57Z",
        },
      }),
    (error: unknown) => {
      assert.ok(error instanceof VerificationError);
      assert.equal(error.code, "PROOF_NOT_YET_VALID");
      return true;
    },
  );

  assert.throws(
    () =>
      verifyObjects(sdk, {
        intent,
        pccb,
        context: {
          ...buildContext(),
          now: "2026-01-01T12:05:03Z",
        },
      }),
    (error: unknown) => {
      assert.ok(error instanceof VerificationError);
      assert.equal(error.code, "PROOF_EXPIRED");
      return true;
    },
  );
});
