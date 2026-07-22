import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CounterSignatureVerificationError,
  verifyCountersignature,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.resolve(
  __dirname,
  "../../../conformance/vectors/receipt_countersignature_v1",
);

async function loadFixture(name: string): Promise<unknown> {
  const raw = await readFile(path.join(fixturesDir, name), "utf-8");
  return JSON.parse(raw) as unknown;
}

async function expectCounterSignatureError(
  expectedCode: string,
  countersignatureName: string,
  trustedKeysName = "trusted_keys.json",
): Promise<void> {
  const receipt = await loadFixture("receipt.json");
  const countersignature = await loadFixture(countersignatureName);
  const trustedKeys = await loadFixture(trustedKeysName);

  assert.throws(
    () => verifyCountersignature(receipt, countersignature, trustedKeys),
    (error: unknown) => {
      assert.ok(error instanceof CounterSignatureVerificationError);
      assert.equal(error.code, expectedCode);
      return true;
    },
  );
}

test("counter-signature verifies offline under a historical kid", async () => {
  const receipt = await loadFixture("receipt.json");
  const countersignature = await loadFixture("countersignature.json");
  const trustedKeys = await loadFixture("trusted_keys.json");

  const verified = verifyCountersignature(receipt, countersignature, trustedKeys);

  assert.equal(verified.key_id, "actenon-countersignature-fixture-2025-11");
  assert.equal(
    verified.receipt_digest.value,
    "47dbb2e07068f0f5459d0ad4c2ca425c721962b89ff9c29f3305c3b77bacfb1c",
  );
});

test("counter-signature accepts a pinned receipt digest", async () => {
  const countersignature = (await loadFixture("countersignature.json")) as {
    receipt_digest: unknown;
  };
  const trustedKeys = await loadFixture("trusted_keys.json");

  const verified = verifyCountersignature(
    countersignature.receipt_digest,
    countersignature,
    trustedKeys,
  );

  assert.equal(verified.witness.id, "actenon-countersignature-fixture");
});

test("counter-signature rejects an unknown kid", async () => {
  await expectCounterSignatureError(
    "UNKNOWN_KEY_ID",
    "mutations/countersignature_unknown_kid.json",
  );
});

test("counter-signature rejects a wrong public key", async () => {
  await expectCounterSignatureError(
    "SIGNATURE_INVALID",
    "countersignature.json",
    "mutations/trusted_keys_wrong_key.json",
  );
});

test("counter-signature rejects an altered receipt digest", async () => {
  await expectCounterSignatureError(
    "RECEIPT_DIGEST_MISMATCH",
    "mutations/countersignature_altered_digest.json",
  );
});
