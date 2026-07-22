import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  TransparencyVerificationError,
  verifyCheckpointSignature,
  verifyConsistency,
  verifyCountersignature,
  verifyCountersignatureInclusion,
  verifyInclusion,
  verifyMonitorUpdate,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.resolve(
  __dirname,
  "../../../conformance/vectors/transparency_log_v1",
);

async function loadFixture(name: string): Promise<unknown> {
  return JSON.parse(
    await readFile(path.join(fixturesDir, name), "utf-8"),
  ) as unknown;
}

function expectCode(expected: string, operation: () => unknown): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof TransparencyVerificationError);
    assert.equal(error.code, expected);
    return true;
  });
}

test("transparency proofs and historical checkpoint kids verify offline", async () => {
  const keys = await loadFixture("trusted_keys.json");
  const oldCheckpoint = await loadFixture("checkpoint_old.json");
  const newCheckpoint = await loadFixture("checkpoint_new.json");

  assert.equal(
    verifyCheckpointSignature(oldCheckpoint, keys).key_id,
    "fixture-log-2025",
  );
  assert.equal(
    verifyCheckpointSignature(newCheckpoint, keys).key_id,
    "fixture-log-2026",
  );
  assert.equal(
    verifyInclusion(
      await loadFixture("leaf_digest.json"),
      await loadFixture("inclusion_proof.json"),
      newCheckpoint,
    ).leaf_index,
    2,
  );
  assert.equal(
    verifyConsistency(
      oldCheckpoint,
      newCheckpoint,
      await loadFixture("consistency_proof.json"),
    ).new_tree_size,
    4,
  );
});

test("monitor rejects a signed fork and a rewind", async () => {
  const keys = await loadFixture("trusted_keys.json");
  const oldCheckpoint = await loadFixture("checkpoint_old.json");
  const newCheckpoint = await loadFixture("checkpoint_new.json");
  const proof = await loadFixture("consistency_proof.json");
  const forkedCheckpoint = await loadFixture(
    "mutations/checkpoint_new_forked.json",
  );
  const sameSizeProof = {
    contract: {
      name: "transparency_consistency_proof",
      version: "v1",
    },
    log_id: "actenon-transparency-fixture",
    hash_algorithm: "sha-256",
    old_tree_size: 4,
    new_tree_size: 4,
    consistency_path: [],
  };

  assert.equal(
    verifyMonitorUpdate(oldCheckpoint, newCheckpoint, proof, keys).current
      .tree_size,
    4,
  );
  expectCode("EQUIVOCATION_DETECTED", () =>
    verifyMonitorUpdate(
      newCheckpoint,
      forkedCheckpoint,
      sameSizeProof,
      keys,
    ),
  );
  expectCode("REWIND_DETECTED", () =>
    verifyConsistency(newCheckpoint, oldCheckpoint, proof),
  );
});

test("checkpoint verification rejects an unknown kid", async () => {
  const checkpoint = await loadFixture(
    "mutations/checkpoint_unknown_kid.json",
  );
  const keys = await loadFixture("trusted_keys.json");

  expectCode("UNKNOWN_KEY_ID", () =>
    verifyCheckpointSignature(checkpoint, keys),
  );
});

test("a signed but unlogged counter-signature is rejected as orphaned", async () => {
  const orphan = (await loadFixture(
    "mutations/countersignature_orphan.json",
  )) as { receipt_digest: unknown };
  const keys = await loadFixture("trusted_keys.json");
  const inclusionProof = await loadFixture("inclusion_proof.json");
  const checkpoint = await loadFixture("checkpoint_new.json");

  verifyCountersignature(orphan.receipt_digest, orphan, keys);
  expectCode("ORPHAN_COUNTERSIGNATURE", () =>
    verifyCountersignatureInclusion(
      orphan,
      inclusionProof,
      checkpoint,
      keys,
    ),
  );
});
