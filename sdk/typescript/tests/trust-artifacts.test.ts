import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  TrustArtifactVerificationError,
  verifyApprovalArtifact,
  verifyIssuerStatus,
} from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(
  __dirname,
  "../../../conformance/vectors/trust_artifacts_v1",
);

async function load(name: string): Promise<unknown> {
  return JSON.parse(await readFile(path.join(fixtures, name), "utf-8")) as unknown;
}

function expectCode(expected: string, operation: () => unknown): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof TrustArtifactVerificationError);
    assert.equal(error.code, expected);
    return true;
  });
}

test("issuer status is fail-closed and approval verifies offline", async () => {
  const issuer = await load("issuer.json");
  const statusKeys = await load("issuer_status_trusted_keys.json");
  const approvalKeys = await load("approval_trusted_keys.json");
  const approval = (await load("approval.json")) as { action_hash: never };
  const revoked = await load("issuer_status_revoked.json");
  const stale = await load("issuer_status_stale.json");
  const changedApproval = await load("mutations/approval_action_changed.json");
  const forgedApproval = await load("mutations/approval_signature_changed.json");
  const now = new Date("2026-06-06T12:05:00Z");

  assert.equal(
    verifyIssuerStatus(
      issuer,
      await load("issuer_status_good.json"),
      statusKeys,
      now,
    )?.status,
    "good_standing",
  );
  assert.equal(
    verifyApprovalArtifact(
      approval,
      approvalKeys,
      approval.action_hash,
    ).approval_type,
    "finance_approver",
  );

  expectCode("ISSUER_REVOKED", () =>
    verifyIssuerStatus(
      issuer,
      revoked,
      statusKeys,
      now,
    ),
  );
  expectCode("ISSUER_STATUS_REQUIRED", () =>
    verifyIssuerStatus(issuer, undefined, undefined, now),
  );
  expectCode("ISSUER_STATUS_STALE", () =>
    verifyIssuerStatus(issuer, stale, statusKeys, now),
  );
  expectCode("APPROVAL_ACTION_MISMATCH", () =>
    verifyApprovalArtifact(
      changedApproval,
      approvalKeys,
      approval.action_hash,
    ),
  );
  expectCode("SIGNATURE_INVALID", () =>
    verifyApprovalArtifact(
      forgedApproval,
      approvalKeys,
      approval.action_hash,
    ),
  );
});
