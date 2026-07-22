import express from "express";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  VerifierSDK,
  VerificationError,
  buildLocalProofVerifier,
  type ActionIntent,
  type PCCB,
  type VerifiedProtectedRequest,
} from "../../sdk/typescript/src/index.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.resolve(__dirname, "../../sdk/typescript/fixtures/portable-local-proof");
const app = express();

app.use(express.json());

async function readJsonFixture<T>(filename: string): Promise<T> {
  const raw = await readFile(path.join(fixturesDir, filename), "utf-8");
  return JSON.parse(raw) as T;
}

function buildRequestId(prefix: string): string {
  return `${prefix}_${Date.now()}`;
}

function executeProtectedHello(verified: VerifiedProtectedRequest, requestId: string) {
  const message = verified.intent.action.parameters.message;
  if (typeof message !== "string" || message.length === 0) {
    throw new Error("HELLO_MESSAGE_INVALID");
  }
  return {
    resource_id: "hello_resource_demo_001",
    message,
    request_id: requestId,
    intent_id: verified.intent.intent_id,
    pccb_id: verified.pccb.pccb_id,
    action_hash: verified.pccb.action_hash.value,
    external_reference: `hello_local_${requestId}`,
    operator_summary: `Hello world protected resource returned the bound message '${message}'.`,
  };
}

function buildExecutionReceipt(verified: VerifiedProtectedRequest, requestId: string, protectedResponse: Record<string, unknown>) {
  return {
    contract: { name: "receipt", version: "v1" },
    receipt_id: `rcpt_${requestId}`,
    intent_id: verified.intent.intent_id,
    occurred_at: "2026-01-01T12:00:00Z",
    outcome: "executed",
    phase: "execution",
    tenant: verified.intent.tenant,
    subject: verified.intent.requester,
    action: verified.intent.action,
    target: verified.intent.target,
    correlation: {
      pccb_id: verified.pccb.pccb_id,
      request_id: requestId,
    },
    summary: "The protected action executed successfully.",
    side_effects: {
      state: "completed",
      external_reference: protectedResponse.external_reference,
    },
    details: protectedResponse,
  };
}

function buildRefusal(
  requestId: string,
  intent: ActionIntent | null,
  pccb: PCCB | null,
  error: VerificationError,
) {
  return {
    contract: { name: "refusal", version: "v1" },
    refusal_id: `rfsl_${requestId}`,
    intent_id: intent?.intent_id ?? null,
    category: "proof",
    refusal_code: error.code,
    message: error.message,
    retryable: false,
    refused_at: "2026-01-01T12:00:00Z",
    tenant: intent?.tenant ?? null,
    subject: intent?.requester ?? null,
    audience: { type: "service", id: "portable-hello-world-endpoint" },
    action: intent?.action ?? null,
    target: intent?.target ?? null,
    correlation: {
      pccb_id: pccb?.pccb_id ?? null,
      request_id: requestId,
    },
    details: error.details ?? {},
  };
}

function buildRefusedReceipt(requestId: string, intent: ActionIntent, refusal: ReturnType<typeof buildRefusal>) {
  return {
    contract: { name: "receipt", version: "v1" },
    receipt_id: `rcpt_${requestId}`,
    intent_id: intent.intent_id,
    occurred_at: "2026-01-01T12:00:00Z",
    outcome: "refused",
    phase: "execution",
    tenant: intent.tenant,
    subject: intent.requester,
    action: intent.action,
    target: intent.target,
    correlation: {
      refusal_id: refusal.refusal_id,
      request_id: requestId,
    },
    summary: refusal.message,
    reason_codes: [refusal.refusal_code],
    side_effects: {
      state: "none",
    },
    details: {},
  };
}

app.get("/", (_request, response) => {
  response.json({ ok: true, endpoint: "/protected-resource" });
});

app.post("/protected-resource", async (request, response) => {
  const verifier = new VerifierSDK(buildLocalProofVerifier());
  const requestId = buildRequestId("express");
  const fallbackIntent = await readJsonFixture<ActionIntent>("action_intent.json");
  const fallbackPccb = await readJsonFixture<PCCB>("pccb.json");
  const intentPayload = request.body?.intent ?? fallbackIntent;
  const pccbPayload = request.body?.pccb ?? fallbackPccb;

  let parsedIntent: ActionIntent | null = null;
  let parsedPccb: PCCB | null = null;

  try {
    parsedIntent = verifier.parseIntent(intentPayload);
    parsedPccb = verifier.parsePccb(pccbPayload);

    // Proof verification happens here, before the protected action is allowed to run.
    const verified = verifier.verify({
      intent: parsedIntent,
      pccb: parsedPccb,
      context: {
        request_id: requestId,
        audience: { type: "service", id: "portable-hello-world-endpoint" },
        now: "2026-01-01T12:00:00Z",
        scope_capabilities: ["protected_resource.read"],
        parameter_constraints: { exact_message: "portable hello world" },
        resource_selectors: [{ resource_id: "hello_resource_demo_001" }],
      },
    });

    const protectedResponse = executeProtectedHello(verified, requestId);
    const receipt = buildExecutionReceipt(verified, requestId, protectedResponse);
    response.json({
      ok: true,
      protected_response: protectedResponse,
      receipt,
    });
  } catch (error) {
    if (error instanceof VerificationError && parsedIntent !== null) {
      const refusal = buildRefusal(requestId, parsedIntent, parsedPccb, error);
      const receipt = buildRefusedReceipt(requestId, parsedIntent, refusal);
      response.status(403).json({
        ok: false,
        refusal,
        receipt,
      });
      return;
    }
    response.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : "invalid_request",
    });
  }
});

app.listen(3000, () => {
  process.stdout.write("Protected Express example listening on http://127.0.0.1:3000\n");
});
