import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildLocalProofVerifier, parseStrictJson, StrictJsonError, VerifierSDK, VerificationError } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.resolve(__dirname, "../fixtures/portable-local-proof");
const port = Number(process.env.PORT ?? "3000");

async function readFixture(filename: string): Promise<Buffer> {
  return readFile(path.join(fixturesDir, filename));
}

async function readBody(request: import("node:http").IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) {
    return {};
  }
  // Untrusted body: parse strictly (no duplicate members, no float/exponent
  // number lexemes) before handing members to the verifier.
  return parseStrictJson(Buffer.concat(chunks));
}

const verifier = new VerifierSDK(buildLocalProofVerifier());

const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true, endpoint: "/protected-resource" }));
    return;
  }

  if (request.method !== "POST" || request.url !== "/protected-resource") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: false, error: "not_found" }));
    return;
  }

  try {
    const body = (await readBody(request)) as { intent?: unknown; pccb?: unknown };
    const verified = verifier.verifyJSON({
      intent: body.intent !== undefined ? JSON.stringify(body.intent) : await readFixture("action_intent.json"),
      pccb: body.pccb !== undefined ? JSON.stringify(body.pccb) : await readFixture("pccb.json"),
      context: {
        request_id: `ts_example_${Date.now()}`,
        audience: { type: "service", id: "portable-hello-world-endpoint" },
        now: "2026-01-01T12:00:00Z",
        scope_capabilities: ["protected_resource.read"],
        parameter_constraints: { exact_message: "portable hello world" },
        resource_selectors: [{ resource_id: "hello_resource_demo_001" }],
      },
    });

    const message = String(verified.intent.action.parameters.message ?? "hello");
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        ok: true,
        pccb_id: verified.pccb.pccb_id,
        message,
      }),
    );
  } catch (error) {
    if (error instanceof StrictJsonError) {
      response.writeHead(400, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: false, category: "request", code: "MALFORMED_REQUEST" }));
      return;
    }
    if (error instanceof VerificationError) {
      response.writeHead(403, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          ok: false,
          category: "proof",
          code: error.code,
          message: error.message,
        }),
      );
      return;
    }
    response.writeHead(500, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        ok: false,
        error: "internal_error",
      }),
    );
  }
});

server.listen(port, () => {
  process.stdout.write(`Protected endpoint example listening on http://127.0.0.1:${port}\n`);
});
