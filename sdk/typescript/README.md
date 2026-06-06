# TypeScript Verifier SDK

Minimal protected-endpoint verifier SDK for Node and TypeScript, aligned to the Python kernel's public `action_intent` and `pccb` contracts.

This package is intentionally narrow. It focuses on verifier-side proof checking at the protected execution edge and offline verification of Receipt counter-signatures. It does not issue counter-signatures or contain private-key custody or service code.

Choosing between Python, TypeScript, and Go paths? Start with [`../../SDK_SELECTION_GUIDE.md`](../../SDK_SELECTION_GUIDE.md).

## Current Scope

- `action_intent` v1 and `pccb` v1 TypeScript interfaces
- protected-endpoint proof verification
- exact audience, tenant, subject, action, target, action-hash, not-before, and expiry checks
- optional verifier-side clock skew tolerance, defaulting to zero
- deterministic local-proof verification using the OSS local `HS256` signer
- custom signature verification via the exported `SignatureVerifier` interface
- offline Receipt counter-signature verification by historical or active `kid`
- plain Node protected-endpoint example

## Out Of Scope

- replay enforcement
- escrow enforcement
- receipt and refusal generation
- provider adapters
- approval workflows
- hosted or paid control-plane features
- counter-signature issuance and private-key custody

## Install

From this repository:

```bash
cd sdk/typescript
npm install
npm run build
```

To consume it locally from another Node service:

```bash
npm install /absolute/path/to/repo/sdk/typescript
```

## Verify A Proof

```ts
import { buildLocalProofVerifier, VerifierSDK } from "@actenon/verifier-sdk";

const verifier = new VerifierSDK(buildLocalProofVerifier());

const verified = verifier.verifyPayloads({
  intent_payload,
  pccb_payload,
  request_id: "req_ts_001",
  audience: { type: "service", id: "portable-hello-world-endpoint" },
  now: "2026-01-01T12:00:00Z",
  scope_capabilities: ["protected_resource.read"],
  parameter_constraints: { exact_message: "portable hello world" },
  resource_selectors: [{ resource_id: "hello_resource_demo_001" }],
});
```

Clock skew tolerance is strict by default. If a deployment needs to absorb small NTP drift, configure it explicitly:

```ts
const verifier = new VerifierSDK(buildLocalProofVerifier(), {
  clockSkewToleranceMs: 10_000,
});
```

If verification fails, the SDK throws `VerificationError` with stable codes such as:

- `AUDIENCE_MISMATCH`
- `ACTION_MISMATCH`
- `PROOF_EXPIRED`
- `SIGNATURE_INVALID`

## Verify A Receipt Counter-Signature

```ts
import { verifyCountersignature } from "@actenon/verifier-sdk";

const verified = verifyCountersignature(
  receiptOrDigest,
  countersignature,
  pinnedPublicKeys,
);
```

`pinnedPublicKeys` is a trusted `key_discovery v1` document. Verification is
offline, selects the exact public key by `kid`, and supports retained
historical keys. It performs no key fetch and contains no signing path.

## Example

Run the plain Node protected-endpoint example:

```bash
cd sdk/typescript
npm run example
```

Then call it:

```bash
curl -X POST http://127.0.0.1:3000/protected-resource \
  -H 'content-type: application/json' \
  -d @fixtures/portable-local-proof/request-body.json
```

If you omit the request body, the example falls back to the bundled local-proof fixtures.

## Tests

```bash
cd sdk/typescript
npm test
```

Current coverage includes:

- valid proof
- audience mismatch
- action mutation
- expired proof
- strict and tolerant clock-boundary behavior
- valid historical counter-signature plus unknown-key, wrong-key, and altered-digest rejection

## Example Fixtures

Bundled fixtures live under:

- `fixtures/portable-local-proof/action_intent.json`
- `fixtures/portable-local-proof/pccb.json`
- `fixtures/portable-local-proof/request-body.json`

These match the Python portable local proof demo and are suitable for local verifier smoke tests.

## Contract Sources

The canonical public specs and schemas remain in the repository root:

- [`../../spec/action-intent/SPEC.md`](../../spec/action-intent/SPEC.md)
- [`../../spec/pccb/SPEC.md`](../../spec/pccb/SPEC.md)
- [`../../schemas/action_intent.v1.json`](../../schemas/action_intent.v1.json)
- [`../../schemas/pccb.v1.json`](../../schemas/pccb.v1.json)
- [`../../spec/countersignature/SPEC.md`](../../spec/countersignature/SPEC.md)
- [`../../schemas/receipt_countersignature.v1.json`](../../schemas/receipt_countersignature.v1.json)
