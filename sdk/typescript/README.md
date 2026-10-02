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
- offline, fail-closed issuer-status verification
- signed exact-action approval verification
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

Pass untrusted proof material to `verifyJSON` **as received** (the raw
request bytes or text). Do not `JSON.parse` it first: `JSON.parse` keeps the
last of duplicate members and turns `2500.0` or `2.5e3` into `2500`, so a
proof the Python reference refuses would verify. `verifyJSON` parses strictly
(duplicate members, fractional/exponent numbers, unsafe integers, lone
surrogates, a BOM, trailing content and oversize or over-deep input are
refused) and signature values must be canonical unpadded base64url.

```ts
import { VerifierSDK, HmacSha256Verifier } from "@actenon/verifier-sdk";

const verifier = new VerifierSDK(new HmacSha256Verifier({ secret, keyId }));

const verified = verifier.verifyJSON({
  intent: rawIntentBody,   // string | Uint8Array, exactly as received
  pccb: rawPccbBody,       // string | Uint8Array, exactly as received
  context: {
    request_id: "req_ts_001",
    audience: { type: "service", id: "portable-hello-world-endpoint" },
    now: new Date().toISOString(),
    scope_capabilities: ["protected_resource.read"],
  },
});
```

`verifyJSON` is the only verification entry point: the SDK does not accept
already-parsed objects, because it could not tell what `JSON.parse` discarded.
For an envelope that carries both documents, parse it with the exported
`parseStrictJson` and pass `JSON.stringify(member)` for each.

Production issuers (actenon-permit) sign with Ed25519. Pin the issuer's public
JWK:

```ts
import { Ed25519Verifier, VerifierSDK } from "@actenon/verifier-sdk";

const verifier = new VerifierSDK(new Ed25519Verifier([issuerPublicJwk]));
```

The endpoint's own declarations in `context` are enforced (protocol
`13-edge-binding.md`): the intent's capability must be one of
`scope_capabilities`, every `parameter_constraints` member must have been
signed into the proof, the proof's target must satisfy one of
`resource_selectors`, and only single-use proofs verify.

Clock skew tolerance is strict by default. If a deployment needs to absorb small NTP drift, configure it explicitly:

```ts
const verifier = new VerifierSDK(new Ed25519Verifier([issuerPublicJwk]), {
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

## Verify Transparency Proofs

```ts
const checkpoint = verifyCheckpointSignature(treeHead, pinnedPublicKeys);
const inclusion = verifyInclusion(receiptDigest, inclusionProof, treeHead);
const consistency = verifyConsistency(oldTreeHead, treeHead, consistencyProof);
```

`verifyMonitorUpdate` combines checkpoint-signature and consistency checks for
an independent monitor. `verifyCountersignatureInclusion` rejects a
counter-signature whose exact digest is not included at its declared log leaf.

## Verify Issuer Status And Approval

```ts
const standing = verifyIssuerStatus(
  issuer,
  signedStatus,
  pinnedStatusAuthorityKeys,
  new Date(),
);
const approval = verifyApprovalArtifact(
  signedApproval,
  pinnedApproverKeys,
  expectedActionHash,
);
```

Issuer status fails closed by default for missing, stale, expired, revoked, or
unverifiable assertions. Setting `statusPolicy: "disabled"` is an explicit,
warning-emitting opt-out. Approval verification is public-key-only and can
require the signed approval to match the expected exact-action hash.

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
- transparency inclusion, consistency, key rotation, fork/rewind, and orphan rejection
- fail-closed issuer status and exact-action signed approval verification

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
- [`../../spec/transparency-log/SPEC.md`](../../spec/transparency-log/SPEC.md)
- [`../../schemas/transparency_checkpoint.v1.json`](../../schemas/transparency_checkpoint.v1.json)
- [`../../spec/issuer-status/SPEC.md`](../../spec/issuer-status/SPEC.md)
- [`../../schemas/issuer_status.v1.json`](../../schemas/issuer_status.v1.json)
- [`../../spec/approval-artifact/SPEC.md`](../../spec/approval-artifact/SPEC.md)
- [`../../schemas/approval_artifact.v1.json`](../../schemas/approval_artifact.v1.json)
