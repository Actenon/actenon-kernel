# Go Verifier SDK

Minimal protected-endpoint verifier SDK for Go, aligned to the Python kernel's public `action_intent` and `pccb` contracts.

This package is intentionally narrow. It focuses on verifier-side proof checking at the protected execution edge and offline verification of Receipt counter-signatures. It does not issue counter-signatures or contain private-key custody or service code.

Choosing between Python, TypeScript, and Go paths? Start with [`../../SDK_SELECTION_GUIDE.md`](../../SDK_SELECTION_GUIDE.md).

## Current Scope

- `action_intent` v1 and `pccb` v1 Go data structures
- protected-endpoint proof verification
- exact audience, tenant, subject, action, target, action-hash, not-before, and expiry checks
- optional verifier-side clock skew tolerance, defaulting to zero
- deterministic local-proof verification using the OSS local `HS256` verifier
- custom signature verification via the exported `SignatureVerifier` interface
- offline Receipt counter-signature verification by historical or active `kid`
- stdlib HTTP protected-endpoint example

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
cd sdk/go
go test ./...
```

To consume it locally from another Go module, use a `replace` directive:

```go
require github.com/actenon/sdk-go v0.0.0

replace github.com/actenon/sdk-go => /absolute/path/to/repo/sdk/go
```

Then import:

```go
import "github.com/actenon/sdk-go/verifier"
```

## Verify A Proof

```go
localVerifier := verifier.BuildLocalProofVerifier()
sdk := verifier.NewVerifier(localVerifier)

verified, err := sdk.VerifyJSON(intentPayload, pccbPayload, verifier.VerificationContext{
	RequestID:         "req_go_001",
	Audience:          verifier.AudienceRef{Type: "service", ID: "portable-hello-world-endpoint"},
	Now:               time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	ScopeCapabilities: []string{"protected_resource.read"},
	ParameterConstraints: map[string]any{
		"exact_message": "portable hello world",
	},
	ResourceSelectors: []map[string]any{
		{"resource_id": "hello_resource_demo_001"},
	},
})
```

Clock skew tolerance is strict by default. If a deployment needs to absorb small NTP drift, configure it explicitly:

```go
sdk := verifier.NewVerifier(
	localVerifier,
	verifier.WithClockSkewTolerance(10*time.Second),
)
```

If verification fails, the SDK returns `*VerificationError` with stable codes such as:

- `AUDIENCE_MISMATCH`
- `ACTION_MISMATCH`
- `PROOF_EXPIRED`
- `SIGNATURE_INVALID`

## Verify A Receipt Counter-Signature

```go
verified, err := verifier.VerifyCountersignature(
	receiptOrDigest,
	countersignature,
	pinnedPublicKeys,
)
```

`pinnedPublicKeys` is a trusted `key_discovery v1` document parsed with
`ParseTrustedCounterSignatureKeysJSON`. Verification is offline, selects the
exact public key by `kid`, and supports retained historical keys. It performs
no key fetch and contains no signing path.

## Example

Run the stdlib HTTP protected-endpoint example:

```bash
cd sdk/go
go run ./examples/http-protected-endpoint
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
cd sdk/go
go test ./...
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
