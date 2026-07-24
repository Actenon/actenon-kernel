# Verifier SDK Reference

## Purpose

The verifier SDK is the portable developer entry point for protected endpoint verification.

It is implemented in:

- `actenon/verifier/sdk.py`

## Choose A Verifier Path

| Path | Use it when you want... | Scope |
| --- | --- | --- |
| [Python verifier and kernel path](../../../docs/guides/INTEGRATION_QUICKSTART.md) | the full OSS reference path, local proof mode, CLI verification, and protected-endpoint examples | kernel plus verifier-first adoption |
| [TypeScript verifier SDK](../../../sdk/typescript/README.md) | verifier-edge proof checking in Node or TypeScript services | verifier-only |
| [Go verifier SDK](../../../sdk/go/README.md) | verifier-edge proof checking in Go services | verifier-only |
| [Rust verifier SDK](../../../sdk/rust/README.md) | verifier-edge proof checking in Rust services or systems components | verifier-only |

For a fast language chooser, use [../../../SDK_SELECTION_GUIDE.md](../../../SDK_SELECTION_GUIDE.md).

If you only need the smallest protected-endpoint walkthrough, start with [HELLO_WORLD_PROTECTED_RESOURCE.md](HELLO_WORLD_PROTECTED_RESOURCE.md).

If you want to verify a specific Action Intent and PCCB pair from the terminal without writing code, use:

```bash
actenon-kernel verify-proof --intent /path/to/action_intent.json --pccb /path/to/pccb.json --audience service:protected-endpoint
```

## Public API

Primary type:

- `VerifierSDK`
- `VerifierSDK(signature_verifier, clock_skew_tolerance=timedelta(0))`

Primary result model:

- `VerifiedPortableRequest`

Main methods:

- `parse_intent(payload)`
- `parse_pccb(payload)`
- `build_context(...)`
- `verify(intent=..., pccb=..., context=...)`
- `verify_payloads(...)`

Receipt counter-signature verification:

- `verify_countersignature(receipt_or_digest, countersignature, trusted_keys)`

Transparency-log verification:

- `verify_checkpoint_signature(checkpoint, trusted_keys)`
- `verify_inclusion(digest, inclusion_proof, checkpoint)`
- `verify_consistency(old_checkpoint, new_checkpoint, consistency_proof)`
- `verify_countersignature_inclusion(countersignature, inclusion_proof, checkpoint, trusted_keys)`
- `verify_monitor_update(previous_checkpoint, current_checkpoint, consistency_proof, trusted_keys)`

Trust-artifact verification:

- `verify_issuer_status(issuer, status_artifact, trusted_keys, now)`
- `verify_approval_artifact(approval, trusted_keys, expected_action=...)`

The counter-signature API is offline and verify-only. `trusted_keys` is an
already trusted, pinned `key_discovery v1` document containing current and
historical public keys. The verifier selects the exact public key by `kid`; it
does not fetch keys, sign artifacts, or handle private key custody.

The transparency APIs are also offline and verify-only. They validate signed
checkpoints, Merkle inclusion, append-only consistency, and monitor updates.
`verify_countersignature_inclusion` checks the log anchor after the caller has
verified the counter-signature itself with `verify_countersignature`.

The trust-artifact APIs are offline and public-key-only. Issuer status fails
closed by default when the assertion is missing, stale, expired, revoked, or
unverifiable. The optional disabled policy is an explicit, logged opt-out.
Approval verification selects an approver key by `kid`; when
`expected_action` is supplied, it also enforces exact-action binding.

## What The Verifier Needs From A Protected Endpoint

The verifier does not run by itself. A Protected Endpoint still has to supply:

- the Action Intent payload
- the PCCB payload
- the endpoint's local audience identity
- the endpoint's permitted capability set
- the current verification time
- any parameter or resource constraints the endpoint treats as security-relevant

The `actenon-kernel verify-proof` CLI is a thin wrapper over this same verifier path. It asks you for the artifact paths plus the explicit local audience identity needed to evaluate the proof in verifier context. It does not silently inherit that verifier identity from the PCCB.

## Production Verification Model

Protected endpoints verify proof. They do not need to mint proof.

The repository now exposes explicit verifier-side contracts in:

- `actenon.proof.SignatureVerifier`
- `actenon.verifier.VerifierSDK`
- `sdk/typescript/src/signers.ts`
- `sdk/go/verifier/signers.go`
- `sdk/rust/src/signers.rs`

Local demos use `build_local_proof_signer()` because the repo ships a deterministic local trust root for testing and examples. That local `HS256` HMAC path is dev/demo-only: the default secret is public repository material, so anyone can forge local-mode proofs. The signer emits a runtime warning in development and refuses creation whenever an Actenon production flag is set. Production flags have no local-HMAC override.

Production deployments can instead supply any verifier-compatible implementation that can validate PCCB signatures against the deployment's configured trust root. The OSS kernel does not ship a hosted signer service or remote verification service.

For deployments that know an issuer origin and want to avoid bilateral key distribution, the Python path also exposes:

- `actenon.proof.WellKnownKeyResolver`
- `actenon.proof.WellKnownKeySignatureVerifier`

That path resolves verification keys from the issuer's `/.well-known/actenon/keys.json` document, enforces `key_id` / status / time checks, and caches the discovery result locally. The default resolver uses HTTPS only, requires the canonical well-known path on the configured issuer origin, does not follow redirects, and rejects localhost/private/link-local/metadata IP destinations where visible to the fetcher. In the zero-dependency runtime it handles trust resolution and fail-closed key selection; actual asymmetric signature verification requires the optional `cryptography` package and is not a hard dependency of the OSS kernel.

Install that optional verifier path with:

```bash
pip install -e ".[asymmetric]"
```

## Minimal Use

```python
from datetime import datetime, timezone

from actenon.models import AudienceRef
from actenon.proof import build_local_proof_signer
from actenon.verifier import VerifierSDK

signature_verifier = build_local_proof_signer()
sdk = VerifierSDK(signature_verifier)
verified = sdk.verify_payloads(
    intent_payload=intent_payload,
    pccb_payload=pccb_payload,
    request_id="req_demo_001",
    audience=AudienceRef(type="service", id="protected-endpoint"),
    now=datetime.now(timezone.utc),
    scope_capabilities=("protected_resource.read",),
)
```

Verify a Receipt counter-signature:

```python
from actenon.verifier import verify_countersignature

verified_witness = verify_countersignature(
    receipt,
    countersignature,
    pinned_public_keys,
)
```

The same conformance vectors are exercised by the TypeScript, Go, and Rust
verifier SDKs. See
[`../../../spec/countersignature/SPEC.md`](../../../spec/countersignature/SPEC.md)
for the signed statement and key-rotation rules.

Verify a transparency checkpoint and proof:

```python
from actenon.verifier import (
    verify_checkpoint_signature,
    verify_consistency,
    verify_inclusion,
    verify_monitor_update,
)

verified_checkpoint = verify_checkpoint_signature(
    checkpoint,
    pinned_public_keys,
)
verified_inclusion = verify_inclusion(
    receipt_digest,
    inclusion_proof,
    checkpoint,
)
verified_history = verify_consistency(
    previous_checkpoint,
    checkpoint,
    consistency_proof,
)
verified_update = verify_monitor_update(
    previous_checkpoint,
    checkpoint,
    consistency_proof,
    pinned_public_keys,
)
```

See
[`../../../spec/transparency-log/SPEC.md`](../../../spec/transparency-log/SPEC.md)
for the hash domains, proof ordering, checkpoint signature input, and monitor
state requirements.

Verify issuer status and an exact-action approval:

```python
from actenon.verifier import verify_approval_artifact, verify_issuer_status

standing = verify_issuer_status(
    issuer,
    signed_status,
    pinned_status_authority_keys,
    now,
)
approval = verify_approval_artifact(
    signed_approval,
    pinned_approver_keys,
    expected_action=action_intent,
)
```

See [`../../../spec/issuer-status/SPEC.md`](../../../spec/issuer-status/SPEC.md)
and
[`../../../spec/approval-artifact/SPEC.md`](../../../spec/approval-artifact/SPEC.md).

## Standalone CLI Verification

Human-readable success output:

```bash
actenon-kernel verify-proof \
  --intent artifacts/portable_local_proof/action_intent.json \
  --pccb artifacts/portable_local_proof/pccb.json \
  --audience service:portable-hello-world-endpoint \
  --verification-time pccb-issued-at
```

Structured JSON failure output:

```bash
actenon-kernel verify-proof \
  --intent artifacts/portable_local_proof/action_intent.json \
  --pccb artifacts/portable_local_proof/pccb.json \
  --audience service:wrong-endpoint \
  --verification-time pccb-issued-at \
  --json
```

Required verifier-side input:

- `--intent`
- `--pccb`
- `--audience`

Optional verifier-side input:

- `--audience-type`
- `--verification-time`
- `--request-id`
- `--json`
- `--signer`

## What Verification Enforces

The SDK enforces:

- proof expiry
- proof not-before time
- audience match
- exact action match
- exact target match
- tenant and subject match
- canonical action hash match
- signature verification

Those checks are the minimum verifier-edge contract. They do not replace replay enforcement, policy evaluation, or hosted control-plane behavior.

## Clock Skew Tolerance

By default, the verifier SDKs use strict time checks:

- `context.now` must be greater than or equal to `pccb.not_before`
- `context.now` must be less than or equal to `pccb.expires_at`

Distributed deployments can opt into a small verifier-side tolerance.

Python:

```python
from datetime import timedelta

sdk = VerifierSDK(signature_verifier, clock_skew_tolerance=timedelta(seconds=10))
```

TypeScript:

```ts
const verifier = new VerifierSDK(buildLocalProofVerifier(), {
  clockSkewToleranceMs: 10_000,
});
```

Go:

```go
sdk := verifier.NewVerifier(
	localVerifier,
	verifier.WithClockSkewTolerance(10*time.Second),
)
```

Rust:

```rust
let verifier = Verifier::new(build_local_proof_verifier())
    .with_clock_skew_tolerance(Duration::seconds(10))?;
```

The default is zero. Configured tolerance is symmetric: it allows a verifier
clock to be slightly behind `not_before` or slightly ahead of `expires_at`.
That expands temporal acceptance by no more than the configured tolerance, so
it should cover expected NTP drift only, not queueing delay or operational
retry windows. Replay/single-use enforcement remains mandatory and prevents
the tolerance from creating additional proof uses.

Python, TypeScript, Go, and Rust run the same vectors from
`actenon/conformance/vectors/verifier_sdk_v1`. The vectors assert exact binding
semantics, boundary-time behavior, reason codes, and public-safe messages.

Suggested proof validity windows:

- high-risk or irreversible actions: 30 to 120 seconds
- ordinary consequential actions: 2 to 5 minutes
- low-risk read, diagnostic, or demo actions: bounded and preferably under 10 minutes

## What The SDK Does Not Do

The portable verifier SDK does not provide:

- policy evaluation
- approval routing
- evidence collection
- hosted replay state
- hosted receipt pipelines
- counter-signature issuance, signing, or private-key custody
- a running transparency log, checkpoint signing, fetching, gossip, or durable monitor state

## Related Docs

- [../../../spec/protected-endpoint/SPEC.md](../../../spec/protected-endpoint/SPEC.md)
- [../../../docs/guides/INTEGRATION_QUICKSTART.md](../../../docs/guides/INTEGRATION_QUICKSTART.md)
- [../../../SDK_SELECTION_GUIDE.md](../../../SDK_SELECTION_GUIDE.md)
- [../../../docs/reference/ecosystem/SIGNER_KMS_SPEC.md](../../../docs/reference/ecosystem/SIGNER_KMS_SPEC.md)
- [../../../spec/key-discovery/SPEC.md](../../../spec/key-discovery/SPEC.md)
- [../../../spec/countersignature/SPEC.md](../../../spec/countersignature/SPEC.md)
- [../../../spec/transparency-log/SPEC.md](../../../spec/transparency-log/SPEC.md)
- [HELLO_WORLD_PROTECTED_RESOURCE.md](HELLO_WORLD_PROTECTED_RESOURCE.md)
