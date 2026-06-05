# Integration Quickstart

For a broader stack-by-stack index, start with [../../INTEGRATIONS.md](../../INTEGRATIONS.md).

If you want the fastest "protect a dangerous endpoint today" path, start with [../../examples/refund_guard_local/README.md](../../examples/refund_guard_local/README.md) and then come back here.

## What A Protected Endpoint Is

A Protected Endpoint is the last component before a consequential side effect.

It sits at the execution edge and refuses to act unless it can verify:

- the Action Intent
- the PCCB
- the endpoint's local audience and capability context
- the execution path's replay and single-use checks when required

Minimal shape:

```text
agent or app -> Action Intent + PCCB -> Protected Endpoint -> side effect -> Receipt or Refusal
```

## Start With The Smallest Useful Pattern

If you only need to protect an endpoint, start with the verifier side first.

A protected endpoint should:

1. receive an Action Intent and PCCB
2. build verification context for the endpoint audience and capability
3. verify the PCCB against the exact Action Intent
4. execute only after verification succeeds

The normative behavior for that edge lives in [`../../spec/protected-endpoint/SPEC.md`](../../spec/protected-endpoint/SPEC.md).

## Fastest Dangerous-Endpoint Path

If you need something more real than a hello-world route, use the local refund endpoint first.

Why:

- it is consequential enough to feel operational
- it mutates local state visibly
- it makes replay and exact-parameter binding obvious
- it stays entirely local and inspectable

Start here:

- [../../examples/refund_guard_local/README.md](../../examples/refund_guard_local/README.md)
- [../../docs/guides/LOCAL_PROOF_RUNBOOK.md](../../docs/guides/LOCAL_PROOF_RUNBOOK.md)

That refund path now includes a tiny stdlib Python server plus a one-command caller, so you can issue proof locally and hit a real protected endpoint without pulling in FastAPI, Express, or a future control plane first.

## Adoption Ladder

The kernel now supports a practical ladder instead of an all-or-nothing migration:

1. edge-only admission
2. local issuing
3. proof-carrying flow
4. cross-boundary trust later

What those mean:

- edge-only admission: a raw framework request reaches the protected endpoint, and Actenon normalizes it into a local `Action Intent`, runs local admission policy, and emits Receipt or Refusal artifacts at the edge
- local issuing: your service calls a local issuer path such as `POST /v1/intents` first and gets a PCCB plus escrow when allowed
- proof-carrying flow: the caller now sends the `Action Intent` and PCCB directly to the protected endpoint, which verifies before side effects
- cross-boundary trust later: asymmetric keys, well-known discovery, and verifier-only SDK paths matter once proof has to cross service or organizational boundaries

That distinction is important:

- proof-present verification is the stronger portable trust mode
- proof-absent local admission is an adoption on-ramp for existing callers, not a weakening of proof-bound semantics

## Mandatory Checks

At minimum, the Protected Endpoint must verify:

- signature integrity and trust
- `not_before` and `expires_at`
- exact audience match
- exact action match
- exact target match
- tenant and subject match
- scope capability match
- action-hash match
- replay or single-use checks for the execution path

If a side effect can happen without those checks, the model is broken even if upstream policy or approval existed.

Clock skew tolerance is optional and verifier-side. The default is zero. If a distributed deployment needs tolerance for small NTP drift, configure it explicitly and keep it short; do not use tolerance to compensate for long queues, retries, or stale proof.

## Common Integration Mistakes

These mistakes break the Protected Endpoint model:

- verifying proof after the side effect instead of before it
- trusting upstream approval or workflow state as a substitute for endpoint verification
- sharing one audience identity across unrelated endpoints
- passing hidden side-effect parameters outside the verified Action Intent
- skipping replay protection on a path that claims single-use execution
- verifying one request shape and executing another transformed shape

## Fastest Verifier Example

```bash
python3 -m actenon.demo.portable_local_proof --artifacts-dir artifacts/portable_local_proof
```

Reference files:

- `actenon/verifier/sdk.py`
- `examples/hello_world_protected_resource_python/protected_resource.py`
- `docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md`

## Choose An Adoption Path

| If you need... | Start here |
| --- | --- |
| the smallest verifier-first path | `actenon.demo.portable_local_proof` and [docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md](../reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md) |
| the strongest tool-integration path | [../../MCP_HERO_PATH.md](../../MCP_HERO_PATH.md) and [../../examples/mcp_server_protected_tool/README.md](../../examples/mcp_server_protected_tool/README.md) |
| a Python HTTP route | [../../examples/fastapi_protected_route/README.md](../../examples/fastapi_protected_route/README.md) |
| a Node or TypeScript HTTP route | [../../examples/express_protected_route/README.md](../../examples/express_protected_route/README.md) |
| an OpenAI Agents SDK tool | [../../examples/openai_agents_sdk_protected_tool/README.md](../../examples/openai_agents_sdk_protected_tool/README.md) |
| an MCP tool | [../../examples/mcp_server_protected_tool/README.md](../../examples/mcp_server_protected_tool/README.md) |
| a Go verifier-edge service | [../../sdk/go/README.md](../../sdk/go/README.md) |
| the language-specific verifier SDK overview | [../../SDK_SELECTION_GUIDE.md](../../SDK_SELECTION_GUIDE.md) and [../reference/verifier/VERIFIER_SDK_REFERENCE.md](../reference/verifier/VERIFIER_SDK_REFERENCE.md) |

## Minimal VerifierSDK Example

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
    request_id="req_example_001",
    audience=AudienceRef(type="service", id="protected-endpoint"),
    now=datetime.now(timezone.utc),
    scope_capabilities=("protected_resource.read",),
)
```

`build_local_proof_signer()` is the deterministic local demo trust root. It uses local `HS256` HMAC material that is public in this repository, so it is forgeable and must not be used for production signing or verification. A production protected endpoint only needs a `SignatureVerifier`-compatible verifier backed by the deployment's asymmetric trust root, not proof-minting capability.

For deployments with small expected clock drift, initialize the SDK with an explicit tolerance:

```python
from datetime import timedelta

sdk = VerifierSDK(signature_verifier, clock_skew_tolerance=timedelta(seconds=10))
```

Keep proof validity windows short: roughly 30 to 120 seconds for high-risk or irreversible actions, 2 to 5 minutes for ordinary consequential actions, and bounded read or diagnostic windows only where risk is low.

## If You Want The Full Kernel Pattern

Use the kernel admission, proof, replay, and middleware flow in this repository:

- `actenon/core/kernel.py`
- `actenon/verifier/middleware.py`
- `examples/refund_guard_local/protected_endpoint.py`
- `examples/invoice_payment_guard_local/protected_endpoint.py`

## Adoption Rule Of Thumb

- use the portable verifier path if you only need proof verification at the endpoint
- use the full kernel path if you also need admission, refusal generation, receipt generation, and local wedge references
- use the language SDKs when you need verifier-edge protection inside an existing service without porting the full kernel

## Boundary

This repo gives you:

- kernel logic
- verifier logic
- local proof examples
- public contracts and behavior specs

It does not give you:

- hosted approval services
- hosted evidence services
- provider-backed execution
- full control-plane APIs
