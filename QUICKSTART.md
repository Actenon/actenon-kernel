# Quickstart

## Goal

Get from clone to a complete local trust runtime, a memorable execution-gap simulation, and a first proof-bound protected-endpoint success in a few minutes, with no external accounts, provider sandboxes, or API keys.

If you want the category problem first, read [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md) before this guide. Quickstart is the shortest path to seeing the answer, not the full argument for why the answer is needed.

## Requirements

- `python3`
- `make`

## Install For Local Verification

The core kernel stays dependency-light. Install the asymmetric extra when you
want to verify Cloud-issued Ed25519 proof and outcome-attestation artifacts:

```bash
pip install -e ".[asymmetric]"
```

## Fastest Path

This is the shortest product-shaped path through the kernel:

```bash
make install
actenon up
```

In another terminal:

```bash
actenon doctor
actenon simulate --incident replit
```

Then protect a real endpoint:

```bash
python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime
```

For a real deployment, this pattern is strongest when the protected endpoint is
the only path to the side effect. If an agent still has a standing production
credential that can call the provider directly, that side door bypasses the
protected boundary. The desired shape is: agent requests action, protected
endpoint verifies proof, endpoint uses or brokers the privileged credential, and
the agent never handles the raw production credential.

Then follow [examples/refund_guard_local/README.md](examples/refund_guard_local/README.md) to:

1. start with proof-absent local admission at `/refunds/local-admission` if your caller cannot mint Actenon proof yet
2. move to `POST /v1/intents` when you want explicit local issuing
3. call the protected refund endpoint with the issued PCCB
4. inspect the resulting Intent Record, Receipt, or Refusal under `artifacts/local_runtime/artifacts/`

Then prove the runtime is portable:

```bash
actenon bundle export --runtime-dir artifacts/local_runtime
actenon bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon
```

The old compact proof-demo path is still available if you specifically want the original seeded lab flow:

```bash
make install
bash ./scripts/first_run.sh
make public-verify
```

## Verify The Cloud-To-Kernel Vector

The accepted v2 keystone vector shows Actenon Cloud issuing invoice-payment
proof and outcome artifacts that the open Kernel verifies independently.

Inspect the vector:

```bash
ls conformance/vectors/cloud_invoice_payment_v1
ls conformance/vectors/cloud_invoice_payment_v1/mutations
```

Run the kernel verification test:

```bash
python -m pytest tests/integration/test_cloud_invoice_payment_conformance_vector.py -q
```

That test verifies the Cloud-issued PCCB through the real well-known key
resolver and verifies copied Receipt/Refusal attestation envelopes for origin
and integrity. It also proves mutation failures for amount, audience, expiry,
action hash, signature, key id, key purpose, outcome artifact, artifact digest,
proof binding, issuer, and issued-at tampering.

If you have the Cloud repo checked out too, run the portable cross-repo script
from the Cloud repo:

```bash
ACTENON_KERNEL_REPO="/path/to/actenon-verifier-kernel" \
ACTENON_CLOUD_REPO="/path/to/actenon-cloud" \
bash "$ACTENON_CLOUD_REPO/scripts/verify_cloud_to_kernel.sh"
```

Read the details in
[docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md](docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md)
and [ACTENON_V2_KEYSTONE_ACCEPTANCE.md](ACTENON_V2_KEYSTONE_ACCEPTANCE.md).

## Why This Path Works

- `actenon up` bootstraps and starts a complete local single-node trust runtime under `artifacts/local_runtime/`
- the runtime exposes `POST /v1/intents`, `GET /healthz`, and local key-discovery routes on `http://127.0.0.1:8787/`
- when available, the local read-only trace viewer starts on `http://127.0.0.1:8421`
- startup output tells you exactly where local artifacts, replay state, escrow state, and the publishable key-discovery file live
- `actenon doctor` is fast by default and checks signer usability, replay and escrow access, writable artifact paths, runtime-server reachability, key-discovery response, and trace-viewer readiness
- `actenon doctor --deep` adds slower lab, portable verifier, evidence-query, and scanner checks
- `actenon simulate --incident replit` is the fastest memorable path: it names the execution gap directly and shows weak control, proof-bound control, the remaining proof-only gap, and how bounded intent changes the outcome
- `actenon simulate --incident all` runs the named `replit`, `openai-eggs`, and `amazon-kiro` simulations
- `actenon simulate --scenario all` still runs the lower-level technical cases for audience mismatch, action-hash mismatch, expiry, and replay refusal
- the refund endpoint example proves this is not just simulator theater: you can protect a consequential endpoint immediately
- `actenon bundle export` emits a `.actenon` portable execution evidence bundle
- `actenon bundle verify` checks that bundle hashes and chain metadata still match the contained artifacts
- `make install` installs the repo in editable mode
- `bash ./scripts/first_run.sh` gives you the fastest end-to-end protected-endpoint proof run
- `make public-verify` runs the same gate as `bash scripts/verify_release_gate.sh`: keystone tests, full kernel tests, Ruff, public boundary validation, and public archive validation

That first run is doing more than a demo happy path. It shows the missing boundary in concrete terms:

- auth, policy, or approval alone are not enough once execution is separate
- the missing category is the execution gap
- proof-bound execution is the mechanism that closes it
- the protected endpoint verifies proof before side effects
- mutated, replayed, or otherwise invalid requests are blocked and surfaced as canonical Refusals
- the protected endpoint should be the credential-broker boundary, not a
  voluntary wrapper next to standing agent credentials

## The Five-Step Story

If you are evaluating whether the kernel feels complete now, this is the shortest honest sequence:

1. `actenon up`: start the local issuer, verifier-adjacent runtime surfaces, persistence, and viewer
2. `actenon doctor`: confirm the local trust machine is healthy
3. `actenon simulate --incident replit`: make the execution gap unforgettable
4. `python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime`: protect a real consequential endpoint
5. `actenon bundle export --runtime-dir artifacts/local_runtime`: export the runtime without relying on any paid service
6. `actenon bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon`: verify the portable artifact class you just created

## Recommended Sequence After The First Run

Use this order if you want the cleanest adoption path after the first five commands:

1. inspect the first incident pack under `artifacts/local_runtime/simulations/replit/`
2. inspect the first local runtime Intent Record, Receipt, and Refusal under `artifacts/local_runtime/artifacts/`
3. open the read-only [TRACE_VIEWER.md](TRACE_VIEWER.md) at `http://127.0.0.1:8421` to inspect Action Intent, Intent Record, PCCB, Receipt, Refusal, replay entries, and protected-endpoint state
4. read [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md) for the exact first-run flow
5. move to [MCP_HERO_PATH.md](MCP_HERO_PATH.md) for the strongest agent-tool integration path
6. run `actenon conformance run`

## What Success Looks Like

During `bash ./scripts/first_run.sh`, you should see outcomes such as:

- `refund.allow: executed`
- `refund.deny: deny`
- `refund.approval_required: approval-required`
- `invoice_payment.allow: executed`
- `invoice_payment.batch_hash_mismatch: deny`

After the run, start here:

- `artifacts/local_proof/SUMMARY.txt`
- `artifacts/local_proof/manifest.json`
- `artifacts/local_proof/outcomes/receipts/`
- `artifacts/local_proof/outcomes/refusals/`

## What That First Run Demonstrates

The first run exercises the open kernel's core model:

- an Action Intent is evaluated before execution
- a PCCB is verified at a Protected Endpoint before side effects
- replay and refusal behavior are exercised, not just happy-path execution
- canonical Receipt and Refusal artifacts are emitted

This is the shortest local proof of why Actenon exists: the execution edge checks the exact action it is about to perform instead of trusting upstream "allow" state.

Protected-endpoint reference files:

- `examples/refund_guard_local/protected_endpoint.py`
- `examples/invoice_payment_guard_local/protected_endpoint.py`
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)

## Verify The Emitted Artifacts With The CLI

`actenon verify-proof` requires explicit local audience context. It does not treat the PCCB's own audience as sufficient verifier input.

Verifier time checks are strict by default: the PCCB must be within its `not_before` / `expires_at` window at the supplied verification time. In production integrations, use short proof windows and only configure clock skew tolerance in code for small, expected distributed-clock drift.

Verify a proof artifact from the local refund proof run:

```bash
actenon verify-proof \
  --intent artifacts/local_proof/scenarios/allow/action_intent.json \
  --pccb artifacts/local_proof/scenarios/allow/pccb.json \
  --audience service:local-refund-endpoint \
  --verification-time pccb-issued-at
```

Ask for structured failure details instead of human-readable output:

```bash
actenon verify-proof \
  --intent artifacts/local_proof/scenarios/allow/action_intent.json \
  --pccb artifacts/local_proof/scenarios/allow/pccb.json \
  --audience service:wrong-endpoint \
  --verification-time pccb-issued-at \
  --json
```

Verify a receipt from the refund local proof run:

```bash
actenon verify-receipt \
  --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json \
  --intent artifacts/local_proof/scenarios/allow/action_intent.json \
  --pccb artifacts/local_proof/scenarios/allow/pccb.json
```

Verify a refusal from the refund local proof run:

```bash
actenon verify-refusal \
  --refusal artifacts/local_proof/scenarios/deny/refusal.json \
  --intent artifacts/local_proof/scenarios/deny/action_intent.json \
  --receipt artifacts/local_proof/scenarios/deny/decision_receipt.json
```

Query the local evidence chain for the executed allow path:

Point `--artifacts-dir` at the local proof artifact root, such as `artifacts/local_proof`, or directly at an `outcomes/` directory.

```bash
actenon evidence query \
  --intent-id intent_allow \
  --artifacts-dir artifacts/local_proof
```

Ask for machine-readable evidence verdict output:

```bash
actenon evidence query \
  --pccb-id pccb_0001 \
  --artifacts-dir artifacts/local_proof \
  --json
```

Run the single-node runtime doctor:

```bash
actenon doctor \
  --runtime-dir artifacts/local_runtime
```

Run the built-in local incident simulations:

```bash
actenon simulate \
  --runtime-dir artifacts/local_runtime \
  --scenario all
```

Each scenario writes an `INCIDENT_SUMMARY.md` file under `artifacts/local_runtime/simulations/<scenario>/` so you can inspect the exact lesson afterward. The replay case is especially important because it shows something easy to miss: proof alone still verifies twice; replay refusal comes from stateful protected-endpoint enforcement.

If you want the fastest route from this runtime into a real consequential endpoint, go next to [examples/refund_guard_local/README.md](examples/refund_guard_local/README.md).

Export the local runtime as a portable bundle:

```bash
actenon bundle export \
  --runtime-dir artifacts/local_runtime
```

Verify the exported `.actenon` bundle:

```bash
actenon bundle verify \
  artifacts/local_runtime/bundles/actenon-local-runtime.actenon
```

That bundle is meant to feel like a real artifact class:

- it is portable execution evidence
- it carries manifest-linked file hashes plus canonical artifact digests
- it is tamper-evident relative to the bundle manifest
- it is not a cryptographic attestation of origin in active v1

Local runtime state lives on disk:

- labs root: `artifacts/local_runtime/labs/`
- refund proof lab: `artifacts/local_runtime/labs/local_proof/`
- invoice payment issuer lab: `artifacts/local_runtime/labs/invoice_payment_local_proof/`
- portable verifier lab: `artifacts/local_runtime/labs/portable_local_proof/`
- live runtime artifacts: `artifacts/local_runtime/artifacts/`
- live runtime replay: `artifacts/local_runtime/state/replay.sqlite3`
- live runtime escrow: `artifacts/local_runtime/state/escrow.sqlite3`
- live runtime receipts: `artifacts/local_runtime/artifacts/outcomes/receipts/`
- live runtime refusals: `artifacts/local_runtime/artifacts/outcomes/refusals/`
- local simulations: `artifacts/local_runtime/simulations/`
- local bundles: `artifacts/local_runtime/bundles/`
- local keys: `artifacts/local_runtime/keys/`
- runtime service manifest: `artifacts/local_runtime/service_manifest.json`

If you only want the files and labs without starting the HTTP services, use `actenon up --bootstrap-only`.

That bootstrap-only path is intentionally not a fully serving local trust runtime. `actenon doctor` will report `needs_attention` until the foreground runtime process is actually running.

In default local `HS256` mode, the startup banner also tells you where the runtime would serve a publishable key-discovery document, while staying explicit that the local symmetric trust key is not public verifier material.

Reset options:

- full reset: remove `artifacts/local_runtime/` and run `actenon up` again
- live execution reset while keeping seeded labs: remove `artifacts/local_runtime/artifacts/`, `artifacts/local_runtime/state/`, and `artifacts/local_runtime/service_manifest.json`
- simulation cleanup only: remove `artifacts/local_runtime/simulations/`
- bundle cleanup only: remove `artifacts/local_runtime/bundles/`

Create a local execution anchor from the executed refund receipt:

```bash
actenon graph anchor \
  --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json \
  --dry-run
```

Run conformance:

```bash
actenon conformance run
```

Open the read-only local trace viewer:

```bash
python3 -m actenon.ui.trace_viewer.app
```

Then open `http://127.0.0.1:8421`.

## Choose Your Next Path

| If you want to... | Start here |
| --- | --- |
| understand the category and boundary first | [CATEGORY.md](CATEGORY.md), [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md), [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md) |
| inspect the first run visually before integrating anything | [TRACE_VIEWER.md](TRACE_VIEWER.md), [docs/guides/TRACE_VIEWER_LOCAL.md](docs/guides/TRACE_VIEWER_LOCAL.md) |
| adopt the protected-endpoint pattern in an existing service | [docs/guides/INTEGRATION_QUICKSTART.md](docs/guides/INTEGRATION_QUICKSTART.md) |
| adopt the strongest agent-tool path in this repo | [MCP_HERO_PATH.md](MCP_HERO_PATH.md), [examples/mcp_server_protected_tool/README.md](examples/mcp_server_protected_tool/README.md) |
| start with the smallest verifier-first demo | [docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md](docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md) |
| evaluate compatibility claims and run the suite | [CONFORMANCE.md](CONFORMANCE.md), [docs/guides/CONFORMANCE_TESTS_GUIDE.md](docs/guides/CONFORMANCE_TESTS_GUIDE.md) |
| choose a verifier-edge SDK | [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md), [docs/reference/verifier/VERIFIER_SDK_REFERENCE.md](docs/reference/verifier/VERIFIER_SDK_REFERENCE.md) |
| jump into framework and agent examples | [INTEGRATIONS.md](INTEGRATIONS.md) |

## Read First If You Are Evaluating The Project

- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [CATEGORY.md](CATEGORY.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [SPEC_INDEX.md](SPEC_INDEX.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)
- [CONFORMANCE.md](CONFORMANCE.md)

## If You Want The Kernel Gate First

```bash
make verify
make judge
```

## Read Next

- [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
- [TRACE_VIEWER.md](TRACE_VIEWER.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md)
- [docs/guides/INTEGRATION_QUICKSTART.md](docs/guides/INTEGRATION_QUICKSTART.md)
- [docs/guides/CONFORMANCE_TESTS_GUIDE.md](docs/guides/CONFORMANCE_TESTS_GUIDE.md)
- [INTEGRATIONS.md](INTEGRATIONS.md)
