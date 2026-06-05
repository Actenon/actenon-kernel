# Actenon

No valid proof, no execution. Every consequential AI action leaves a verifiable receipt.

![Actenon demo: unproven agent action refused before side effect](docs/assets/actenon-hero-devops.gif)


Actenon is the open proof gate and receipt standard for consequential AI actions. It sits at the execution boundary, refuses unproven actions before side effects happen, and emits verifiable Receipt/Refusal artifacts for audit, compliance, and trust.

Your AI agent can try to delete your production database. When that action is routed through a protected endpoint, Actenon makes sure it cannot execute without valid proof and a verifiable Receipt or Refusal.

[Release gate: local command](scripts/verify_release_gate.sh) · [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) · [![Python: 3.9-3.12](https://img.shields.io/badge/python-3.9--3.12-blue)](pyproject.toml) · [Conformance tests](CONFORMANCE.md) · [Adversarial tests](docs/security/SECURITY_TESTING.md)

## 60-Second Quickstart

```bash
python3 -m pip install -e ".[asymmetric]"
bash scripts/demo_hero.sh
```

This is a safe local simulation. It does not contact a cloud account, use
external secrets, or perform a real destructive action.

Expected output excerpt:

```text
Actenon hero demo
No valid proof, no execution. Every consequential AI action leaves a verifiable receipt.

Phase 1/3: Without execution-edge proof binding
Outcome: WOULD_EXECUTE

Phase 2/3: With Actenon, but no matching proof
Outcome: REFUSED
Reason code: ACTION_HASH_MISMATCH
Side effect executed: false

Phase 3/3: With valid proof
Outcome: EXECUTED
Receipt artifact: artifacts/hero_demo_runtime/simulations/replay-refused/execution_receipt.json
```

Full transcript: [docs/assets/ACTENON_HERO_DEMO_TRANSCRIPT.md](docs/assets/ACTENON_HERO_DEMO_TRANSCRIPT.md)

## Artifact Snippet

The demo writes real local artifacts under `artifacts/hero_demo_runtime/`. Here is the refused-action summary from the current deterministic run:

```json
{
  "outcome": "refused",
  "reason_code": "ACTION_HASH_MISMATCH",
  "side_effect_executed": false,
  "pccb_id": "pccb_incident_replit",
  "action_hash": "badc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffebadc0ffe",
  "artifact_digest": "sha256:9408f4573e097f38d38a483280ec70b3737df74d4119e09af4615b19840ff121"
}
```

And the allowed path emits a receipt:

```json
{
  "outcome": "executed",
  "side_effect_executed": true,
  "receipt_id": "rcpt_sim_replay_0002",
  "pccb_id": "pccb_sim_replay_001",
  "artifact_digest": "sha256:353c73da14c3a6884c5308cf7d3826d8faeda8413a80ada9a1e2aab879fbfc71"
}
```


## Consequential Action Gallery

Actenon is not limited to database deletes. The same proof-before-execution pattern applies anywhere an AI agent can cause a real side effect.

| Surface | Demo | What Actenon shows |
| --- | --- | --- |
| DevOps / Database | ![Actenon DevOps demo](docs/assets/actenon-hero-devops.gif) | Unproven destructive data action is refused before execution. |
| Fintech / Payments | ![Actenon Fintech demo](docs/assets/actenon-demo-fintech.gif) | Unapproved money movement is refused; approved payment executes once with a receipt. |

All demos are safe local simulations. They do not perform real database, payment, email, cloud, or browser actions.

## What Actenon Does / Does Not Do

Actenon does:

- refuse unproven consequential actions at a protected endpoint
- bind proof to exact action parameters
- consume replay or escrow where configured
- broker credentials after verification
- emit Receipt/Refusal artifacts
- support local verification, conformance tests, and copied Cloud-issued artifact verification without requiring a hosted service

Actenon does not:

- stop a model from trying to act
- make a bad-but-authorized action good
- protect paths not routed through a protected endpoint
- prove downstream business finality
- replace identity providers
- certify that a repo is vulnerable
- claim Actenon Network, Agent Trust Score, insurer endorsement, regulator recognition, or production KMS/HSM custody in this open kernel

## Docs Navigation

| Start here | Why |
| --- | --- |
| [Quickstart](QUICKSTART.md) | Run the local proof-gate demo path. |
| [First 10 Minutes](docs/guides/FIRST_10_MINUTES.md) | Walk through the first local runtime and inspection flow. |
| [Scanner Methodology](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md) | Understand the advisory scanner and consequence-class wording. |
| [Preflight](docs/guides/PREFLIGHT.md) | See the local policy/evidence decision surface. |
| [Credential Broker](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md) | Remove standing credentials from agent runtime paths. |
| [MCP Hero Path](MCP_HERO_PATH.md) | Wrap consequential MCP tools with a proof gate. |
| [External Anchors](docs/guides/EXTERNAL_ANCHORS.md) | Add local durability evidence outside signed payloads. |
| [Threat Model](THREAT_MODEL.md) | Review assets, attacker classes, mitigations, and limits. |
| [Open Source Boundary](OPEN_SOURCE_BOUNDARY.md) | Understand what is public kernel versus private/commercial scope. |
| [Governance](GOVERNANCE.md) | Read the open standard and stewardship posture. |
| [Open Source Boundary](OPEN_SOURCE_BOUNDARY.md) | Review Apache-2.0 licensing, public kernel scope, and commercial boundary. |
| [Conformance](CONFORMANCE.md) | Run and interpret the compatibility test surface. |

## Next Steps

- Read [QUICKSTART.md](QUICKSTART.md) for the complete local runtime path.
- Read [MCP_HERO_PATH.md](MCP_HERO_PATH.md) for the clearest agent-tool integration path.
- Read [docs/assets/DEMO_CAPTURE.md](docs/assets/DEMO_CAPTURE.md) to record the hero GIF.
- Read [docs/architecture/TECHNICAL_ARCHITECTURE.md](docs/architecture/TECHNICAL_ARCHITECTURE.md), [docs/architecture/TRUST_BOUNDARIES.md](docs/architecture/TRUST_BOUNDARIES.md), and [docs/architecture/DEPLOYMENT_ARCHITECTURES.md](docs/architecture/DEPLOYMENT_ARCHITECTURES.md) for the trust-boundary and runtime enforcement doctrine.
- Read [docs/architecture/BYPASS_RESISTANCE.md](docs/architecture/BYPASS_RESISTANCE.md) for the no-standing-agent-credentials deployment model.
- Read [docs/architecture/PRODUCTION_SIGNING_CUSTODY.md](docs/architecture/PRODUCTION_SIGNING_CUSTODY.md) and [docs/operations/KEY_LIFECYCLE_RUNBOOK.md](docs/operations/KEY_LIFECYCLE_RUNBOOK.md) before making production signing-custody claims.
- Run `bash scripts/verify_release_gate.sh` before publishing a release.

## Standard And Governance

Actenon is defining the open standard for Verifiable Action Receipts: proof-bound records of consequential agent actions. The open Kernel and conformance suite are available today; operated network, reputation, and insurance layers are future commercial layers.

The standards doctrine is simple: neutralize the standard, monetize the operation. You do not need to buy Actenon Cloud or ask Actenon's permission to implement the neutral VAR surface or verify VAR artifacts that conform to the open specs.

The open kernel, specs, conformance suite, SDKs, and examples in this repository are licensed under Apache-2.0. Apache-2.0 keeps the surface permissive while adding an explicit contributor patent grant, which supports neutral infrastructure adoption by implementers, competitors, platforms, and standards-oriented users.

Read the standard and governance doctrine:

- [NEUTRALITY_COMMITMENTS.md](#)
- [IP_POLICY.md](#)
- [TRADEMARK_AND_CONFORMANCE_POLICY.md](#)
- [DATA_AND_REPUTATION_GOVERNANCE.md](#)
- [ACTENON_MONSTER_UNICORN_THESIS.md](#)

## Cloud-Issued Artifacts Verified By The Open Kernel

The accepted v2 keystone proves the two-repo story:

- Actenon Cloud issues a pilot invoice-payment proof.
- Cloud exports a real kernel-compatible PCCB.
- Cloud emits copied Receipt and Refusal attestation envelopes.
- The open Kernel verifies those artifacts through well-known key discovery.
- Mutating signed fields, wrong key ids, wrong key purpose, expiry, and hard-revoke-without-anchor cases fail verification.

Start with:

- [ACTENON_V2_KEYSTONE_ACCEPTANCE.md](#)
- [docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md](docs/guides/CLOUD_TO_KERNEL_VERIFICATION.md)
- [conformance/vectors/cloud_invoice_payment_v1/](conformance/vectors/cloud_invoice_payment_v1/)

Finance and invoice payment are one high-stakes proof point for consequential action receipts. The kernel remains horizontal: the same receipt standard applies to destructive infrastructure operations, privileged access grants, sensitive data exports, payments, refunds, and protected agent tools when those wedges are implemented and enforced.

## What This Proves

- external verification of Cloud-issued proof artifacts
- origin and integrity verification for copied Receipt/Refusal attestation envelopes
- mutation and tampering failure for signed proof and outcome fields
- purpose-bound key discovery for proof issuance versus outcome attestation

## What This Does Not Prove

- that the upstream business decision was correct
- that a downstream provider action reached finality
- that an adapter or external provider behaved honestly after handoff
- that replay protection is active unless it is deployed and enforced at the protected endpoint
- that hosted transparency, long-term archive, RFC-3161-style timestamping, or production KMS/HSM custody exists in the OSS kernel

## The Deployment Rule: Remove The Side Door

Actenon only stops consequential actions that pass through the protected execution boundary.

The strongest deployment pattern is no standing agent credentials for production systems. The agent requests an action. The protected endpoint verifies the Action Intent and PCCB, consumes a single-use capability or escrow record, uses or brokers the privileged credential, executes or refuses, and emits a Receipt or Refusal. The agent never touches the raw production credential.

Without Actenon:

```text
agent -> standing credential -> production system
```

Weak Actenon deployment:

```text
agent -> protected endpoint -> production system
agent -> standing credential -> production system  [bypass remains]
```

Strong Actenon deployment:

```text
agent -> protected endpoint -> brokered single-use credential -> production system
no standing agent credential
```

The bypass risk is the central deployment risk. If an agent still has a raw production credential that can reach the provider directly, Actenon can produce useful proof, receipts, and refusals for the protected path, but it cannot stop side-door execution on the unprotected path.

Trust grade matters:

- OSS local Receipt: local/self-audit evidence unless asymmetric signing and verification material are configured.
- Cloud-issued attested Receipt: externally verifiable origin and integrity for the copied artifact.
- Local external anchor: append-only local durability evidence for signed Receipt/Refusal attestations.
- Hosted trust network anchoring: future stronger durability and compliance layer, not implemented in the OSS kernel.

Read [docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md](docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md) for the deployment pattern.

## Why This Exists

If you read only one explanatory doc before touching the product surface, read [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md).

It is the kernel's canonical public problem statement for proof-bound consequential execution, written to stand on its own outside GitHub context as well as inside the repository.

It answers the category question this repository exists to solve:

- auth, policy, and approval can all say "allow"
- the execution edge can still receive the wrong parameters, the wrong endpoint binding, the wrong tenant or subject, or a replayed request
- the missing trust boundary is the protected endpoint
- Actenon exists so that the execution edge verifies bound proof before side effects

Then move to [QUICKSTART.md](QUICKSTART.md) when you want to see the defense locally, or [MCP_HERO_PATH.md](MCP_HERO_PATH.md) when you want the clearest neutral integration pattern.

If you want the local scanner and the public definition behind it, read [EXECUTION_GAP_SCANNER.md](#).

If you are integrating delegated tools or multiple agents, read [MULTI_AGENT_EXECUTION_MODEL.md](MULTI_AGENT_EXECUTION_MODEL.md) before treating upstream approval or proof forwarding as sufficient execution authority.

## The Category And The Answer

The missing category is the execution gap: the gap between upstream authorization and the execution edge that actually performs the consequential side effect.

The answer is proof-bound execution: the execution edge independently verifies bound proof for the exact action, audience, tenant, subject, target, scope, expiry window, and replay identity before side effects.

This repository is meant to make both things obvious:

- why the market is missing an execution-edge trust primitive
- why proof-bound execution is the narrow mechanism that closes that gap
- why a complete local runtime matters for adoption, not just a verifier library

## First Run

The shortest credible first run is:

```bash
make install
actenon up
actenon doctor
actenon simulate --incident replit
python3 -m examples.refund_guard_local.server --runtime-dir artifacts/local_runtime
actenon bundle export --runtime-dir artifacts/local_runtime
actenon bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon
```

That path is intentionally product-shaped:

- `actenon up` starts a complete local trust machine
- `actenon doctor` tells you whether it is healthy
- `actenon simulate --incident replit` makes the execution gap memorable
- the protected refund endpoint proves you can guard a dangerous endpoint now
- `actenon bundle export` creates a `.actenon` portable execution evidence bundle
- `actenon bundle verify` proves the bundle is internally consistent and tamper-evident relative to its manifest, while staying explicit that v1 is not attestation-of-origin

If you want the exact walkthrough, start with [QUICKSTART.md](QUICKSTART.md) and then [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md).

Core docs:

- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [EXECUTION_GAP_SCANNER.md](#)
- [MULTI_AGENT_EXECUTION_MODEL.md](MULTI_AGENT_EXECUTION_MODEL.md)
- [CATEGORY.md](CATEGORY.md)
- [QUICKSTART.md](QUICKSTART.md)
- [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
- [GOVERNANCE.md](GOVERNANCE.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md)
- [TRACE_VIEWER.md](TRACE_VIEWER.md)
- [SUPPORT_AND_COMPATIBILITY_STATUS.md](SUPPORT_AND_COMPATIBILITY_STATUS.md)
- [SPEC_INDEX.md](SPEC_INDEX.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)

For evaluators:

- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md)
- [ADOPTION_DECISION_RECORD_TEMPLATE.md](ADOPTION_DECISION_RECORD_TEMPLATE.md)

Community and project standards:

- [GOVERNANCE.md](GOVERNANCE.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [LICENSE](LICENSE)

Recommended launch path:

1. [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
2. [QUICKSTART.md](QUICKSTART.md)
3. [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
4. [TRACE_VIEWER.md](TRACE_VIEWER.md)
5. [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
6. [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md)
7. [CONFORMANCE.md](CONFORMANCE.md)

## What This Repository Is

This repository is the public open kernel for proof-bound consequential execution.

It owns:

- the canonical public contracts under [`/spec`](spec)
- versioned public schemas under [`/schemas`](schemas)
- the reference verifier implementation and protected endpoint pattern
- the complete local single-node trust runtime
- local proof mode and replay/refusal/receipt primitives
- verifier-edge SDKs
- conformance tests and reusable examples

This repository is meant to be the default developer product for the category. It should read like serious execution infrastructure, not like an internal implementation dump and not like a thin open wrapper around a closed service.

## Why Now

Agent systems are no longer only choosing words. They are calling tools, touching provider APIs, changing state, and initiating irreversible actions.

Most current stacks still stop at authentication, policy, approvals, or workflow state. Those controls matter, but they do not by themselves guarantee that the protected endpoint executes the exact approved action exactly once.

That missing category is the execution gap.

Proof-bound execution is the mechanism this kernel publishes to close it.

## What The Kernel Publishes

- `Action Intent`: the public request contract for a consequential action
- `Intent Record`: the additive bounded-delegation artifact for local issuer, simulator, and future runtime-enforcement paths
- `PCCB`: the proof artifact a protected endpoint verifies before execution
- `Receipt`: the canonical structured outcome artifact
- `Refusal`: the canonical structured failure artifact
- `Protected Endpoint`: the execution-edge behavior that verifies proof before side effects
- `Replay`: the duplicate-execution defense surface

Start here:

- [THE_EXECUTION_GAP.md](THE_EXECUTION_GAP.md)
- [CATEGORY.md](CATEGORY.md)
- [QUICKSTART.md](QUICKSTART.md)
- [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [TRACE_VIEWER.md](TRACE_VIEWER.md)
- [SPEC_INDEX.md](SPEC_INDEX.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)
- [docs/reference/EXECUTION_SEMANTICS.md](docs/reference/EXECUTION_SEMANTICS.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [INTEGRATIONS.md](INTEGRATIONS.md)

## What `No Proof, No Action` Means

`No proof, no action` means a protected endpoint does not execute a consequential side effect because:

- the caller is authenticated
- an internal service said "allow"
- a workflow step completed
- an approval happened somewhere upstream

It executes only after verifier-side checks succeed against portable proof bound to the exact execution attempt.

That exactness matters because most consequential failures are not "unauthenticated caller" failures. They are "approved upstream, executed differently downstream" failures:

- wrong parameters
- wrong target
- wrong audience
- wrong tenant or subject
- duplicate execution through replay

Replay protection only helps when the replay path is actually enforced at that protected endpoint. If a host bypasses or disables replay enforcement, the kernel cannot prevent duplicate execution.

For storage, SQLite is the default local and single-node replay backend. For production OSS deployments with multiple workers, processes, containers, or nodes, use `PostgresReplayStore` so every protected endpoint instance claims against the same transactional replay table:

```bash
pip install "actenon-kernel[postgres]"
```

```python
from actenon.replay import PostgresReplayStore, ReplayProtector

replay_protector = ReplayProtector(
    PostgresReplayStore(dsn="postgresql://actenon:secret@db.example/actenon")
)
```

The normative behavior for that edge lives in:

- [spec/pccb/SPEC.md](spec/pccb/SPEC.md)
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [spec/replay/SPEC.md](spec/replay/SPEC.md)

## Who This Is For

- platform teams protecting consequential tools, routes, or provider calls
- security teams that want execution-edge guarantees instead of policy-only claims
- SDK and framework teams integrating protected tools or protected routes into agent stacks
- teams that need portable receipts and refusals, not only internal logs
- open-source adopters who want a verifier-first path without committing to a hosted layer

## What The Kernel Guarantees

When integrated correctly, the OSS kernel guarantees:

- public, versioned contracts instead of hidden request shapes
- exact proof binding to action, target, tenant, subject, audience, scope, expiry, and nonce at the protected endpoint
- protected-endpoint refusal of mutated, expired, mis-addressed, mis-scoped, or replayed requests before side effects when the relevant checks are actually enforced
- optional local PCCB mint audit records for retrospective issuer-side inspection when a minter is configured with an audit sink
- structured Receipt and Refusal artifacts with stable public meaning
- opt-in signed Receipt/Refusal attestation envelopes for deployments that need portable origin checks on copied outcome artifacts
- deterministic local proof mode and a public conformance target for compatible implementations

It does not guarantee provider truthfulness, hosted workflow correctness, production key custody, long-term archive, or enterprise operations. Read the exact line in [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## What This Does Not Solve

- a compromised issuer, signer, or external control plane can still mint or cause minting of valid proof for the wrong action
- mint audit records improve detectability after the fact; they do not prevent bad proof issuance or prove the upstream business decision was correct
- a malicious or buggy adapter can still lie about downstream side effects after control passes to it
- replay defense only exists where the protected endpoint actually enforces the replay path
- v1 Receipt and Refusal artifacts by themselves are canonical structured artifacts, not portable cryptographic attestations of origin
- provider-backed reconciliation or finality is not part of active v1
- reserved surfaces such as Reconciliation and Policy Bundle are named extension boundaries, not active v1 standards

For portable origin checks, use the opt-in Outcome Attestation v2alpha1 envelope in [spec/outcome-attestation/SPEC.md](spec/outcome-attestation/SPEC.md). The attestation envelope signs an embedded v1 Receipt or Refusal; it does not change v1 outcome semantics or add hosted trust services.

## Artifacts

The kernel's canonical public artifacts and behavior surfaces are:

- Action Intent
- PCCB
- Receipt
- Refusal
- Protected Endpoint
- Replay

In v1, Receipt and Refusal are canonical structured artifacts with stable public meaning. When an adopter needs portable origin verification for a copied outcome artifact, the kernel supports opt-in v2alpha1 outcome attestation envelopes for Receipt and Refusal.

The reference flows also emit:

- local proof manifests
- local Intent Record artifacts
- receipt and refusal JSON artifacts
- replay and endpoint state artifacts in the local demos
- conformance output

## Compatibility And Conformance

This repository is a public compatibility target, not only a reference implementation.

Compatibility means honoring the active public contracts and behavior for:

- Action Intent
- PCCB
- Protected Endpoint
- Replay
- Receipt
- Refusal

Current compatibility does not include Reconciliation or Policy Bundle. Those remain reserved public surfaces, not active v1 standards. Provider-backed reconciliation or finality is not part of active v1.

Reconciliation is still an important future standard boundary for normalizing post-execution provider state, but activation requires explicit spec, reference-implementation, and conformance work. See [RECONCILIATION_ACTIVATION_PLAN.md](#).

The Protected Endpoint is the central behavioral compatibility surface. A system is not meaningfully compatible if proof verification happens only upstream while the execution edge can still act without re-checking proof and replay requirements.

Fastest compatibility path:

```bash
make install
actenon conformance run
```

Use that path when you want the quickest operational signal for active v1 compatibility. Use the demo and trace-viewer path when you want the broader product walkthrough.

Start here:

- [CONFORMANCE.md](CONFORMANCE.md)
- [SPEC_INDEX.md](SPEC_INDEX.md)
- [docs/guides/CONFORMANCE_TESTS_GUIDE.md](docs/guides/CONFORMANCE_TESTS_GUIDE.md)
- [docs/guides/COMPATIBILITY_FAQ.md](docs/guides/COMPATIBILITY_FAQ.md)

If you want the boundary-regression companion to conformance, see [EXECUTION_GAP_SCANNER.md](#) and [docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md](docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md). The repository ships `actenon scan` as a local advisory scanner for candidate agent-controlled consequential action paths. It maps agent authority; it does not accuse a repo of being vulnerable. Consequence Class is not Vulnerability Severity: a Critical-impact candidate means an action surface could have critical consequences if reachable, agent-controlled and ungated, not that a critical vulnerability has been proven. The scanner remains kernel-adjacent rather than an active v1 contract surface, and its output is not a certification or exploitability proof. For the screenshot-friendly report shape, see [docs/examples/scanner-report-example.md](docs/examples/scanner-report-example.md).

Quick scanner path:

```bash
actenon scan --target replay-harness
actenon scan repo --path .
actenon scan mcp --path examples/mcp_server_protected_tool
```

GitHub Actions path:

- [.github/actions/execution-gap-scan/README.md](#)

Run the public conformance surface locally:

```bash
actenon conformance run
```

## Try It Locally

Single-node runtime path:

```bash
make install
actenon up
```

In another terminal:

```bash
actenon doctor
actenon simulate --incident replit
```

`actenon up` now starts the local single-node trust runtime itself. By default it serves:

- `POST /v1/intents` on `http://127.0.0.1:8787/v1/intents`
- `GET /.well-known/actenon/keys.json` and `GET /.well-known/actenon-keys.json`
- `GET /healthz`
- the local read-only trace viewer on `http://127.0.0.1:8421` when that port is available

In default local `HS256` trust mode, the key-discovery URLs are present but return an explicit unavailable response until you place a publishable key-discovery document at `artifacts/local_runtime/keys/actenon-keys.json`.

That path gives you a complete local single-node trust runtime under `artifacts/local_runtime/`:

- local issuer and verifier labs
- a separate seeded invoice-payment issuer lab for approval and evidence workflow scenarios
- a local issuer HTTP surface backed by the shipped kernel minting path
- local replay-backed protected-endpoint runs with durable SQLite replay and escrow
- local receipts, refusals, and evidence-query artifacts
- local incident simulations, including named educational incident runs for `replit`, `openai-eggs`, and `amazon-kiro`, plus lower-level technical scenarios for audience mismatch, action-hash mismatch, expiry, and replay refusal
- local bundle export and local key generation commands without any required hosted dependency
- local Intent Record artifacts that make bounded machine delegation inspectable before proof and after execution

Persisted local runtime storage:

- labs root: `artifacts/local_runtime/labs/`
- refund proof lab: `artifacts/local_runtime/labs/local_proof/`
- invoice payment issuer lab: `artifacts/local_runtime/labs/invoice_payment_local_proof/`
- portable verifier lab: `artifacts/local_runtime/labs/portable_local_proof/`
- live runtime artifact root: `artifacts/local_runtime/artifacts/`
- live runtime requests: `artifacts/local_runtime/artifacts/requests/`
- live runtime receipts: `artifacts/local_runtime/artifacts/outcomes/receipts/`
- live runtime refusals: `artifacts/local_runtime/artifacts/outcomes/refusals/`
- live runtime durable state: `artifacts/local_runtime/state/`
- live runtime replay store: `artifacts/local_runtime/state/replay.sqlite3`
- live runtime escrow store: `artifacts/local_runtime/state/escrow.sqlite3`
- live runtime simulations: `artifacts/local_runtime/simulations/`
- live runtime bundle exports: `artifacts/local_runtime/bundles/`
- live runtime key material: `artifacts/local_runtime/keys/`
- live runtime service manifest: `artifacts/local_runtime/service_manifest.json`

`actenon doctor` now defaults to a fast local runtime diagnostic: signer usability, replay and escrow accessibility, artifact writability, runtime-server reachability, key-discovery reachability, and trace-viewer readiness when configured. Use `actenon doctor --deep` when you also want slower lab, evidence-query, portable verifier, and scanner checks. A bootstrap-only runtime will report `needs_attention` until the foreground runtime is actually running.

When `actenon up` starts the foreground runtime, it prints:

- issuer URL
- health URL
- key-discovery URL and legacy alias
- the local key-publication file path at `artifacts/local_runtime/keys/actenon-keys.json`
- trace viewer URL or an explicit "not started" reason
- artifact, replay, and escrow paths
- a first `curl` against `/healthz`

That startup output is intentionally honest in local `HS256` mode: the runtime prepares the well-known publication surface, but it does not pretend the local symmetric trust secret is publishable verifier material.

`actenon simulate` is the fastest way to make the execution gap legible. Start with a named incident such as:

```bash
actenon simulate --incident replit
```

Each incident run is an educational simulation inspired by public incidents, not an exact forensic reconstruction. The simulator writes an `INCIDENT_SUMMARY.md` into each incident or scenario directory and shows:

- the counterfactual outcome without execution-edge verification
- what proof verification catches directly
- what still requires protected-endpoint runtime state, such as replay enforcement
- what the persisted Action Intent plus Receipt or Refusal lets you prove afterward

Named incident runs also write first-class `weak_control_path.json`, `proof_bound_path.json`, `proof_only_gap.json`, and `bounded_intent_change.json` artifacts so the boundary is visible without reading long prose.

If the local runtime is serving with the trace viewer enabled, refresh the viewer after a simulation run and open the `Incident Simulator` run to inspect those same incident artifacts interactively.

## Authorization, Intent, Proof, Evidence

Actenon now separates four things explicitly:

- authorization: who may ask for something
- intent: what bounded machine action is actually being delegated, including prohibited actions, abort conditions, blast-radius limits, required approvals, and required evidence
- proof: the `PCCB` that a protected endpoint verifies before side effects
- execution evidence: the `Receipt`, `Refusal`, receipt chain, and evidence query surfaces that show what actually happened

The new draft Intent Record layer is additive. It does not replace `Action Intent` or `PCCB`, and it does not change active v1 proof semantics. It makes bounded delegation inspectable in the local issuer and simulator paths now, while leaving broader enforcement work for future versions.

The current draft artifact shape and semantics live in [spec/intent-record/SPEC.md](spec/intent-record/SPEC.md).

If you want the labs and manifests without starting the HTTP services, use `actenon up --bootstrap-only`.

Reset the local runtime by removing `artifacts/local_runtime/` or recreating it in a fresh directory with `actenon up --runtime-dir ...`. If you only want to clear durable runtime execution state while keeping the seeded labs, remove `artifacts/local_runtime/state/`, `artifacts/local_runtime/artifacts/`, and `artifacts/local_runtime/service_manifest.json`.

If your goal is "protect a dangerous endpoint quickly," start with the refund endpoint at [examples/refund_guard_local/README.md](examples/refund_guard_local/README.md). It is the shortest local path from clone to a consequential protected side effect.

Shortest credible path:

1. run `actenon up`
2. start `python3 -m examples.refund_guard_local.server`
3. either call `/refunds/local-admission` with a plain framework request or `POST /v1/intents` to the local issuer
4. call the protected refund endpoint directly or with `python3 -m examples.refund_guard_local.call_endpoint`
5. inspect the emitted Receipt or Refusal under `artifacts/local_runtime/artifacts/outcomes/`

Adoption ladder:

- edge-only admission now: raw caller request is normalized into a local Action Intent and evaluated at the edge
- local issuing next: the caller gets a PCCB from the local issuer before execution
- proof-carrying flow after that: the endpoint verifies Action Intent plus PCCB directly
- cross-boundary trust later: move to published verification material and verifier-only SDKs when proof must travel between systems or organizations

Use the local issuer directly:

The runtime issuer currently supports:

- `refund.execute`
- `invoice_payment.execute`

It returns a real policy decision on every request. `allow` responses include a PCCB and escrow id. `deny` responses include a structured refusal. `approval-required` and `needs-evidence` responses stop before proof minting and return the decision receipt without a PCCB.

Allow example:

```bash
curl -s http://127.0.0.1:8787/v1/intents \
  -H 'Content-Type: application/json' \
  -d @- <<'JSON'
{
  "action_intent": {
    "contract": {"name": "action_intent", "version": "v1"},
    "intent_id": "intent_local_runtime_allow",
    "issued_at": "2026-01-01T12:00:00Z",
    "expires_at": "2026-01-01T12:05:00Z",
    "tenant": {"tenant_id": "tenant_demo"},
    "requester": {"type": "service", "id": "demo_actor"},
    "action": {
      "name": "refund.create",
      "capability": "refund.execute",
      "parameters": {"amount_minor": 1500, "currency": "USD"},
      "constraints": {"exact_amount_minor": 1500, "exact_currency": "USD"},
      "scope": {"single_use": true, "target_resource_type": "payment"}
    },
    "target": {"resource_type": "payment", "resource_id": "payment_demo_001"}
  },
  "context": {
    "audience": "service:local-refund-endpoint",
    "now": "2026-01-01T12:00:00Z"
  }
}
JSON
```

That response will include:

- `decision.outcome: "allow"`
- `pccb`
- `escrow_id`
- canonical `receipt`
- request artifact paths under `artifacts/local_runtime/artifacts/requests/`

Approval-required example with a shipped local lab intent:

```bash
python3 - <<'PY' | curl -s http://127.0.0.1:8787/v1/intents -H 'Content-Type: application/json' -d @-
import json
from pathlib import Path

payload = json.loads(
    Path("artifacts/local_runtime/labs/local_proof/scenarios/approval_required/action_intent.json").read_text(encoding="utf-8")
)
print(json.dumps({"action_intent": payload, "context": {"now": payload["issued_at"]}}))
PY
```

That response will include:

- `decision.outcome: "approval-required"`
- no `pccb`
- no `escrow_id`
- canonical decision `receipt`
- no `refusal`

If you replay shipped lab intents directly, supply an in-window `context.now` or use a fresh intent. Those fixtures carry fixed timestamps and will otherwise fail chronology checks once they are outside their validity window.

Timing guidance:

- high-risk or irreversible actions should use short proof windows, commonly 30 to 120 seconds
- ordinary consequential actions should generally stay in the 2 to 5 minute range
- low-risk read, diagnostic, or demo flows can use longer windows, but should still avoid open-ended proof lifetime
- verifier-side clock skew tolerance defaults to zero and should only cover expected NTP drift, such as a few seconds to tens of seconds, not queueing delay or stale proof reuse

Local mint audit hook:

```python
from actenon.proof import LocalAppendOnlyAuditLogSink, PCCBMinter

minter = PCCBMinter(
    signer=signature_signer,
    issuer=issuer,
    audit_sink=LocalAppendOnlyAuditLogSink("artifacts/mint-audit.jsonl"),
)
```

The sink writes privacy-conscious PCCB mint records for retrospective inspection. It logs correlation and detection fields such as `pccb_id`, `intent_id`, issuer, audience, capability, action hash, key id, and hashed tenant, subject, nonce, and target material. It does not log action parameters, plaintext subject identifiers, plaintext tenant identifiers, target resource ids, or signature bytes.

This is detectability, not prevention. A configured sink can help you find suspicious issuance after the fact, but it does not stop a compromised issuer from minting proof or provide hosted transparency by itself.

Fastest first pass if you only want the original proof demo:

```bash
make install
bash ./scripts/first_run.sh
make public-verify
```

That path gives you:

- a zero-credential local proof run
- inspectable Action Intent, PCCB, receipt, and refusal artifacts
- protected-endpoint and replay behavior in a deterministic local environment
- a public verification pass for installability and coherence

Before a public release or launch archive, run the hard release gate:

```bash
bash scripts/verify_release_gate.sh
```

That gate blocks on the focused keystone suite, full `pytest tests/`, Ruff,
public boundary validation, and public archive creation/validation.

After that first run, the fastest way to inspect what happened is the read-only OSS Trace Viewer:

```bash
python3 -m actenon.ui.trace_viewer.app
```

Then open `http://127.0.0.1:8421`.

If you want the strongest agent-tool integration path after that first run, go next to:

- [docs/guides/FIRST_10_MINUTES.md](docs/guides/FIRST_10_MINUTES.md)
- [TRACE_VIEWER.md](TRACE_VIEWER.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [examples/mcp_server_protected_tool/README.md](examples/mcp_server_protected_tool/README.md)

The trace viewer is local and read-only. It helps you inspect Action Intent, PCCB, Receipt, Refusal, replay entries, and protected-endpoint state from local kernel artifacts. It does not mint proof, change workflow state, or act as the operational product.

Inspect this order first:

- Action Intent and PCCB
- the emitted Receipt or Refusal
- replay entries and protected-endpoint state when present
- the execution-flow timeline

The viewer is not an approvals UI, evidence review UI, policy editor, reconciliation UI, audit operations dashboard, tenant or admin UI, or the operational product.

Useful next commands:

```bash
actenon doctor --runtime-dir artifacts/local_runtime
actenon simulate --runtime-dir artifacts/local_runtime --scenario all
actenon bundle export --runtime-dir artifacts/local_runtime
actenon bundle verify artifacts/local_runtime/bundles/actenon-local-runtime.actenon
actenon keys generate --key-id local-runtime-dev --output artifacts/local_runtime/keys/local-runtime-dev.json
actenon verify-proof --intent artifacts/local_proof/scenarios/allow/action_intent.json --pccb artifacts/local_proof/scenarios/allow/pccb.json --audience service:local-refund-endpoint --verification-time pccb-issued-at
actenon verify-receipt --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json --intent artifacts/local_proof/scenarios/allow/action_intent.json --pccb artifacts/local_proof/scenarios/allow/pccb.json
actenon attest-receipt --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json --output artifacts/local_proof/scenarios/allow/execution_receipt.attestation.json
actenon verify-receipt-attestation --attestation artifacts/local_proof/scenarios/allow/execution_receipt.attestation.json
actenon evidence query --intent-id intent_allow --artifacts-dir artifacts/local_proof
actenon graph anchor --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json --dry-run
actenon keys publish --issuer-origin https://trust.example --issuer-id issuer_demo --key-id issuer-ed25519-2026-04 --algorithm EdDSA --public-jwk-file ./issuer-public.jwk.json --output ./keys.json
actenon conformance run
```

The bundle class is intentionally narrow and useful:

- portable execution evidence you can move between machines or teams
- manifest-linked file hashes and canonical artifact digests for tamper checks
- proof-chain metadata for Action Intent, PCCB, and Receipt or Refusal where available
- not a cryptographic attestation of origin in v1

Standalone proof verification with explicit audience:

The CLI requires the local protected-endpoint audience explicitly. It does not infer verifier context from the PCCB.

```bash
actenon verify-proof \
  --intent artifacts/local_proof/scenarios/allow/action_intent.json \
  --pccb artifacts/local_proof/scenarios/allow/pccb.json \
  --audience service:local-refund-endpoint \
  --verification-time pccb-issued-at
```

Structured JSON failure output:

```bash
actenon verify-proof \
  --intent artifacts/portable_local_proof/action_intent.json \
  --pccb artifacts/portable_local_proof/pccb.json \
  --audience service:wrong-endpoint \
  --verification-time pccb-issued-at \
  --json
```

Local execution evidence lookup:

The CLI can also answer whether a local artifact root contains a verified execution or refusal chain for a specific receipt, PCCB, intent, or action hash. This is a local evidence query over emitted artifacts, not a hosted evidence service.

```bash
actenon evidence query \
  --intent-id intent_allow \
  --artifacts-dir artifacts/local_proof
```

Local execution-anchor creation:

The CLI can also create a local `execution_anchor v1` artifact from an executed receipt or a refusal. This is useful for demos and inspection, and publication remains optional.

```bash
actenon graph anchor \
  --receipt artifacts/local_proof/scenarios/allow/execution_receipt.json \
  --dry-run
```

Publish a well-known key-discovery document:

For deployments using asymmetric verifier trust, the CLI can generate a conformant `key_discovery` document from a public JWK without adding hosted infrastructure or key-lifecycle machinery.

```bash
actenon keys publish \
  --issuer-origin https://trust.example \
  --issuer-id issuer_demo \
  --key-id issuer-ed25519-2026-04 \
  --algorithm EdDSA \
  --public-jwk-file ./issuer-public.jwk.json \
  --output ./keys.json
```

Generate local single-node key material:

For fully local issuer and verifier experiments, the CLI can also generate symmetric HS256 key material for single-node use. This is local runtime material, not public verification material, so it is not publishable through key discovery.

```bash
actenon keys generate \
  --key-id local-runtime-dev \
  --output artifacts/local_runtime/keys/local-runtime-dev.json
```

## Specs, SDKs, And Integrations

Specs and behavior:

- [SPEC_INDEX.md](SPEC_INDEX.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [VERSIONING_POLICY.md](VERSIONING_POLICY.md)
- [docs/reference/EXECUTION_SEMANTICS.md](docs/reference/EXECUTION_SEMANTICS.md)
- [docs/guides/CONFORMANCE_TESTS_GUIDE.md](docs/guides/CONFORMANCE_TESTS_GUIDE.md)

Verifier SDKs and examples:

Python is the reference kernel path. TypeScript and Go are verifier-edge SDK paths; the current tested support posture lives in [SUPPORT_AND_COMPATIBILITY_STATUS.md](SUPPORT_AND_COMPATIBILITY_STATUS.md).

Framework example sequence:

1. MCP
2. LangChain
3. Claude Managed Agents
4. LlamaIndex
5. CrewAI
6. Semantic Kernel

MCP remains the neutral hero path. Claude Managed Agents is a strong secondary platform example. The other framework examples support category distribution and adoption, but they are not equal launch stories.

The Claude Managed Agents example is Anthropic-specific but kernel-compatible. It is there to show the same verifier-first execution boundary on one managed agent surface, not to imply partnership, endorsement, or hosted control-plane coupling.


- [docs/reference/verifier/VERIFIER_SDK_REFERENCE.md](docs/reference/verifier/VERIFIER_SDK_REFERENCE.md)
- [SDK_SELECTION_GUIDE.md](SDK_SELECTION_GUIDE.md)
- [MCP_HERO_PATH.md](MCP_HERO_PATH.md)
- [SUPPORT_AND_COMPATIBILITY_STATUS.md](SUPPORT_AND_COMPATIBILITY_STATUS.md)
- [sdk/typescript/README.md](sdk/typescript/README.md)
- [sdk/go/README.md](sdk/go/README.md)
- [sdk/rust/README.md](sdk/rust/README.md)
- [INTEGRATIONS.md](INTEGRATIONS.md)
- [docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md](docs/reference/verifier/HELLO_WORLD_PROTECTED_RESOURCE.md)

## Where The Paid Layer Begins

This repository is not the hosted control plane and must not become it.

The paid control plane begins where the product requires:

- approvals and workflow routing
- evidence intake and review
- provider runtime services
- reconciliation operations
- hosted transparency or network-scale audit services
- long-term archive and dashboards
- audit operations
- billing, tenant administration, and enterprise multi-tenancy

The exact boundary is defined in [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md).

## Community

If you want to contribute, report a bug, ask a compatibility question, or review project expectations, start here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
