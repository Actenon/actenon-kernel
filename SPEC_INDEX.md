# Spec Index

This index is the canonical entry point for the repository's normative public surface.

The rule is simple:

1. human-readable norms live under [`/spec`](spec)
2. versioned machine schemas live under [`/schemas`](schemas)
3. if an older top-level document conflicts with `/spec`, `/spec` wins

Only the active contract and behavior surfaces below are current compatibility targets. Reserved surfaces are named extension boundaries, not active v1 standards.

For a public compatibility claim to be safe, an implementation should target these active surfaces and pass the public conformance suite for them. The protected endpoint remains the central behavioral compatibility surface.

## Active Contract Specs

| Surface | Status | Human spec | Machine schema | Examples |
| --- | --- | --- | --- | --- |
| Action Intent | Active v1 | [`spec/action-intent/SPEC.md`](spec/action-intent/SPEC.md) | [`spec/action-intent/schema.json`](spec/action-intent/schema.json) | [`spec/action-intent/examples/`](spec/action-intent/examples) |
| PCCB | Active v1 | [`spec/pccb/SPEC.md`](spec/pccb/SPEC.md) | [`spec/pccb/schema.json`](spec/pccb/schema.json) | [`spec/pccb/examples/`](spec/pccb/examples) |
| Receipt | Active v1 | [`spec/receipt/SPEC.md`](spec/receipt/SPEC.md) | [`spec/receipt/schema.json`](spec/receipt/schema.json) | [`spec/receipt/examples/`](spec/receipt/examples) |
| Refusal | Active v1 | [`spec/refusal/SPEC.md`](spec/refusal/SPEC.md) | [`spec/refusal/schema.json`](spec/refusal/schema.json) | [`spec/refusal/examples/`](spec/refusal/examples) |
| Outcome Attestation | Active opt-in v2alpha1 | [`spec/outcome-attestation/SPEC.md`](spec/outcome-attestation/SPEC.md) | [`schemas/receipt_attestation.v2alpha1.json`](schemas/receipt_attestation.v2alpha1.json), [`schemas/refusal_attestation.v2alpha1.json`](schemas/refusal_attestation.v2alpha1.json) | Embedded v1 Receipt or Refusal artifacts |

## Active Behavior Specs

| Surface | Status | Human spec | Purpose |
| --- | --- | --- | --- |
| Protected Endpoint | Active behavioral spec | [`spec/protected-endpoint/SPEC.md`](spec/protected-endpoint/SPEC.md) | Defines what the execution edge must verify before side effects. |
| Replay | Active behavioral spec | [`spec/replay/SPEC.md`](spec/replay/SPEC.md) | Defines duplicate-execution defense semantics at the protected edge. |

Proof binding happens at the protected endpoint. Replay only helps where the replay path is actually enforced at that protected endpoint.

## Public Kernel Surface Specs

| Surface | Status | Human spec | Current meaning |
| --- | --- | --- | --- |
| Receipt Chain | Public additive kernel surface | [`spec/receipt-chain/SPEC.md`](spec/receipt-chain/SPEC.md) | Standardizes `evidence_refs.type=actenon.receipt`, digest expectations, and receipt-chain verification semantics on top of active v1 artifacts. |
| Evidence API | Public local kernel service surface | [`spec/evidence-api/SPEC.md`](spec/evidence-api/SPEC.md) | Defines the local `EvidenceQuery`, `EvidenceVerdict`, `EvidenceResult`, and bounded evidence-chain lookup semantics. This is not a hosted API contract. |
| Key Discovery | Public cross-boundary trust surface | [`spec/key-discovery/SPEC.md`](spec/key-discovery/SPEC.md) | Defines the well-known HTTPS document for publishing issuer verification keys by `key_id` without requiring Actenon-hosted infrastructure. |
| Execution Graph | Public optional publication surface | [`spec/execution-graph/SPEC.md`](spec/execution-graph/SPEC.md) | Defines the narrow `execution_anchor v1` publication artifact for publishing canonical digests of a terminal execution outcome without making publication part of protected-endpoint correctness. |
| Intent Record | Public draft bounded-delegation surface | [`spec/intent-record/SPEC.md`](spec/intent-record/SPEC.md) | Defines the additive `intent_record v1alpha1` artifact for recording bounded machine delegation, approvals/evidence requirements, and proof/evidence state without changing active v1 proof semantics. |

These specs are public and implementation-aligned, but they do not by themselves create new top-level artifact contracts or independent hosted-service compatibility claims.

## Reserved Public Surfaces

| Surface | Status | Human spec | Current meaning |
| --- | --- | --- | --- |
| Reconciliation | Reserved, no active v1 contract | [`spec/reconciliation/SPEC.md`](spec/reconciliation/SPEC.md) | Provider-authenticated reconciliation is important, but not part of the current OSS kernel contract set. Activation requirements are tracked in [`RECONCILIATION_ACTIVATION_PLAN.md`](RECONCILIATION_ACTIVATION_PLAN.md). |
| Policy Bundle | Reserved, no active v1 contract | [`spec/policy-bundle/SPEC.md`](spec/policy-bundle/SPEC.md) | Policy interchange remains reserved rather than standardized in the current OSS kernel. |

Reserved surfaces are named extension boundaries, not active v1 standards, conformance targets, or compatibility claims.

## What This Index Does Not Make Active

- provider-backed reconciliation or finality is not part of active v1
- mapper interfaces, local receipt fields, or ecosystem guidance do not by themselves activate Reconciliation
- in v1, Receipt and Refusal are active artifact contracts but remain canonical structured artifacts, not portable cryptographic attestations of origin
- Outcome Attestation v2alpha1 is an opt-in signed envelope; it does not change Receipt v1 or Refusal v1 semantics
- receipt chain and evidence query specs do not by themselves create a hosted evidence service or new top-level artifact contract
- key discovery does not by itself define trust bootstrap, operator workflows, or a hosted registry
- execution graph does not by itself define a hosted transparency service, archive, or public search endpoint
- intent record does not by itself create a new mandatory protected-endpoint input or activate a new v1 proof-verification requirement
- reserved surfaces such as Reconciliation and Policy Bundle are not active standards until a future version explicitly activates them

## Companion Documents

- [CATEGORY.md](CATEGORY.md)
- [KERNEL_GUARANTEES.md](KERNEL_GUARANTEES.md)
- [docs/reference/EXECUTION_SEMANTICS.md](docs/reference/EXECUTION_SEMANTICS.md)
- [CONFORMANCE.md](CONFORMANCE.md)
- [docs/guides/COMPATIBILITY_FAQ.md](docs/guides/COMPATIBILITY_FAQ.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [RECONCILIATION_ACTIVATION_PLAN.md](RECONCILIATION_ACTIVATION_PLAN.md)
- [RECEIPT_V2_DESIGN.md](RECEIPT_V2_DESIGN.md)
- [spec/outcome-attestation/SPEC.md](spec/outcome-attestation/SPEC.md)
- [VERSIONING_POLICY.md](VERSIONING_POLICY.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)

## Normative Priority

For active public contracts, the normative source is the relevant `/spec/<surface>/SPEC.md` together with its active schema surface.

For machine validation, the underlying versioned compatibility unit remains the schema published under `/schemas`.
