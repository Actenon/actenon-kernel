# Kernel Guarantees

These guarantees define what the OSS kernel provides when it is integrated according to the published specs and when the relevant protected-endpoint checks are actually enforced.

## What The OSS Kernel Guarantees

- Explicit public contracts. Consequential requests enter the system as versioned Action Intent payloads, not hidden internal request shapes.
- Exact proof binding. A valid PCCB is bound to the exact action, target, tenant, subject, audience, scope, expiry window, and nonce it authorizes, and that binding is verified at the protected endpoint before side effects.
- Default-strict time enforcement. The verifier enforces `not_before` and `expires_at` with zero clock skew tolerance unless an adopter explicitly configures a bounded tolerance.
- Protected-endpoint refusal. A protected endpoint can refuse mutated, expired, mis-addressed, mis-scoped, or otherwise invalid execution attempts before side effects.
- Replay primitives. When the replay path is actually enforced at the protected endpoint, the kernel can claim, consume, release, and reject duplicate execution attempts at the execution edge.
- Escrow-aware execution checks. When the execution path includes escrow, the kernel can refuse missing, expired, revoked, or already-consumed capability state before side effects.
- Optional mint audit logging. A PCCB minter can emit a privacy-conscious local mint record to an `AuditLogSink` so issuance is retrospectively inspectable when the adopter configures a sink.
- Canonical outcome artifacts. Receipt and refusal payloads are structured, machine-readable, correlation-friendly, and stable at the contract level.
- Opt-in outcome attestation. The kernel can wrap a v1 Receipt or Refusal in an active v2alpha1 signed attestation envelope so consumers can verify artifact integrity and origin against a configured key.
- Deterministic local proof mode. The repository can demonstrate the proof-required flow without external accounts or provider sandboxes.
- Public conformance base. The repository publishes compatibility targets for Action Intent, PCCB, Protected Endpoint, Replay, Receipt, and Refusal that independent adopters can test against.
- Boundary discipline. The repository keeps public contracts, verifier behavior, and local reference flows separate from the paid control plane.

## What The OSS Kernel Does Not Guarantee

- that upstream policy or approvals were correct
- that a compromised issuer, signer, or external control plane did not mint bad proof
- that mint audit logging prevents bad proof issuance or provides hosted transparency
- that a provider or adapter reported truthful side-effect status
- provider-authenticated reconciliation or settlement finality
- a global proof revocation service
- hosted approval routing or evidence review
- long-term archive, dashboards, or audit operations
- production key custody or HSM-backed signing
- multi-tenant hosted-service isolation
- business correctness outside the kernel boundary
- portable cryptographic attestation of origin for copied receipts or refusals unless an Outcome Attestation envelope is present and verified against a trusted key
- provider-backed reconciliation or finality as an active v1 standard
- active v1 compatibility targets for Reconciliation or Policy Bundle

Outcome Attestation is additive and opt-in. It does not change Receipt v1 or Refusal v1 semantics, and it does not provide hosted trust administration, provider finality, or production key custody by itself.

## Conditions

These guarantees hold only if the adopter:

- verifies proof before any protected side effect
- enforces the replay path on consequential execution attempts that need duplicate-execution defense
- does not bypass the protected endpoint, replay, or escrow checks required by the relevant path
- uses replay and escrow storage with durability and atomicity appropriate to the deployment
- configures and preserves mint audit records if issuer-side retrospective inspection is required
- treats audience, tenant, subject, and capability matching as mandatory security checks
- maintains reasonable clock correctness for `not_before` and `expires_at`, and keeps any configured clock skew tolerance short enough for the action risk class
- protects signer trust roots and verifier configuration appropriately for the environment

## What This Does Not Solve

- a compromised issuer, signer, or external control plane can still produce valid-looking but bad proof
- mint audit records improve detectability after issuance; they do not stop compromised issuance
- a malicious or buggy adapter can still lie about side effects after control passes to it
- replay protection only helps where the protected endpoint actually enforces the replay path
- clock skew tolerance only reduces false refusals from small time drift; it does not make long proof windows safe
- v1 Receipt and Refusal artifacts alone are canonical structured artifacts, not portable cryptographic attestations of origin
- Outcome Attestation only proves the signed envelope matches the embedded v1 artifact and the configured signing key
- provider-backed reconciliation or finality is not part of active v1
- reserved surfaces such as Reconciliation and Policy Bundle are not active v1 standards

## Local Proof Mode

Local proof mode is a reference environment. It demonstrates the kernel end to end, but it does not claim:

- provider-backed execution
- production signing infrastructure
- production reconciliation
- hosted operations

Related documents:

- [THREAT_MODEL.md](THREAT_MODEL.md)
- [docs/reference/EXECUTION_SEMANTICS.md](docs/reference/EXECUTION_SEMANTICS.md)
- [spec/protected-endpoint/SPEC.md](spec/protected-endpoint/SPEC.md)
- [spec/replay/SPEC.md](spec/replay/SPEC.md)
- [spec/outcome-attestation/SPEC.md](spec/outcome-attestation/SPEC.md)
- [OPEN_SOURCE_BOUNDARY.md](OPEN_SOURCE_BOUNDARY.md)
- [RECEIPT_V2_DESIGN.md](RECEIPT_V2_DESIGN.md)
