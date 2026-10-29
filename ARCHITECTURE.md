# Actenon Architecture

Actenon is the **proof-required execution control layer** for consequential AI agent actions. It is organized across a seven-repository topological DAG so that wire specifications, stateless edge verifiers, static authority discovery, runtime capability brokers, and pre-merge/runtime governance remain cleanly separated and independently verifiable.

---

## 1. The Seven-Repository Ecosystem

| Tier | Repository | Package / Artifact | Responsibility |
| :--- | :--- | :--- | :--- |
| **Tier 0** | `Actenon/actenon-protocol` | PyPI `actenon-protocol`, npm `@actenon/protocol-types`, npm `@actenon/canonical` | Wire schemas (`ActionIntent`, `PCCB`, `Receipt`, `Refusal`), strict canonicalization profile (`ACTENON-JCS-STRICT-1`), and authoritative effect ownership profile (`ACTENON-EFFECT-1`). |
| **Tier 1A** | `Actenon/actenon-kernel` | PyPI `actenon-kernel` | Reference verification engine (`PCCBVerifier`, `ActenonGate`, `BoundaryVerifier`), atomic replay protection (`ReplayStore`), effect ownership (`EffectProtector`), and locked conformance vectors (`conformance/vector-lock.json`). |
| **Tier 1B** | `Actenon/actenon-scan` | PyPI `actenon-scan` | Zero-dependency static AST and call-graph reachability scanner for Python, TypeScript, and Go codebases; emits `RESOLVED` vs `HEURISTIC` consequential capability inventories and SARIF/PR authority diffs. |
| **Tier 2** | `Actenon/sdk-go` & `Actenon/sdk-rust` | Go module `github.com/Actenon/sdk-go`, Rust crate `actenon-verifier` | Independent polyglot edge verifiers synchronized byte-for-byte against `conformance/vector-lock.json`. |
| **Tier 3** | `Actenon/actenon-permit` | PyPI `actenon-permit`, npm `@actenon/sdk` | Runtime authority broker, HMAC/Ed25519 grant compilation, UCAN-style attenuated sub-agent delegation, atomic budget and effect reservation, server-side secret resolution, and provider adapters. |
| **Tier 4** | `Actenon/actenon-airlock` | `actenon-airlock` | Pre-merge authority diffing, protected container runner for coding agents, and hash-chained Ed25519 receipt journals (`actenon-airlock/receipt/v1`). |

---

## 2. Canonicalization & Cryptographic Profiles

1. **Strict Wire Canonicalization (`ACTENON-JCS-STRICT-1`)**
   - Defined in `actenon-protocol` (`actenon_protocol.canonical`).
   - Enforces RFC 8785 / JCS key ordering and compact UTF-8 JSON serialization while **rejecting all floating-point numbers** (`float`), `NaN`/`Infinity`, duplicate object keys, non-NFC Unicode strings, integers outside IEEE 754 safe bounds (`[-9007199254740991, 9007199254740991]`), and payloads exceeding depth (`64`) or size (`1 MiB`) limits.
   - Monetary amounts and quantities in `ActionIntent.action.parameters` must be represented as integer minor units (e.g., `amount_minor: 2500`) or strings.
   - Note: `actenon-airlock` maintains a distinct internal canonicalizer (`actenon_airlock.common.canonical`) for its local receipt journal (`actenon-airlock/receipt/v1`) and authority manifests (`actenon-airlock/authority/v1`).

2. **Authoritative Effect Profile (`ACTENON-EFFECT-1`)**
   - Defined in `actenon-protocol` (`actenon_protocol.effects`) and enforced at the edge by `actenon.execution.effects.EffectProtector`.
   - Binds each consequential side effect to an `effect_id`, `reservation_id`, and `owner_attempt_id`.
   - Post-dispatch crashes, network timeouts, or reconciliation conflicts transition the effect reservation to `OUTCOME_UNKNOWN` (`AMBIGUOUS`) and **never automatically release or refund** the reservation until out-of-band reconciliation settles it.

---

## 3. End-to-End Execution Lifecycle

```
┌──────────────────┐     1. Discover capabilities      ┌──────────────────────┐
│   actenon-scan   │ ────────────────────────────────► │   actenon-airlock    │
│  (Static AST)    │     (RESOLVED vs HEURISTIC)       │ (Pre-merge & Ledger) │
└──────────────────┘                                   └──────────────────────┘
                                                                  │
                                                       2. Policy / Grants
                                                                  ▼
┌──────────────────┐     3. Request execution          ┌──────────────────────┐
│   AI Agent /     │ ────────────────────────────────► │    actenon-permit    │
│   Application    │     (Typed parameters, no keys)   │  (Authority Broker)  │
└──────────────────┘                                   └──────────────────────┘
                                                                  │
                                                       4. Reserve budget/effect
                                                          & mint Ed25519 PCCB
                                                                  │
                                                                  ▼
┌──────────────────┐     5. Verify PCCB, claim nonce   ┌──────────────────────┐
│ External / Local │ ◄──────────────────────────────── │    actenon-kernel    │
│ Resource Edge    │     & effect, resolve secret      │  (Edge Verifier)     │
└──────────────────┘                                   └──────────────────────┘
```

1. **Discovery (`actenon-scan`):** Scans source repositories for consequential operations (`stripe.Refund.create`, `requests.post`, `subprocess.run`, SQL mutations, filesystem writes) without widening dynamic unknowns to `*`.
2. **Authorization & Reservation (`actenon-permit`):** Evaluates capability grants, spend caps, rate limits, and approval requirements; reserves budget and effect ownership atomically; and mints a single-use `PCCB` proof bound to the canonical `ActionIntent` hash (`sha256_hex`).
3. **Edge Verification (`actenon-kernel`, `sdk-go`, `sdk-rust`):** Verifies the `PCCB` signature, expiration, audience, trusted edge `scope_capabilities`, parameter constraints, single-use replay claim, and `ACTENON-EFFECT-1` ownership before any side effect or secret resolution occurs.
4. **Execution & Reconciliation (`actenon-permit` / `actenon-airlock`):** Dispatches the action using server-side credentials, records a signed `Receipt` or `Refusal`, and preserves `OUTCOME_UNKNOWN` on post-dispatch uncertainty.

---

## 4. Integration Entrypoints

### Kernel Edge Gate (`actenon-kernel`)

```python
from actenon.gate import ActenonGate

gate = ActenonGate.local_dev(
    audience="service:refund-service",
    capabilities=("payment.refund",),
)

intent = gate.build_action(
    name="payment.refund",
    capability="payment.refund",
    parameters={"charge_id": "ch_101", "amount_minor": 2500, "currency": "USD"},
    target_type="charge",
    target_id="ch_101",
)
proof = gate.mint_proof(intent)

outcome = gate.protect(
    intent,
    proof,
    lambda: {"status": "refunded", "charge_id": "ch_101"},
)
assert outcome.ok
```

### Resource Boundary Verifier (`actenon-kernel`)

```python
from actenon.boundary import BoundaryVerificationRequest, BoundaryVerifier
from actenon.proof import PCCBVerifier

verifier = BoundaryVerifier(
    pccb_verifier=PCCBVerifier(public_key_verifier),
    replay_store=sqlite_replay_store,
    scope_capabilities=("payment.release",),
)
result = verifier.verify_boundary(
    BoundaryVerificationRequest(
        proof_token=token,
        action_type="payment.release",
        action_hash=expected_hash,
        audience="service:payment-release-endpoint",
        target="payment_001",
        intent=intent_payload,
        scope_capabilities=("payment.release",),
    )
)
```

### Permit Broker & Kernel Bridge (`actenon-permit`)

```python
from actenon_permit import Actenon
from actenon_permit.kernel_bridge import verify_pccb_with_kernel
```

`actenon-permit` delegates PCCB minting and verification to `actenon-kernel` via `actenon_permit.kernel_bridge`, ensuring a single cryptographic implementation of `ACTENON-JCS-STRICT-1` and `PCCBVerifier` across Python broker and edge deployments.
