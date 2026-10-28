# Actenon System Architecture

> **This file is identical in all three repos:** `actenon-kernel`, `actenon-permit`, `actenon-cloud`.
> If you're reading it in one repo and want the canonical version, it lives at the same path in all three.
> Changes require a cross-repo PR (see §7 — Governance).

## 1. The three repos, one sentence each

| Repo | One-sentence job | Trust role | Depends on |
|---|---|---|---|
| **actenon-kernel** | The open **verifier + spec + conformance authority**. Source of truth for the PCCB, the receipt, the action-hash, and the canonicalization profile. | The **anchor**. Verifies proofs; issues nothing; enforces nothing. | Nobody. Zero runtime deps. |
| **actenon-permit** | The open **on-ramp**: developer-first issuer + PDP + the real **execution/broker layer** (the PEP that releases credentials). Self-hostable, free. | The **edge + on-ramp**. Issues PCCBs (via kernel code), enforces at the edge, releases credentials through a real broker. | `actenon-kernel` (runtime). |
| **actenon-cloud** | The **managed control plane**: the same issuance/policy/approval/evidence, operated for you, multi-tenant, with the commercial surface. | The **operator surface**. Calls permit's spine (or the same kernel spine permit calls), adds tenancy + governance + transparency log. | `actenon-kernel` (runtime) + `actenon-permit` (runtime, for the broker). |

**The one decision this table forces:** permit is not a separate product from cloud. It is the open core of it. Permit issues PCCBs and enforces via the kernel; cloud is the managed, multi-tenant version of the same spine plus operator tooling. That makes permit the top-of-funnel for the whole stack and gives cloud the real broker it's currently faking.

## 2. Which one do I use?

```
                ┌─────────────────────────────────────────────────────┐
                │            "I want to..."                            │
                └─────────────────────────────────────────────────────┘
                              │                    │
              ┌───────────────┘                    └───────────────┐
              ▼                                                    ▼
   "build an agent / tool              "run a managed control plane for many
    and guard its calls locally"        tenants with approvals + evidence"
              │                                                    │
              ▼                                                    ▼
   ┌─────────────────────┐                            ┌─────────────────────┐
   │ actenon-permit      │                            │ actenon-cloud       │
   │                     │                            │                     │
   │ • issue grants      │                            │ • hosted tenants    │
   │ • decide() at edge  │                            │ • approvals/evidence│
   │ • broker releases   │                            │ • transparency log  │
   │   the real cred     │                            │ • operator UI       │
   │ • MCP + TS SDK      │                            │                     │
   └─────────┬───────────┘                            └─────────┬───────────┘
             │                                                  │
             │              both call the same spine            │
             └──────────────────┬───────────────────────────────┘
                                ▼
                   ┌─────────────────────────┐
                   │   actenon-kernel        │
                   │                         │
                   │   • PCCB builder        │
                   │   • receipt verifier    │
                   │   • action-hash         │
                   │   • canonicalization    │
                   │   • conformance suite   │
                   └─────────────────────────┘
```

- **Building an agent or tool?** Use `actenon-permit`. Self-host the gateway, register your tools, issue a grant, mint a token. Free, open, runs from a cold clone in one command.
- **Operating a control plane for multiple teams?** Use `actenon-cloud`. It hosts the same spine, adds tenancy/approvals/evidence/transparency log, and is the commercial surface.
- **Implementing a verifier in another language?** Use `actenon-kernel`'s conformance vectors. They're hash-locked, versioned, and the source of truth for what "a valid PCCB" means.

## 3. The single artifact spine (the thing they all speak)

Every consequential action in the system flows through **one artifact**: a **PCCB** (Proof of Constrained Capability Bound), built and signed via `actenon-kernel` code.

```
   agent proposes action
            │
            ▼
   ┌─────────────────────────────────────────────────────────┐
   │  CONTROL PLANE (permit self-host  OR  cloud managed)    │
   │                                                         │
   │  1. evaluate policy + approval  →  ALLOW / DENY         │
   │  2. on ALLOW: build a PCCB via kernel code              │
   │     • bound to the EXACT action (target, amount,        │
   │       tenant, subject, expiry, replay key)              │
   │     • signed (dev: local HMAC; prod: KMS/HSM)           │
   │  3. return the PCCB to the agent                        │
   └─────────────────────────┬───────────────────────────────┘
                             │  agent presents PCCB at the edge
                             ▼
   ┌─────────────────────────────────────────────────────────┐
   │  EXECUTION EDGE (permit gateway / MCP PEP)              │
   │                                                         │
   │  4. kernel verifies the PCCB:                           │
   │     • signature valid?                                  │
   │     • intent matches the exact action being attempted?  │
   │     • not expired?  not replayed?  correct audience?    │
   │  5. on verify: broker swaps PCCB → real credential     │
   │     for ONE call; secret never enters agent memory      │
   │  6. emit a signed receipt → transparency log            │
   └─────────────────────────────────────────────────────────┘
```

**The invariant that makes this work:** the PCCB is built and signed by **kernel code**, not by parallel implementations. Cloud and permit both call `actenon_kernel.proof.service.PCCBMinter.mint(...)` (or a thin wrapper). Neither mirrors the kernel's data structures. Neither rolls its own canonicalization. The kernel's `actenon-jcs-sha256-v1` profile is the only canonicalization in the system.

This is the single decision that kills the current divergence: **one artifact, one builder, one verifier, one canonicalization.**

## 4. What each repo owns (and does NOT own)

### actenon-kernel owns
- The PCCB data model + `unsigned_payload()` + `PCCBMinter.mint()` + `PCCBVerifier.verify()`
- The receipt data model + `verify_receipt_attestation()`
- The action-hash input builder (`build_action_hash_input`)
- The canonicalization profile (`actenon-jcs-sha256-v1`, in `actenon.proof.canonical`)
- The conformance suite (`conformance/` — hash-locked, versioned, multi-SDK)
- Asymmetric signing adapters (Ed25519, RSA, KMS/HSM/ExternalManaged protocols)
- The production guardrails (hard-reject dev-HMAC in production envs)

### actenon-kernel does NOT own
- Policy evaluation (that's permit/cloud)
- Credential storage or release (that's permit's broker)
- Tenancy, approvals UI, transparency log storage (that's cloud)
- Any network surface (it's a library, not a service)

### actenon-permit owns
- The developer-facing CLI (`permit issue`, `permit demo`, `permit serve --with-gateway`, etc.)
- The PDP (deterministic, fail-closed decision engine)
- The in-process + out-of-process PEP (`@guard` decorator, MCP stdio gateway, HTTP proxy)
- The **real credential broker** (resolves by name from env, never returns secret to agent, reconciles cost)
- The v1 grant token wire format (will become a PCCB wrapper — see §5)
- Grant attenuation (UCAN-style strict weakening)
- The TS SDK

### actenon-permit does NOT own
- The PCCB data model or verifier (that's kernel — permit calls it)
- The conformance vectors (that's kernel)
- Multi-tenancy, hosted governance, transparency log (that's cloud)

### actenon-cloud owns
- The hosted control plane (FastAPI app, Dockerfile, docker-compose, Alembic migrations)
- Multi-tenancy: tenants, actors, row-level isolation, per-tenant key separation
- The approval workflow + evidence store + transparency log
- The operator UI (pilot_ui)
- The commercial surface (pilot docs, design partner program, billing hooks)
- The managed signing path (KMS/HSM integration via kernel adapters)

### actenon-cloud does NOT own
- The PCCB builder or verifier (that's kernel — cloud calls it)
- The credential broker (that's permit — cloud calls it, or embeds it)
- A parallel canonicalization (deleted — uses kernel's)
- A parallel `IssuedProof` format (deleted — uses PCCB)

## 5. The migration: from two issuers to one spine

This is the honest current-state → target-state delta. Each row is a code change, not a doc change.

| Component | Current state (verified in code) | Target state (Phase 1) |
|---|---|---|
| Cloud proof signing | `app/services/signing.py:285` — stdlib HMAC-SHA256 over `sort_keys` JSON, key from `dev_signing_secret` | Calls `PCCBMinter.mint()` from kernel; signs with kernel's canonicalization; production uses kernel's `[asymmetric]` adapters |
| Cloud proof artifact | `app/models/issuance.py:IssuedProof` (SQLAlchemy ORM model, local shape) | `IssuedProof` becomes a DB record that **references** a kernel `PCCB` (stores its hash + the signed bytes); the PCCB itself is built by kernel code |
| Cloud `export_kernel_pccb` | Does not exist | Exists; returns a real `actenon_kernel.models.contracts.PCCB` built via `PCCBMinter.mint` |
| Cloud canonicalization | `signing.py:58` naive `sort_keys` (proof path) + `rfc8785` (countersignature path) | Single: kernel's `actenon-jcs-sha256-v1` everywhere |
| Permit token | `v1.<base64url(HMAC-SHA256 grant)>` — self-contained, not a PCCB | `v1.<base64url(PCCB)>` — the token IS a kernel PCCB; permit's `Grant` becomes the policy input to `PCCBMinter.mint`, not the signed artifact itself |
| Permit ↔ kernel | Zero imports | `from actenon_kernel.proof.service import PCCBMinter, PCCBVerifier` in permit's PDP/gateway |
| Cloud ↔ kernel | Dev-only dep, test-only imports | Runtime dep; `import actenon_kernel` in `issuance.py` and `signing.py` |
| Cloud ↔ permit | Zero imports | Cloud calls permit's broker (or embeds it) for capability release — replaces `development_simulated` |

**What does NOT change:**
- Permit's broker (already real — env resolution, real call, cost reconciliation)
- Permit's PDP (deterministic, fail-closed — stays as-is)
- Permit's attenuation (UCAN-style — stays as-is)
- Kernel's conformance suite (already the source of truth — stays as-is)
- Cloud's tenancy/approvals/evidence/transparency log (stays as-is — they're the operator surface)

## 6. The compatibility guarantee (the thing that keeps the three honest)

Three repos evolving independently will drift. The only cure is machine-enforced compatibility.

1. **Kernel publishes versioned conformance vectors** (already exists: `conformance/suite.json` + `conformance/vectors/`). Each spec version gets a released, hash-locked vector pack.
2. **Permit and cloud each run a CI job** that pulls the kernel's published vectors and runs them against their own issuance/verification. A mismatch fails the build.
3. **SemVer + dual-support windows** on the canonicalization/PCCB/receipt contracts (kernel's `VERSIONING_POLICY.md` already mandates this; wire it to CI). Bumping the profile requires vectors for both versions before either repo can drop the old one.
4. **Nightly live-compat workflow**: each of permit/cloud verifies against the *current* kernel `main`, so drift is caught in a day, not at a customer.

**The gate:** merging a breaking change to a shared artifact in any repo turns the other two repos' CI red automatically. Until that's true, "work flawlessly together" is a hope, not a property.

## 7. Governance

- **This file** (`ARCHITECTURE.md`) is identical in all three repos. A change to it requires opening the same PR in all three within the same week; the PRs cross-reference each other.
- **The wire contracts** (PCCB shape, receipt shape, canonicalization profile, action-hash input) live in `actenon-kernel` under `spec/` and `conformance/`. The other two repos pin to a released kernel version and run the conformance suite in CI.
- **The conformance suite** is the court of last resort. If permit and cloud disagree on whether a PCCB is valid, the kernel's `PCCBVerifier.verify()` decides. There is no appeal.

## 8. What this architecture is NOT

- **Not a monorepo.** Three repos, three release cycles, three licenses (kernel and permit are Apache-2.0; cloud's license is its own). The spine is a shared library + conformance pack, not a shared codebase.
- **Not cloud-vs-permit competition.** Cloud is permit's capabilities hosted and governed. If you can run permit, you can run the same spine cloud runs. Cloud sells the operation, not a different mechanism.
- **Not "kernel does everything."** The kernel is a library, not a service. It has no network surface, no state, no policy. It only builds and verifies artifacts. All the interesting system behavior (policy, approvals, brokering, tenancy) lives in permit and cloud.

---

## Appendix: the verified current-state reference matrix

This is the code-level reality as of the audit on 2026-07-09. It's included here so the migration in §5 is grounded in evidence, not aspiration.

| Wire | Status | Evidence |
|---|---|---|
| permit → kernel | **none** | Zero `kernel`/`PCCB`/`actenon_kernel` matches in permit's `src/` |
| permit → cloud | **none** | Zero `cloud`/`actenon_cloud` matches in permit; cloud's `permit` hits are all the English verb |
| cloud → kernel | **dev-only dep, test-only imports** | `cloud/pyproject.toml:25` pins `actenon-kernel[asymmetric]` as a dev dep; `import actenon` only in `tests/integration/` |
| cloud → permit | **none** | Zero references either direction |
| cloud proof signing | **dev-HS256 HMAC over `sort_keys` JSON** | `cloud/app/services/signing.py:58` (canonical), `:285-289` (HMAC); `BLOCKERS.md:33` admits it |
| cloud capability release | **simulated** | `cloud/app/services/escrow.py:172,209,252` (`"simulated": True`); `BLOCKERS.md:44` admits it |
| cloud PCCB construction | **does not exist** | No `export_kernel_pccb` anywhere; `IssuedProof` is a local ORM model, not a kernel `PCCB` |
| permit broker | **real, in-process** | `permit/src/actenon_permit/broker.py:38-49` (env resolve), `:82` (real call), `:85` (cost reconcile) |
| permit token | **own HMAC grant, not PCCB** | `permit/src/actenon_permit/token.py:31-49`; `model.py:119-121` |
| kernel conformance suite | **real, hash-locked, multi-SDK** | `kernel/conformance/suite.json` + `kernel/actenon/conformance/test_*.py` |
| kernel asymmetric signing | **real adapters, integrator supplies backend** | `kernel/actenon/proof/signers/{external_managed,kms,hsm,well_known}.py` |
| kernel production guardrail | **hard-rejects dev-HMAC in prod** | `kernel/actenon/proof/signers/external_managed.py:147-176`; `local.py:62-68` |
