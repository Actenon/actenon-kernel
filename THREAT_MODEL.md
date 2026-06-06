# Threat Model

Status: auditor-readable threat model for the open Actenon kernel and its
documented deployment architecture. This is not a hosted-service threat model
and is not a third-party audit attestation.

## Purpose

Actenon protects the execution boundary for consequential AI actions. The core
security objective is narrow and deliberate:

> Prompt injection can make the agent want to act; it cannot make the action execute without valid proof.

That statement is true only when the consequential action is routed through a
Protected Endpoint or equivalent enforcement boundary that verifies proof,
checks replay/escrow state where required, brokers credentials after approval,
and emits Receipt/Refusal artifacts.

## Security Objectives

When integrated correctly, the open kernel is designed to make these properties
true:

- a consequential action executes only after the Protected Endpoint verifies a
  valid PCCB bound to the exact Action Intent being attempted
- proof minted for one tenant, subject/requester, audience, action, target, or
  scope is refused when replayed or substituted for another
- stale, premature, revoked, already-consumed, or replayed execution attempts
  are refused before side effects when the protected path enforces replay and
  escrow
- production agents do not need standing credentials for consequential systems
- allowed and refused decisions leave structured Receipt/Refusal artifacts
- optional outcome attestations and local external anchors can improve copied
  artifact origin, integrity, and durability properties without changing the
  v1 Receipt/Refusal semantics

## Assets

Asset inventory: proofs/PCCBs; receipts/refusals/VARs; issuer signing keys;
well-known key discovery docs; evidence store; escrow/replay state; credential
broker authority; audit logs; external anchors; tenant data.

| Asset | Why it matters | Primary protection |
|---|---|---|
| Proofs / PCCBs | Authorize exact protected execution. | Canonical signing, issuer trust, key lifecycle, audience/action binding, expiry, replay. |
| Receipts / Refusals / VARs | Audit trail for allowed and blocked decisions. | Structured artifact generation, optional signed outcome attestation, storage controls, external anchors. |
| Issuer signing keys | Root of proof issuance trust. | Production KMS/HSM custody requirement, purpose separation, rotation/revocation, audit. |
| Well-known key discovery docs | Public verifier trust input. | HTTPS canonical path, no redirects, origin/path validation, key purpose/status checks, duplicate-key rejection. |
| Evidence store | Holds approval and evidence inputs. | Access control, digest/reference binding, audit retention. |
| Escrow / replay state | Enforces single-use execution. | Atomic claim/consume, durability, expiry/revocation checks, shared production store. |
| Credential broker authority | Releases scoped authority to target systems. | Broker-after-proof ordering, no raw secret artifacts, short-lived scoped credentials. |
| Audit logs | Support investigation and accountability. | Tamper-resistant storage, access controls, redaction, operation metadata. |
| External anchors | Preserve existence evidence outside signed payload. | Local append-only verification; future hosted transparency remains separate. |
| Tenant data | May appear in intents, evidence, audit records, receipts, and control-plane state. | Tenant binding, storage isolation, least privilege, redaction/minimization. |

## Trust Boundaries

| Boundary | Trust posture | Security role |
|---|---|---|
| Untrusted agent | Untrusted | May request an action; must not directly hold production authority for consequential systems. |
| Agent process / SDK | Convenience only | Builds requests and may call Preflight; not the enforcement boundary if it runs with the agent. |
| Protected Endpoint | Enforcement boundary | Verifies proof, policy, replay/escrow, credentials, and emits Receipt/Refusal before side effects. |
| Issuer / control plane | Proof root | Decides whether proof may exist and protects signing keys. |
| Key discovery | Verification trust input | Publishes public keys, purposes, algorithms, and lifecycle state. |
| Credential Broker | Authority boundary | Releases short-lived scoped authority only after protected checks pass. |
| Evidence / audit store | Audit boundary | Stores approvals, evidence, mint audit records, receipts, refusals, replay/escrow transitions. |
| External anchor / transparency log | Durability layer | Local anchors exist; hosted transparency/network durability is future unless separately implemented. |

The Protected Endpoint is the trust boundary that matters for runtime
enforcement. SDK-only or Preflight-only deployment is advisory, not enforcement.

## Assumptions

- The verifier is configured with the correct issuer origin and verification
  policy.
- Consequential actions are routed through a Protected Endpoint or equivalent
  enforcement boundary.
- Production agents do not retain raw provider credentials, database URLs,
  browser session cookies, or long-lived API tokens for consequential systems.
- Replay and escrow stores are atomic and shared by every worker that can
  execute the same protected route.
- System clocks are accurate enough for `not_before` and `expires_at`
  enforcement, with explicit and small skew tolerance when configured.
- Issuer signing custody is appropriate for the deployment; local HMAC and
  pilot-local EdDSA are not production custody.
- Adapters and credential brokers are part of the trusted computing base for
  the side effects they perform.

## Attacker Classes And Attack Paths

Attacker classes covered: prompt injection, compromised agent, replay attacker,
TOCTOU attacker, key substitution attacker, SSRF attacker, policy-bypass
attacker, rogue employee/insider, compromised API key, malicious SaaS
integration, issuer compromise, scanner target adversary, supply-chain
attacker.

| Attacker class | Attack path | What Actenon must prevent | What Actenon cannot prevent | Mitigation status | Residual risk | Relevant tests/docs |
|---|---|---|---|---|---|---|
| Prompt injection | Malicious prompt causes model to call a destructive tool. | Execution without a valid proof bound to the exact action. | The model attempting the action or generating harmful arguments. | Protected Endpoint doctrine implemented; scanner maps ungated paths. | Bypass remains if tool has direct credentials or skips protected endpoint. | `tests/unit/test_protected_executor.py`, `tests/unit/test_scanner_universal.py`, `docs/architecture/TRUST_BOUNDARIES.md` |
| Compromised agent | Agent process is modified to skip SDK checks or call provider directly. | Direct execution through protected path without proof. | Direct side-door execution if standing credentials remain in agent runtime. | Credential-broker doctrine and scanner signals added. | Customer deployment must remove direct credentials. | `tests/unit/test_credential_broker.py`, `docs/architecture/BYPASS_RESISTANCE.md` |
| Replay attacker | Same proof or nonce is submitted concurrently or repeatedly. | Duplicate active execution when replay protection is configured. | Routes that do not enforce replay state. | Kernel replay concurrency tests pass; Cloud active proof issuance collapses concurrent requests to one issued proof in the SQLite test harness; PostgreSQL replay abstraction exists. | Multi-node escrow needs a shared transactional backend validated under production isolation. | `tests/security/test_replay_escrow_attacks.py`, `tests/unit/test_replay_store.py`, `Actenon Cloud Control Layer/tests/integration/test_replay_escrow_atomicity.py`, `docs/cloud/REPLAY_ESCROW_ATOMICITY.md` |
| TOCTOU attacker | Races proof verification, escrow consumption, broker acquisition, or handler failure. | Broker before proof/escrow, duplicate consume, or retry after ambiguity boundary. | External provider finality ambiguity after authority may have been used. | ProtectedExecutor ordering, broker-failure ambiguity, kernel SQLite escrow, and Cloud escrow consume concurrency tests pass. | Reconciliation and downstream provider finality remain deployment/provider responsibilities. | `tests/unit/test_protected_executor.py`, `tests/unit/test_sqlite_escrow.py`, `Actenon Cloud Control Layer/tests/integration/test_replay_escrow_atomicity.py`, `docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md` |
| Key substitution attacker | Supplies wrong `kid`, algorithm, issuer, purpose, or weak key. | Signature confusion and key-purpose mismatch. | A verifier configured to trust the wrong issuer origin. | Algorithm confusion, lifecycle, RSA strength, duplicate key-id tests exist. | Operational configuration risk remains. | `tests/security/test_signature_attacks.py`, `tests/security/test_key_lifecycle_attacks.py`, `tests/unit/test_well_known_key_resolver.py` |
| SSRF attacker | Abuses well-known discovery redirects or private network targets. | Default resolver fetching internal/private/metadata destinations. | Unsafe custom fetchers supplied by host app. | Default resolver disables redirects and validates URL/origin/IP safety. | DNS and network perimeter controls still matter. | `tests/security/test_well_known_resolver_attacks.py` |
| Policy-bypass attacker | Uses stale approval, wrong evidence, over-broad scope, or unbound parameters. | Execution when proof does not match exact action/audience/scope. | Business correctness of an action the issuer deliberately signed. | Binding and policy-refusal tests exist; exact local evidence shapes are documented. | Issuer/control-plane policy quality remains critical. | `tests/security/test_replay_escrow_attacks.py`, `tests/unit/test_preflight.py`, `docs/guides/PREFLIGHT_EVIDENCE.md` |
| Rogue employee / insider | Operator mints proof improperly or changes policy/key lifecycle. | Edge execution with invalid, expired, wrong-audience, or revoked proof. | Malicious issuer with valid signing authority. | Mint audit model and signing custody plan documented. | Requires production IAM, separation of duties, monitoring, and audit review. | `docs/architecture/ISSUER_SECURITY_MODEL.md`, `docs/architecture/PRODUCTION_SIGNING_CUSTODY.md` |
| Compromised API key | Agent or tool has raw production credential and bypasses Actenon. | Credential use through protected endpoint without proof. | Side-door calls using the raw credential outside Actenon. | Credential-broker doctrine and scanner bypass signals exist. | Strong claim requires credential removal or technical blocking. | `tests/unit/test_scanner_universal.py`, `docs/architecture/BYPASS_RESISTANCE.md` |
| Malicious SaaS integration | Provider SDK or adapter lies, leaks, or performs unexpected side effects. | Proofless entry to adapter and raw secret leakage in artifacts. | Provider compromise, adapter dishonesty, downstream finality. | Secret redaction tests and broker hygiene docs exist. | Third-party broker/adapter audits remain deployment responsibility. | `tests/security/test_secret_redaction_attacks.py`, `docs/guides/CREDENTIAL_BROKER_DEPLOYMENT.md` |
| Issuer compromise | Compromised issuer signs bad-but-valid proof. | Execution of proof that fails local binding/lifecycle checks. | A valid proof for a bad business decision from a trusted issuer. | Custody, lifecycle, audit, and external-anchor recovery docs exist. | Production KMS/HSM custody is a required deployment control. | `tests/unit/test_production_signing_custody.py`, `docs/operations/KEY_LIFECYCLE_RUNBOOK.md` |
| Scanner target adversary | Repo under scan tries ReDoS, secret exfiltration, code execution, or misleading reports. | Scanner importing/executing target code or leaking secret-like values. | Perfect classification of every hostile repo statically. | Scanner security tests and cautious report language exist. | Static scanning remains advisory and may need manual review. | `tests/security/test_scanner_security.py`, `docs/guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md` |
| Supply-chain attacker | Dependency, SDK, build, or release artifact is modified. | Verification accepting malformed artifacts or ambiguous JSON. | Compromise of developer workstation, package registry, or CI secrets. | Duplicate JSON, canonicalization, parser hardening, release-boundary checks exist. | Independent supply-chain controls and signed releases are still needed. | `tests/security/test_json_parsing_attacks.py`, `tests/security/test_canonicalization_attacks.py`, `scripts/verify_release_gate.sh` |

## Top Technical Risks

Severity describes consequence to Actenon’s security model if the risk is
present in a real deployment. It is not a claim that a vulnerability is proven.

| Risk | Severity | Exploitability | Impact | Current mitigation | Required fix / owner | Existential? |
|---|---|---|---|---|---|---|
| No production KMS/HSM custody yet | High | Medium in production if local/pilot signing is misused | Compromised or exportable signing keys can mint valid proof. | External-managed seam and production guard docs/tests. | Operate non-exportable asymmetric custody before production proof issuance. | Yes for production trust. |
| SSRF redirects in key fetcher | Medium | Medium if unsafe fetcher follows redirects | Internal network probing or metadata fetch. | Default fetcher does not follow redirects and validates HTTPS/origin/path/private IP. | Preserve policy in custom fetchers and deployment network egress controls. | No. |
| Local HMAC secret production footgun | High | Low after guard, high if bypassed | Anyone with public dev secret could forge local-mode proof. | Production guard and warnings; docs say dev/demo only. | Never enable local HMAC in production. | Yes if misused. |
| Replay/escrow TOCTOU | High | Medium under concurrent execution | Same proof/capability might execute twice. | Atomic kernel SQLite tests, Cloud active proof issuance/escrow consume concurrency tests, replay abstraction, ordering docs. | Shared transactional stores for every worker; production Postgres/RLS isolation and any custom escrow backend must be validated under concurrency. | Yes for single-use claims. |
| Issuer compromise | Critical | Depends on custody/IAM | Bad-but-valid proofs can be minted. | Purpose separation, audit, lifecycle docs, production custody plan. | KMS/HSM, separation of duties, monitoring, emergency revoke/hard-revoke runbook. | Yes. |
| Standing agent credential bypass | Critical | High if credentials remain in agent runtime | Agent can bypass proof gate entirely. | Broker doctrine, scanner bypass signals, docs. | Remove/block standing production credentials from agents. | Yes. |
| RSA minimum key size | High | Medium with weak keys | Weak signatures may be brute-forced or downgraded. | RSA modulus/exponent enforcement tests. | Keep minimum >= 2048 bits and reject unsafe exponents. | No. |
| Duplicate JSON keys | Medium | Medium across parsers | Ambiguous verification material or artifacts. | Duplicate-key parse helper and tests. | Require rejecting duplicates in all verification entrypoints and SDKs. | No. |
| Recursion/size DoS | Medium | Medium with hostile artifacts | Resource exhaustion or unsafe parser failures. | Size/depth limits and parser tests. | Keep limits documented and enforce before canonicalization. | No. |
| Clock skew/time source | Medium | Medium in distributed systems | Premature/stale proof acceptance or false refusal. | Explicit skew tolerance tests; default zero. | Use reliable time sync and short proof windows. | No. |
| Cross-SDK canonicalization divergence | High | Medium in multi-SDK ecosystem | Proof verifies in one SDK but not another, or wrong digest accepted. | Canonicalization interop and mutation tests. | Maintain conformance vectors for every SDK. | Yes for standard credibility. |
| Handler exception secret leakage | High | Medium with provider SDK errors | Secrets/provider bodies leak into artifacts. | Redaction constants and adversarial tests. | Keep raw exception text out of public artifacts; secure log sink only under deployment control. | No. |
| Key discovery cache poisoning | High | Low/Medium depending cache | Verifier may use stale or wrong keys. | Origin/path/kid/purpose/status validation; lifecycle tests. | Cache by issuer/kid with expiry and lifecycle refresh discipline. | No. |
| Proof laundering through MCP/tool chains | High | Medium in agentic tool ecosystems | One tool’s proof may be reused to trigger another side effect. | Audience/action/scope binding; scanner MCP/tool-chain signals. | Protect every tool boundary and avoid over-broad scopes. | Yes for MCP hero path. |
| Over-broad proof scope | High | Medium if issuer signs broad capabilities | Valid proof authorizes too much. | Scope/capability binding and Preflight docs. | Tight consequence-classified policies and short-lived scoped proofs. | Yes if common. |
| Approval-gate spoofing | High | Medium if approval is not bound | Agent claims approval happened without evidence. | Docs require approval/evidence binding into proof/outcome records. | Bind approval/evidence ids/digests and verify at edge. | No. |
| Issuer outage availability | Medium | Medium operationally | Valid actions may be refused or delayed. | Fail-closed doctrine. | HA issuer/control plane and emergency operating procedures. | No, but business-critical. |
| Multi-tenant data bleed in control plane | Critical | Unknown without Cloud audit | Tenant data or proof authority crosses tenants. | Tenant binding in proof; Cloud out of OSS scope. | Cloud isolation review, tests, logging, access control. | Yes for hosted Cloud. |
| Dependency/supply-chain compromise | High | Medium | Malicious package or build changes verifier behavior. | Release gate, conformance, Apache-2.0 boundary docs. | Signed releases, dependency pinning/review, CI hardening. | No. |
| Scanner ReDoS/hostile repo | Medium | Medium | Scanner hangs or leaks target secrets into report. | Scanner security tests, exclusions, timeouts, redaction. | Continue hostile-repo fuzzing and report redaction review. | No. |
| Fail-open misconfiguration | Critical | Medium | Consequential action executes when proof/key/state missing. | Fail-closed architecture docs and tests. | Make protected endpoints refuse by default and monitor bypasses. | Yes. |
| Insufficient tamper-evidence without external anchor | Medium | Medium after hard key compromise | Historical artifacts may be disputed. | Local external anchors and hard-revoke recovery docs/tests. | Use independent anchors/transparency for high-value artifacts. | No, unless durability is core requirement. |
| Client-side-only enforcement | Critical | High if deployed that way | Agent can skip SDK/Preflight checks. | Trust-boundary doctrine states SDK/Preflight are not enforcement. | Route side effects through Protected Endpoint. | Yes. |
| No formal external audit yet | Medium | Certain | Security posture lacks independent validation. | Local adversarial tests and findings register. | Commission third-party audit before broad production claims. | No, but launch-significant. |

## What Actenon Cannot Prevent

Actenon cannot:

- stop a model from trying to act
- make a bad-but-authorized action good
- protect paths not routed through the Protected Endpoint or equivalent boundary
- save historical artifacts after hard key compromise without an external anchor
- guarantee third-party broker or adapter hygiene unless those implementations
  follow the contract and are audited
- prove downstream business finality, settlement, delivery, or provider truth
- protect production if the issuer key/control plane is compromised without
  additional mitigations
- turn SDK-only or Preflight-only integration into enforcement

## Safe Claims

- Actenon can prevent unproven consequential actions when those actions are
  routed through a Protected Endpoint or equivalent enforcement boundary.
- Actenon maps and enforces proof-bound execution boundaries; it does not claim
  generic model alignment.
- Actenon’s open kernel includes adversarial tests for signature confusion,
  canonicalization, key discovery, replay/escrow, external anchors, secret
  redaction, artifact parsing, and scanner safety.
- Scanner findings are static advisory execution-surface findings and require
  maintainer review.

## Unsafe Claims

Do not claim:

- Actenon prevents all bypass when agents still hold production credentials.
- Actenon makes business decisions correct.
- Actenon prevents every SSRF, every secret leak, or every third-party broker bug.
- Actenon Cloud uses production KMS/HSM custody unless that deployment proves it.
- Actenon is formally verified, unhackable, certified, or audit-complete.
- Scanner findings prove exploitability, runtime reachability, production
  exposure, or vulnerability.

## Related Security Documents

- [`docs/security/RISK_REGISTER.md`](docs/security/RISK_REGISTER.md)
- [`docs/security/SECURITY_TESTING.md`](docs/security/SECURITY_TESTING.md)
- [`SECURITY_AUDIT_FINDINGS.md`](SECURITY_AUDIT_FINDINGS.md)
- [`docs/architecture/TRUST_BOUNDARIES.md`](docs/architecture/TRUST_BOUNDARIES.md)
- [`docs/architecture/BYPASS_RESISTANCE.md`](docs/architecture/BYPASS_RESISTANCE.md)
- [`docs/architecture/REPLAY_ESCROW_CONCURRENCY.md`](docs/architecture/REPLAY_ESCROW_CONCURRENCY.md)
- [`docs/cloud/REPLAY_ESCROW_ATOMICITY.md`](docs/cloud/REPLAY_ESCROW_ATOMICITY.md)
- [`docs/architecture/PRODUCTION_SIGNING_CUSTODY.md`](docs/architecture/PRODUCTION_SIGNING_CUSTODY.md)
- [`docs/architecture/ISSUER_SECURITY_MODEL.md`](docs/architecture/ISSUER_SECURITY_MODEL.md)
- [`docs/guides/PREFLIGHT_EVIDENCE.md`](docs/guides/PREFLIGHT_EVIDENCE.md)
