# Security Risk Register

Status: current open-kernel security findings and residual-risk register. This
document is intentionally candid. It is not a third-party audit report and does
not claim production readiness for hosted Cloud infrastructure.

Severity describes impact to the Actenon security model if the risk is present
in a deployment. Exploitability is an implementation/deployment estimate, not a
claim that exploitation has been proven.

## Register

| ID | Risk | Severity | Exploitability | Impact | Mitigation status | Required fix / next control | Existential? |
|---|---|---|---|---|---|---|---|
| R-001 | No production KMS/HSM custody yet | High | Medium in production if local/pilot signing is misused | Exportable or weakly protected signing keys can mint valid proof. | Requirements, external-managed seam, and production guard tests exist. | Operate non-exportable asymmetric KMS/HSM custody before production proof issuance. | Yes for production trust. |
| R-002 | SSRF redirects in key fetcher | Medium | Medium if redirect-following fetcher is used | Key discovery could fetch internal/private/metadata endpoints. | Default resolver rejects redirects and unsafe destinations. | Preserve resolver policy in custom fetchers and deployment network egress controls. | No. |
| R-003 | Local HMAC secret production footgun | High | Low after guard, high if bypassed | Public dev secret could forge local-mode proofs. | Production guard and warnings exist. | Never use local HMAC in production; validate backend selection. | Yes if misused. |
| R-004 | Replay/escrow TOCTOU | High | Medium under concurrency | Same proof or capability could execute twice. | SQLite and in-memory concurrency tests; replay abstraction; ordering docs. | Use storage shared by every worker; add production shared escrow backend where needed. | Yes for single-use claims. |
| R-005 | Issuer compromise | Critical | Depends on custody/IAM | Compromised issuer can mint bad-but-valid proof. | Issuer model, custody plan, lifecycle runbook, audit guidance. | KMS/HSM, separation of duties, anomaly detection, rapid suspend/revoke/hard-revoke. | Yes. |
| R-006 | Standing agent credential bypass | Critical | High if credentials remain in agent runtime | Agent can bypass proof gate entirely. | Credential-broker doctrine and scanner bypass signals. | Remove/block standing production credentials from agents. | Yes. |
| R-007 | Weak RSA keys | High | Medium if accepted | Weak signature verification trust. | RSA modulus/exponent enforcement tests. | Keep minimum 2048-bit RSA and reject unsafe exponents. | No. |
| R-008 | Duplicate JSON keys | Medium | Medium across implementations | Ambiguous parsed artifacts or key docs. | Duplicate-key parser and tests. | Reject duplicate keys in all verification paths and SDKs. | No. |
| R-009 | Recursion/size DoS | Medium | Medium with hostile artifacts | Resource exhaustion or parser crash. | Size/depth checks and tests. | Keep conservative limits and fail closed. | No. |
| R-010 | Clock skew/time source | Medium | Medium in distributed deployments | Premature/stale proof acceptance or refusal. | Clock-skew tests; default zero tolerance. | Reliable time sync, short validity windows, explicit skew policy. | No. |
| R-011 | Cross-SDK canonicalization divergence | High | Medium in multi-SDK use | Verification or digest mismatch across SDKs. | Canonicalization tests and vectors. | Maintain conformance vectors for every SDK release. | Yes for standard credibility. |
| R-012 | Handler exception secret leakage | High | Medium with provider SDK errors | Tokens/provider bodies leak into public artifacts. | Safe message constant and adversarial redaction tests. | Keep raw exception details in deployment-controlled secure logs only. | No. |
| R-013 | Key discovery cache poisoning/staleness | High | Low/Medium depending cache | Wrong or stale key lifecycle state used. | Key document validation, duplicate kid rejection, lifecycle tests. | Cache by issuer/kid with expiry and lifecycle refresh discipline. | No. |
| R-014 | Proof laundering through MCP/tool chains | High | Medium | Proof/control for one tool path used to justify another side effect. | Audience/action/scope binding and scanner MCP rules. | Protect every consequential tool boundary and avoid broad scopes. | Yes for MCP deployments. |
| R-015 | Over-broad proof scope | High | Medium | Valid proof authorizes too much. | Scope/capability binding and Preflight docs. | Consequence-classified policies, narrow scopes, short windows. | Yes if common. |
| R-016 | Approval-gate spoofing | High | Medium if approval not bound | Agent claims approval/evidence happened without enforceable proof. | Docs require evidence/approval ids or digests bound into proof/outcome records. | Edge verification of approval/evidence binding. | No. |
| R-017 | Issuer outage availability | Medium | Medium operationally | Fail-closed behavior can refuse legitimate actions. | Fail-closed doctrine. | HA issuer/control plane and emergency operating runbooks. | No, but business-critical. |
| R-018 | Multi-tenant data bleed in control plane | Critical | Medium until production datastore validation completes | Tenant data/proof authority may cross tenants. | Cloud app-layer two-tenant isolation tests cover actions, policies, approvals, evidence, receipts, audit, and usage; PostgreSQL RLS foundation and session-context unit tests exist. | Run the same matrix against live PostgreSQL/RLS, add migration gates for tenant-scoped tables, and keep platform-admin bypass auditable. | Yes for hosted Cloud. |
| R-019 | Dependency/supply-chain compromise | High | Medium | Malicious dependency or release changes verifier behavior. | Release gate, conformance, boundary hygiene docs. | Signed releases, dependency review/pinning, CI hardening. | No. |
| R-020 | Scanner ReDoS/hostile repo | Medium | Medium | Scanner may hang, misreport, or leak snippets. | Scanner timeout/exclusion/redaction tests. | Continue hostile-repo fuzzing and review report redaction. | No. |
| R-021 | Fail-open misconfiguration | Critical | Medium | Missing proof/key/state could still execute. | Fail-closed architecture docs and protected-executor tests. | Protected endpoints must refuse by default and monitor bypass paths. | Yes. |
| R-022 | Insufficient tamper-evidence without external anchor | Medium | Medium after hard key compromise | Historical artifacts may be disputed. | Local external anchor primitive and tests. | Use independent anchors/transparency for high-value artifacts. | No unless durability is core. |
| R-023 | Client-side-only enforcement | Critical | High if deployed that way | Agent can skip SDK/Preflight checks. | Trust-boundary doctrine. | Route side effects through Protected Endpoint or equivalent boundary. | Yes. |
| R-024 | No formal external audit yet | Medium | Certain | Security posture lacks independent validation. | Local adversarial tests and this register. | Commission third-party audit before broad production claims. | No, but launch-significant. |

## Mitigation Status Legend

- **Implemented**: kernel code/tests enforce the control for the covered path.
- **Documented**: architecture or operations docs define the required control.
- **Deployment required**: customer/operator must configure the control.
- **Future / external**: not implemented in the open kernel; do not claim it as
  active until implemented and verified.

## Current Highest-Risk Deployment Conditions

The highest-risk conditions are:

- agents retain standing production credentials
- side effects are not routed through a Protected Endpoint
- local HMAC or pilot-local signing is represented as production custody
- replay/escrow stores are not shared by all workers that can execute the route
- issuer keys or control-plane permissions are weakly protected
- approvals/evidence are not bound into proof or outcome records
- Cloud tenant isolation has not been validated against the production
  PostgreSQL/RLS deployment path

## Claims Discipline

Safe:

- The strong Actenon deployment removes standing agent credentials and routes
  consequential actions through a Protected Endpoint.
- Scanner output is a static advisory map of candidate action surfaces.
- The open kernel includes adversarial tests; this is not a substitute for an
  independent third-party audit.

Unsafe:

- Actenon prevents all bypass even if agents keep production credentials.
- Actenon Cloud uses production KMS/HSM custody unless the Cloud deployment
  separately proves it.
- Scanner findings prove exploitability or a confirmed vulnerability.
- A valid proof proves downstream business correctness or finality.

## Related Documents

- [../../THREAT_MODEL.md](../../THREAT_MODEL.md)
- [SECURITY_TESTING.md](SECURITY_TESTING.md)
- [../../SECURITY_AUDIT_FINDINGS.md](../../SECURITY_AUDIT_FINDINGS.md)
- [../architecture/TRUST_BOUNDARIES.md](../architecture/TRUST_BOUNDARIES.md)
- [../architecture/BYPASS_RESISTANCE.md](../architecture/BYPASS_RESISTANCE.md)
- [../architecture/PRODUCTION_SIGNING_CUSTODY.md](../architecture/PRODUCTION_SIGNING_CUSTODY.md)
- [../cloud/TENANT_ISOLATION_MODEL.md](../cloud/TENANT_ISOLATION_MODEL.md)
