# Security Testing

Status: local adversarial and conformance testing map for the open kernel. This
is not a substitute for an independent third-party audit.

## Test Philosophy

The security suite is deterministic, local, and CI-safe. It does not require
live network access. Network-sensitive tests use fake fetchers or local stores.

The suite is designed to prove kernel properties such as:

- malformed or substituted proof fails closed
- canonicalization ambiguity changes digests or is rejected
- duplicate JSON keys are invalid
- weak or wrong-purpose keys are rejected
- well-known key discovery does not follow unsafe redirects
- replay and escrow single-use state hold under local concurrency
- handler/provider exception details do not leak into public artifacts
- scanner output remains static advisory and does not execute target code

It does not prove:

- hosted Cloud production security
- production KMS/HSM custody operation
- third-party broker/adapter hygiene
- downstream provider finality
- business correctness of authorized actions
- formal verification

## Commands

Focused adversarial suite:

```bash
python3 -m unittest \
  tests.security.test_signature_attacks \
  tests.security.test_canonicalization_attacks \
  tests.security.test_well_known_resolver_attacks \
  tests.security.test_key_lifecycle_attacks \
  tests.security.test_external_anchor_attacks \
  tests.security.test_replay_escrow_attacks \
  tests.security.test_secret_redaction_attacks \
  tests.security.test_json_parsing_attacks \
  tests.security.test_scanner_safety -q
```

Focused replay/escrow and protected-executor checks:

```bash
python3 -m unittest \
  tests.security.test_replay_escrow_attacks \
  tests.unit.test_replay_store \
  tests.unit.test_sqlite_escrow \
  tests.unit.test_protected_executor -v
```

Full local kernel suite:

```bash
python3 -m unittest discover tests -q
```

When `pytest` and `ruff` are installed, maintainers may also run:

```bash
python3 -m pytest tests/ -q
python3 -m ruff check actenon tests
```

## Test Coverage Map

| Area | Tests | What they prove | Residual limitation |
|---|---|---|---|
| Signature and algorithm confusion | `tests/security/test_signature_attacks.py` | Rejects `alg:none`, wrong algorithm/key type, malformed signatures, signature mutation, weak RSA. | Does not prove signer custody. |
| Canonicalization attacks | `tests/security/test_canonicalization_attacks.py`, `tests/unit/test_canonicalization_interop.py` | Key order invariance, mutation sensitivity, float/non-string-key rejection, Unicode profile behavior. | Cross-language SDKs must keep running conformance vectors. |
| JSON parsing attacks | `tests/security/test_json_parsing_attacks.py`, `tests/unit/test_json_hardening.py` | Duplicate keys, malformed JSON, nested/oversized inputs fail closed. | New raw JSON entrypoints must use the hardened parser. |
| Well-known resolver attacks | `tests/security/test_well_known_resolver_attacks.py`, `tests/unit/test_well_known_key_resolver.py` | Redirects, private/metadata destinations, duplicate kids, lifecycle states, wrong purposes rejected. | Custom fetchers must preserve equivalent safety. |
| Key lifecycle | `tests/security/test_key_lifecycle_attacks.py`, `tests/security/test_well_known_resolver_attacks.py` | Active/retired/soft/hard revocation behavior and purpose/lifecycle boundaries. | Hosted transparency network is not implemented. |
| External anchors | `tests/security/test_external_anchor_attacks.py`, `tests/unit/test_external_anchors.py` | Anchors stay outside unsigned payload, opaque anchors do not break issuer signatures, wrong digests fail when verified, and hard-revoke recovery requires a valid configured anchor. | Hosted transparency network is not implemented. |
| Replay and escrow | `tests/security/test_replay_escrow_attacks.py`, `tests/unit/test_replay_store.py`, `tests/unit/test_sqlite_escrow.py`, `tests/unit/test_postgres_replay_store.py` | Concurrent local replay/escrow claims allow exactly one winner; consumed state persists across SQLite reopen. | Production multi-worker escrow needs a shared transactional backend. |
| Credential broker and protected execution | `tests/unit/test_protected_executor.py`, `tests/unit/test_credential_broker.py` | Broker is called only after proof/policy/replay/escrow; not called on refusal; broker failure is safe and redacted. | Third-party broker implementations still require audit. |
| Secret redaction | `tests/security/test_secret_redaction_attacks.py` | Handler/provider exception text, traceback, raw material, and brokered secrets do not appear in artifacts. | Deployment logs must also be configured safely. |
| Local HMAC guard | `tests/unit/test_local_hmac_guard.py` | Dev HMAC signer is blocked by every Actenon production flag, including when the legacy override variable is present. | Deployment wrappers must set the production signal correctly. |
| Cross-SDK verifier parity | `actenon/conformance/vectors/verifier_sdk_v1`, `scripts/verify_sdk_conformance.sh` | Python, TypeScript, Go, and Rust enforce the same binding, skew-boundary, reason-code, and public-message vectors. | New verifier features must extend the shared vectors. |
| Production signing custody seam | `tests/unit/test_production_signing_custody.py` | Production mode rejects unsafe local backends; external-managed mock signs/audits and refuses bad lifecycle/purpose. | Does not prove a live provider/KMS deployment. |
| Scanner self-safety | `tests/security/test_scanner_safety.py`, `tests/security/test_scanner_security.py`, `tests/unit/test_scanner_universal.py` | Scanner does not execute/import target code, uses cautious language, redacts secret-like evidence, maps consequential action surfaces. | Static analysis cannot prove runtime reachability or exploitability. |
| Replay middleware/conformance | `tests/conformance/test_replay_conformance.py`, `tests/integration/test_replay_middleware.py` | Duplicate execution through the protected path yields structured replay refusal. | Host apps can still bypass the protected middleware. |

## Evidence For Specific Risks

- Standing credential bypass: `tests/unit/test_scanner_universal.py`,
  `tests/unit/test_protected_executor.py`
- Fail-open misconfiguration: `tests/unit/test_protected_executor.py`,
  `tests/security/test_replay_escrow_attacks.py`
- Key substitution and lifecycle: `tests/security/test_signature_attacks.py`,
  `tests/security/test_key_lifecycle_attacks.py`
- Parser ambiguity: `tests/security/test_json_parsing_attacks.py`,
  `tests/security/test_canonicalization_attacks.py`
- SSRF/redirect hardening: `tests/security/test_well_known_resolver_attacks.py`
- External anchor durability: `tests/unit/test_external_anchors.py`

## Safe Public Claim

Actenon's open kernel includes an adversarial security test suite covering
signature confusion, canonicalization, key discovery, replay/escrow, external
anchors, secret redaction and artifact parsing. This is not a substitute for an
independent third-party audit.

## Unsafe Claims

Do not claim:

- formally verified
- unhackable
- certified audit complete
- prevents all possible SSRF
- guarantees third-party broker hygiene
- proves business correctness
- proves scanner findings are exploitable

## Related Documents

- [../../THREAT_MODEL.md](../../THREAT_MODEL.md)
- [RISK_REGISTER.md](RISK_REGISTER.md)
- [../../SECURITY_AUDIT_FINDINGS.md](../../SECURITY_AUDIT_FINDINGS.md)
