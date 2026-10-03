# Full ecosystem E2E — CANDIDATE-ARTIFACT PASS (rehearsal 3)

**Result: 25/25 with SQLite replay, and 25/25 with replay on a real PostgreSQL 16.14 server.**
Evidence: `e2e/runs/rehearsal-3-final/` (`e2e-sqlite.txt`, `e2e-postgres.txt`, `driver.log`). Two harness attempts
before the final run are preserved and classified in `e2e/runs/HARNESS-ATTEMPTS.md`.

## What runs
Every component is installed from the rehearsal-3 artefacts by its normal package manager, the same way as
FRESH-CONSUMER.md, under `env -i` with fresh caches:

| Role | Artefact | Process |
|---|---|---|
| Authority: policy, grant, signed authority | `actenon-permit` 2.0.0 wheel, Ed25519 proof key (`authority.py`) | one process per mint/revoke |
| Python protected edge: gate, single use, execution, receipt | `actenon-kernel[postgres]` 1.3.0 wheel, `ActenonGate` (`edge.py`) | separate processes are separate workers; restarts are new processes |
| TypeScript edge | `@actenon/verifier-sdk` 0.2.0 (`verifyJSON` + `Ed25519Verifier`) | `ts_edge.mjs` |
| Go edge | `github.com/Actenon/sdk-go` v1.1.0 (`VerifyJSON`, `WithRevocationChecker`) | `e2e/go_edge` |
| Rust edge | `actenon-verifier-sdk` 0.2.0 (`verify_json`, `with_revocation_checker`) | `e2e/rust_edge` |
| Replay store | SQLite file shared by the workers, **or** `PostgresReplayStore` on PostgreSQL 16 | |
| Revocation source | Permit's state store, read by each edge (Python: `StoreRevocationChecker`; TS/Go/Rust: the same parent-chain walk, read-only) | |

The scenario script is phase 2's `run_e2e.sh`, transformed mechanically. Every check it made on the
TypeScript edge is now made on the TypeScript, Go **and** Rust edges, with identical arguments. All three
must match: 14 three-edge sites per run, and each run printed 14 `ts`, 14 `go` and 14 `rust` result lines,
with empty stderr.

## Scenarios (identical expectations to phase 2)
- **Policy / grant / authority.** E0: a glob-scoped grant (`payments.*`) yields an exact-capability proof that
  verifies at every edge. E1: the happy path executes once and writes a Receipt (`receipt-E1.json`); TS, Go and
  Rust verify the same proof.
- **Replay / single use.** E2: a second worker and a restarted worker each get `DUPLICATE_REPLAY`, with 1 side
  effect. E3: 16 concurrent presentations in one worker plus 4 in another give 1 side effect. After the
  PostgreSQL run, `action_consumption` holds exactly 4 `consumed` rows, one per proof that should execute (E0,
  E1, E3, E5d).
- **Edge binding, protocol 13.** E4: wrong audience. E5: parameter mutated after minting. E5b: the edge
  declares another capability. E5c: the edge relies on a constraint the proof was not issued under. E5d: a
  non-matching selector refuses and a matching one executes. All refuse at all four edges with the same codes
  (`AUDIENCE_MISMATCH`, `ACTION_MISMATCH`, `SCOPE_CAPABILITY_MISMATCH`, `PARAMETER_MISMATCH`,
  `TARGET_MISMATCH`).
- **Forgery / expiry.** E6: the attacker's Ed25519 key with the issuer's kid. E6b: the public development HMAC
  secret. E7: expired. All refused (`SIGNATURE_INVALID` / `PROOF_EXPIRED`) everywhere.
- **Revocation, E5.** E8a: Permit refuses to mint for a revoked grant. E8b: grant revoked after minting. E8c:
  the parent of a delegated grant revoked. E8d: an edge with no revocation source. E8e: a revocation source
  that does not know the grant. All refused with `AUTHORITY_REVOKED` at all four edges: fail closed.
- **Production configuration.** E9 / E9b / E9c: no replay store (including no PostgreSQL DSN), or no declared
  capabilities. The edge refuses to start, with 0 side effects. E10a–e: no, wrong or invalid signing
  configuration means nothing is minted, and a verifier rooted in the public development secret is refused.

## Scope
This is a *candidate-artefact* run. The same driver runs against the published artefacts after release
(RELEASE-GRAPH.md step 6). PostgreSQL ran on a local PostgreSQL 16 cluster. The kernel's CI job
`Replay store on PostgreSQL 16` runs the real-server tests on every PR, including the concurrent cold-start
regression (actenon-kernel 38dd580).
