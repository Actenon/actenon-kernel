# Mandatory effect constraints at every Python edge entry point

Four preserved attacks dispatched an unowned effect through BoundaryVerifier,
VerifierSDK, ProtectedEndpointMiddleware and PythonProtectedEndpoint. The
proofs were genuine Ed25519 PCCBs; the edge had only a public key. `before.xml`
records the four failing assertions, rather than an invalid-signature demo.

BoundaryVerifier and VerifierSDK now require an EffectProtector for signed
extensions.effect. The same independent identity recomputation and atomic
owner claim used by ProtectedExecutor applies. Configured effect edges refuse
missing references. Proof authentication, exact binding and revocation run
before claims; BoundaryVerifier also enforces proof replay before effect claim.
VerifierSDK accepts a revocation checker and can verify revocable Permit proof
without obtaining minting capability. A successful effect-aware verify call
claims ownership; callers must not claim again through another entry point.
Ordinary SDK verification remains stateless and needs an external proof replay
claim before dispatch. PCCBVerifier is cryptographic inspection, not permission
to execute or ignore stateful signed constraints.

The old escrow middleware cannot produce trusted consequence observations.
It and PythonProtectedEndpoint refuse effect-bearing proofs before escrow,
replay or handler execution. Use ActenonGate / ProtectedExecutor with the
owner's ledger hook and evidence-aware trusted handler for those effects.

Boundary verification is not execution. Its receipt helper requires matching
trusted COMMITTED / NOT_EXECUTED / AMBIGUOUS evidence and refuses contradictory
outcomes or changed receipt requests. The caller owns evidence collection,
ledger settlement, authentication and reconciliation. This helper's dictionary
is not itself a signed receipt or an independent provider observation.

Thirty new cases cover all four entry points, modified identities, forged
proof, revoked grants, unavailable ledgers, strict boolean ownership confirmation,
missing references and consequence receipt integrity. A mixed-API race uses
fresh signed proofs and independent SQLite connections; twelve attempts yield
one dispatch. This hook fixture is not Permit's production ledger and is not
cross-host evidence. Permit's real ledger integration remains in Permit #27.

Full regression: 966 passes, 5 existing documented skips, 323 subtests;
examples: 27 passes; no unexpected skips. PostgreSQL replay executes separately
in CI. This change does not claim protected OS containment, complete portable
SDK effect parity, Airlock HTTP effect integration, PostgreSQL effect ownership,
or finished-product gate PASS. No package, tag or release is published.
