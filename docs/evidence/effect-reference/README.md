# Protected effect ownership

Protocol 1.6 / wire 1.3 specifies `ACTENON-EFFECT-1`. Kernel now supports an
explicit `EffectProtector` on `ActenonGate` / `ProtectedExecutor`. Its owner
configured namespace and trusted descriptor builder recompute the effect from
the actual proof-verified action and target. Exact descriptors cannot omit or
change parameters. Semantic keys require explicit reviewed edge configuration.
The atomic claim hook verifies the signed reference's grant, principal,
execution attempt and action hash in the authority engine's durable ledger.
It must transition RESERVED to DISPATCHING only once, before credentials.
A non-True result or exception refuses; an effect-bearing proof without an
ownership verifier also refuses. Policy, proof and replay checks still apply.
Kernel does not classify agent tools, issue grants or implement budget policy.

`before.xml` captures the regression: a signed effect reference was silently
ignored and the callback executed. The fixed test refuses with zero calls.
`after.xml` exercises reference mutation, identity binding, unavailable state,
fresh-proof races and consequence certainty. The callback must return trusted
`effect_evidence` matching the reference. Missing/malformed evidence, lost
responses and exceptions after dispatch produce OUTCOME_UNKNOWN with
AMBIGUOUS evidence and an unknown side-effect state, never non-execution.
A handler return or HTTP status is not automatically a COMMITTED consequence.
Confirmed NOT_EXECUTED evidence is distinct and does not report success.

Integration requirement: the authority-engine hook must provide durable
atomic ownership, same-transaction budget debit, and trusted settlement /
reconciliation. Kernel's race test uses an in-memory atomic test hook; it is
not cross-process or cross-host ledger evidence. Neither a proof nonce nor an
agent idempotency key substitutes for logical effect identity. Claims remain
held after crash or ambiguity. Kernel never expires/releases them automatically.
Receipt evidence still needs authenticated outcome writing / attestation in
production. This change does not claim a finished Airlock protected runtime,
an OS sandbox, PostgreSQL effect ownership, or remote exactly-once delivery.

The coordinated source pin is the merged Protocol 3442bf3. Registry publication
remains blocked by the existing release gate until the source override is
removed and real public dependency artifacts exist.
