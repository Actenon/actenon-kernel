"""H1 worker: a protected edge built the way the docs show for production
(verifier-only ActenonGate, Ed25519 trust root, default replay protection,
no replay_protector passed). Presents the proof N times in THIS process and
appends every executed side effect to a shared ledger file."""
import json, sys, os, actenon, logging
from actenon.gate import ActenonGate
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ed25519_harness import Ed25519Verifier

proof_file, ledger, label, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
assert "site-packages" in actenon.__file__, actenon.__file__
d = json.load(open(proof_file))
gate = ActenonGate(verifier=Ed25519Verifier(d["jwk"]["x"], d["jwk"]["kid"]), audience="service:payments", issuer="service:issuer",
                   capabilities=("payments.refund",))  # phase 2: kernel >= 78efcf1 requires the declaration
store = getattr(gate._executor.replay_protector, "store", None)
print(f"[{label}] pid={os.getpid()} ACTENON_ENV={os.environ.get('ACTENON_ENV')!r} replay_store={type(store).__name__} path={getattr(store,'path',None) or getattr(store,'db_path',None) or getattr(store,'_path',None)}")
def side_effect(**kw):
    with open(ledger, "a") as f:
        f.write(f"{label} pid={os.getpid()} EXECUTED refund\n")
    return {"refunded": True}
for i in range(n):
    out = gate.protect(d["action"], d["proof"], side_effect)
    print(f"[{label}] attempt {i+1}: outcome={out.outcome} reason={out.reason_code}")
