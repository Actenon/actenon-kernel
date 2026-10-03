"""One protected-edge worker process using PostgresReplayStore (installed kernel wheel).
argv: proof.json dsn ledger label threads"""
import json, os, sys, threading
import actenon
assert "site-packages" in actenon.__file__
from actenon.gate import ActenonGate
from actenon.replay import PostgresReplayStore, ReplayProtector
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "h1h2"))
from ed25519_harness import Ed25519Verifier
proof, dsn, ledger, label, threads = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
d = json.load(open(proof))
try:
    gate = ActenonGate(verifier=Ed25519Verifier(d["jwk"]["x"], d["jwk"]["kid"]), audience="service:payments",
                       issuer="service:issuer", capabilities=("payments.refund",),
                       replay_protector=ReplayProtector(PostgresReplayStore(dsn)))
except Exception as e:
    print(json.dumps({"label": label, "started": False, "error": f"{type(e).__name__}: {e}"[:200]})); sys.exit(0)
if os.environ.get("PG_WAIT_FILE"):  # constructed and connected; wait until the harness has stopped the server
    import time
    print(json.dumps({"label": label, "constructed": True}), flush=True)
    while not os.path.exists(os.environ["PG_WAIT_FILE"]): time.sleep(0.1)
lock, outs = threading.Lock(), []
def effect():
    with lock, open(ledger, "a") as f: f.write(f"{label} pid={os.getpid()} EXECUTED\n")
def go():
    o = gate.protect(d["action"], d["proof"], effect)
    with lock: outs.append((o.outcome, o.reason_code))
ts = [threading.Thread(target=go) for _ in range(threads)]; [t.start() for t in ts]; [t.join() for t in ts]
print(json.dumps({"label": label, "started": True, "outcomes": sorted(set(outs)), "count": len(outs),
                  "downgrades": list(gate.security_downgrades)}))
