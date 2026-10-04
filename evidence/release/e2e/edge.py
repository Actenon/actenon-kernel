"""Protected edge: actenon-kernel (installed package) ActenonGate in its own process.
argv: proof.json jwk.json ledger.txt label [--audience X] [--mutate-amount N] [--intent-from FILE] [--threads N]"""
import json, os, sys, threading, argparse
import actenon
assert "site-packages" in actenon.__file__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ed25519_edge import Ed25519JwkVerifier
from actenon.gate import ActenonGate
ap = argparse.ArgumentParser(); ap.add_argument("proof"); ap.add_argument("jwk"); ap.add_argument("ledger"); ap.add_argument("label")
ap.add_argument("--audience", default="service:actenon-permit-gateway"); ap.add_argument("--mutate-amount", type=int); ap.add_argument("--threads", type=int, default=1)
ap.add_argument("--receipt-out")
a = ap.parse_args()
d = json.load(open(a.proof)); jwk = json.load(open(a.jwk))
intent, pccb = d["intent"], d["pccb"]
if a.mutate_amount is not None:
    intent["action"]["parameters"]["amount_minor"] = a.mutate_amount
try:
    gate = ActenonGate(verifier=Ed25519JwkVerifier(jwk), audience=a.audience, issuer="service:actenon-permit")
except Exception as e:
    print(json.dumps({"label": a.label, "started": False, "error_type": type(e).__name__, "error": str(e)[:300]})); sys.exit(0)
results, lock = [], threading.Lock()
def side_effect():
    with lock, open(a.ledger, "a") as f:
        f.write(f"{a.label} pid={os.getpid()} EXECUTED refund {intent['action']['parameters']['amount_minor']}\n")
    return {"refunded": True}
def go():
    out = gate.protect(intent, pccb, side_effect)
    with lock:
        results.append(out)
ts = [threading.Thread(target=go) for _ in range(a.threads)]
[t.start() for t in ts]; [t.join() for t in ts]
row = {"label": a.label, "started": True, "outcomes": [o.outcome for o in results], "reasons": [o.reason_code for o in results],
       "downgrades": list(gate.security_downgrades) if hasattr(gate, "security_downgrades") else "<n/a>"}
if a.receipt_out and results and results[0].receipt is not None:
    json.dump(results[0].receipt.to_dict(), open(a.receipt_out, "w"), default=str); row["receipt_written"] = a.receipt_out
print(json.dumps(row))
