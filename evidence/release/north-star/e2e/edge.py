"""Protected edge: the INSTALLED actenon-kernel 1.3.0 ActenonGate, in its own process.

North-star copy of evidence/release/phase2/e2e/edge.py. Only change: when E2E_REPLAY_DSN is set the
gate's single-use store is PostgresReplayStore(E2E_REPLAY_DSN) (a real PostgreSQL server shared by
every worker), injected as replay_protector; otherwise the default (ACTENON_REPLAY_DB, SQLite).

usage: edge.py PROOF JWK LEDGER LABEL [--audience A] [--capabilities a,b] [--param-constraints JSON]
       [--resource-selectors JSON] [--revocation-db PATH] [--mutate-amount N] [--threads N] [--receipt-out F]
--revocation-db: Permit's state store, consulted with actenon_permit.revocation.StoreRevocationChecker
(protocol 13 E5). Omit it for an edge with no revocation source. Capabilities default to payments.refund;
pass --capabilities '' to declare none (refused at construction outside development intent).
"""
import argparse, json, os, sys, threading
import actenon
assert "site-packages" in actenon.__file__, "must run from the installed wheel"
from actenon.gate import ActenonGate
from actenon_permit.boundary.proofs import Ed25519PublicKeyVerifier

ap = argparse.ArgumentParser()
for name in ("proof", "jwk", "ledger", "label"): ap.add_argument(name)
ap.add_argument("--audience", default="service:actenon-permit-gateway")
ap.add_argument("--capabilities", default="payments.refund")
ap.add_argument("--param-constraints"); ap.add_argument("--resource-selectors")
ap.add_argument("--revocation-db"); ap.add_argument("--mutate-amount", type=int)
ap.add_argument("--threads", type=int, default=1); ap.add_argument("--receipt-out")
a = ap.parse_args()
d = json.load(open(a.proof)); jwk = json.load(open(a.jwk))
intent, pccb = d["intent"], d["pccb"]
if a.mutate_amount is not None:
    intent["action"]["parameters"]["amount_minor"] = a.mutate_amount
kwargs = {}
if a.capabilities != "":
    kwargs["capabilities"] = tuple(c for c in a.capabilities.split(",") if c)
if a.param_constraints: kwargs["parameter_constraints"] = json.loads(a.param_constraints)
if a.resource_selectors: kwargs["resource_selectors"] = json.loads(a.resource_selectors)
if a.revocation_db:
    from actenon_permit.revocation import StoreRevocationChecker
    from actenon_permit.state import SQLiteStore
    kwargs["revocation_checker"] = StoreRevocationChecker(SQLiteStore(a.revocation_db))
if os.environ.get("E2E_REPLAY_DSN"):
    from actenon.replay import PostgresReplayStore, ReplayProtector
    kwargs["replay_protector"] = ReplayProtector(PostgresReplayStore(os.environ["E2E_REPLAY_DSN"]))
try:
    gate = ActenonGate(verifier=Ed25519PublicKeyVerifier([jwk]), audience=a.audience,
                       issuer="service:actenon-permit", **kwargs)
except Exception as e:
    print(json.dumps({"label": a.label, "edge": "python", "started": False, "error_type": type(e).__name__,
                      "error": str(e)[:300]})); sys.exit(0)
results, lock = [], threading.Lock()
def side_effect():
    with lock, open(a.ledger, "a") as f:
        f.write(f"{a.label} pid={os.getpid()} EXECUTED refund {intent['action']['parameters']['amount_minor']}\n")
    return {"refunded": True}
def go():
    out = gate.protect(intent, pccb, side_effect)
    with lock: results.append(out)
ts = [threading.Thread(target=go) for _ in range(a.threads)]
[t.start() for t in ts]; [t.join() for t in ts]
row = {"label": a.label, "edge": "python", "started": True, "outcomes": [o.outcome for o in results],
       "reasons": [o.reason_code for o in results], "downgrades": list(gate.security_downgrades)}
if a.receipt_out and results and results[0].receipt is not None:
    json.dump(results[0].receipt.to_dict(), open(a.receipt_out, "w"), default=str); row["receipt_written"] = True
print(json.dumps(row))
