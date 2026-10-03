"""Authority side: the actenon-permit 2.0.0rc1 WHEEL decides and mints a PCCB.

usage: authority.py keygen OUT KID
       authority.py mint OUT [--scope S] [--parent-scope S] [--ttl SECONDS] [--amount N]
       authority.py revoke GRANT_ID
       authority.py decide OUT GRANT_ID     (decide again for an existing grant)
Env: E2E_STATE_DB  Permit state store (also the edges' revocation source)
     ACTENON_ED25519_KEY_FILE  Permit's production Ed25519 key
"""
import argparse, json, os, sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import actenon, actenon_permit
assert "site-packages" in actenon.__file__ and "site-packages" in actenon_permit.__file__, "must run from installed wheels"
from actenon_permit.ledger import Ledger
from actenon_permit.model import Action, Budget, Grant, GrantStatus, Scopes
from actenon_permit.pdp import PDP
from actenon_permit.state import SQLiteStore

ap = argparse.ArgumentParser()
ap.add_argument("cmd"); ap.add_argument("arg1", nargs="?"); ap.add_argument("arg2", nargs="?")
ap.add_argument("--scope", default="payments.refund"); ap.add_argument("--parent-scope")
ap.add_argument("--ttl", type=int, default=600); ap.add_argument("--amount", type=int, default=2500)
a = ap.parse_args()

if a.cmd == "keygen":
    from pathlib import Path
    from actenon_permit.ed25519_signer import generate_ed25519_keypair, save_ed25519_keypair
    kp = generate_ed25519_keypair(key_id=a.arg2)
    save_ed25519_keypair(kp, Path(a.arg1))
    json.dump(kp.public_key_jwk, open(a.arg1 + ".pub.jwk", "w"))
    print(json.dumps({"keygen": kp.key_id})); sys.exit(0)

store = SQLiteStore(os.environ["E2E_STATE_DB"])
if a.cmd == "revoke":
    store.set_status(a.arg1, GrantStatus.REVOKED)
    print(json.dumps({"revoked": a.arg1, "status": str(store.get_grant(a.arg1).status)})); sys.exit(0)

def grant(scope, parent=None):
    g = Grant(agent_id="agent-e2e", expires_at=datetime.now(UTC) + timedelta(seconds=a.ttl),
              scopes=Scopes(allow=[scope]),
              budget=Budget(currency="EUR", limit=Decimal("100000"), remaining=Decimal("100000")),
              parent_grant_id=parent.id if parent else None, delegation_depth=1 if parent else 0).sign()
    store.put_grant(g)
    return g

def decide(out, g):
    action = Action(grant_id=g.id, type="payments.refund", target="ch_e2e_1",
                    params={"amount_minor": a.amount, "currency": "EUR"})
    decision, intent, pccb = PDP(store, Ledger(store)).decide_and_mint_pccb(g, action)
    res = {"decision": str(decision.outcome), "reason": decision.reason, "grant_id": g.id,
           "parent_grant_id": g.parent_grant_id,
           "intent": intent.to_dict() if intent else None, "pccb": pccb.to_dict() if pccb else None,
           "signature_alg": pccb.signature.algorithm if pccb else None}
    json.dump(res, open(out, "w"), default=str)
    print(json.dumps({"decision": res["decision"], "pccb_minted": pccb is not None, "alg": res["signature_alg"],
                      "grant_id": g.id, "reason": (decision.reason or "")[:120]}))

if a.cmd == "mint":
    parent = grant(a.parent_scope) if a.parent_scope else None
    decide(a.arg1, grant(a.scope, parent))
elif a.cmd == "decide":
    decide(a.arg1, store.get_grant(a.arg2))
else:
    sys.exit(f"unknown command {a.cmd}")
