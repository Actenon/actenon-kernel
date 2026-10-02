"""Authority side: actenon-permit (installed package) decides and mints a PCCB.
argv: command outfile [options]. Commands: keygen, mint, mint-short, revoke-then-decide
Env: ACTENON_ED25519_KEY_FILE (Permit's documented production Ed25519 key)."""
import json, os, sys, time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import actenon, actenon_permit
assert "site-packages" in actenon.__file__ and "site-packages" in actenon_permit.__file__
from actenon_permit.model import Action, Grant, GrantStatus, Scopes, Budget
from actenon_permit.pdp import PDP
from actenon_permit.state import SQLiteStore
from actenon_permit.ledger import Ledger
cmd, out = sys.argv[1], sys.argv[2]
if cmd == "keygen":
    from actenon_permit.ed25519_signer import generate_ed25519_keypair, save_ed25519_keypair
    from pathlib import Path
    kp = generate_ed25519_keypair(key_id=sys.argv[3] if len(sys.argv) > 3 else None)
    save_ed25519_keypair(kp, Path(out))
    json.dump(kp.public_key_jwk, open(out + ".pub.jwk", "w"))
    print("keygen", kp.key_id); sys.exit(0)
work = os.path.dirname(out)
def pdp():
    store = SQLiteStore(os.path.join(work, "state.db"))
    return PDP(store, Ledger(store))
ttl = timedelta(seconds=3) if cmd == "mint-short" else timedelta(minutes=10)
grant = Grant(agent_id="agent-e2e", expires_at=datetime.now(UTC) + ttl, scopes=Scopes(allow=[os.environ.get("E2E_SCOPE", "payments.refund")]),
              budget=Budget(currency="EUR", limit=Decimal("100000"), remaining=Decimal("100000"))).sign()
action = Action(grant_id=grant.id, type="payments.refund", target="ch_e2e_1", params={"amount_minor": 2500, "currency": "EUR"})
p = pdp()
try:
    p.state.put_grant(grant)
except Exception:
    pass
if cmd == "revoke-then-decide":
    first = p.decide_and_mint_pccb(grant, action)
    grant2 = grant.model_copy(update={"status": GrantStatus.REVOKED})
    action2 = Action(grant_id=grant.id, type="payments.refund", target="ch_e2e_1", params={"amount_minor": 2500, "currency": "EUR"})
    second = p.decide_and_mint_pccb(grant2, action2)
    res = {"before_revocation": {"outcome": str(first[0].outcome), "intent": first[1].to_dict() if first[1] else None, "pccb": first[2].to_dict() if first[2] else None},
           "after_revocation": {"outcome": str(second[0].outcome), "reason": second[0].reason, "pccb_minted": second[2] is not None}}
    json.dump(res, open(out, "w"), default=str); print("revoke:", res["before_revocation"]["outcome"], "->", res["after_revocation"]["outcome"]); sys.exit(0)
decision, intent, pccb = p.decide_and_mint_pccb(grant, action)
res = {"decision": str(decision.outcome), "reason": decision.reason, "intent": intent.to_dict() if intent else None, "pccb": pccb.to_dict() if pccb else None,
       "signature_alg": pccb.signature.algorithm if pccb else None}
json.dump(res, open(out, "w"), default=str)
print("mint:", res["decision"], res["reason"][:80], "alg=", res["signature_alg"])
