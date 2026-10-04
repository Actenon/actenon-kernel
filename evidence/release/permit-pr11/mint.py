"""Mint grant tokens with whichever actenon-permit is installed. argv: out.json"""
import json, sys, importlib.metadata as m
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import actenon_permit
from actenon_permit import grant_to_token
from actenon_permit.model import Grant, Budget, Scopes
assert "site-packages" in actenon_permit.__file__
now = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
cases = {
  "ascii": dict(agent_id="agent-ascii", budget=Budget(currency="USD", limit=Decimal("10.00"), remaining=Decimal("10.00"))),
  "non_ascii": dict(agent_id="agënt-ünïcode-日本", budget=Budget(currency="EUR", limit=Decimal("5"), remaining=Decimal("5"))),
  "decimal_trailing_zero": dict(agent_id="agent-dec", budget=Budget(currency="USD", limit=Decimal("0.10"), remaining=Decimal("0.1"))),
}
out = {"permit_version": m.version("actenon-permit"), "tokens": {}}
for name, kw in cases.items():
    g = Grant(id=f"grant_{name}", issued_at=now, expires_at=now + timedelta(days=3650), scopes=Scopes(allow=["payments.*"]), **kw).sign()
    out["tokens"][name] = grant_to_token(g)
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(out["permit_version"], {k: v[:3] for k, v in out["tokens"].items()})
