"""Verify every token file given with the installed actenon-permit. argv: token files..."""
import json, sys, importlib.metadata as m
import actenon_permit
from actenon_permit import token_to_grant, canonical_json
assert "site-packages" in actenon_permit.__file__
v = m.version("actenon-permit")
for f in sys.argv[1:]:
    d = json.load(open(f))
    for name, tok in d["tokens"].items():
        try:
            g = token_to_grant(tok); r = f"ACCEPT ({g.agent_id})"
        except Exception as e:
            r = f"REJECT {type(e).__name__}: {str(e)[:90]}"
        print(f"producer=permit-py {d['permit_version']:>6} | verifier=permit-py {v:>6} | {name:22} | {r}")
try:
    print(f"canonical_json(1.5) on {v}:", repr(canonical_json({"a": 1.5})))
except Exception as e:
    print(f"canonical_json(1.5) on {v}: RAISES {type(e).__name__}: {str(e)[:80]}")
