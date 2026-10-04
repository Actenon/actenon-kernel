"""H2 victim probe: one fresh process per ACTENON_ENV value. Records what
development/insecure behaviour silently activates."""
import json, sys, os, warnings, tempfile, subprocess
warnings.simplefilter("ignore")
forged = json.load(open(sys.argv[1]))
res = {"ACTENON_ENV": os.environ.get("ACTENON_ENV", "<unset>")}
import actenon
assert "site-packages" in actenon.__file__
from actenon.proof.signers.local import build_local_proof_signer, LOCAL_PROOF_SECRET
from actenon.proof import PCCBVerifier
from actenon.gate import ActenonGate
from actenon.models.contracts import PCCB
from actenon.api import ActionIntentIntakeService
from actenon.models import DynamicContextInput, AudienceRef
from datetime import datetime, timezone
# V1: dev HMAC signer with the public secret constructs?
try:
    s = build_local_proof_signer(); res["V1_local_hmac_signer"] = "CONSTRUCTED" + (" (PUBLIC secret)" if s.secret == LOCAL_PROOF_SECRET else "")
except Exception as e:
    s = None; res["V1_local_hmac_signer"] = f"REFUSED {type(e).__name__}"
# V2: verifier rooted in that signer accepts the attacker's forged proof?
if s is not None:
    intent = ActionIntentIntakeService().parse(forged["action"]); pccb = PCCB.from_dict(forged["proof"])
    sel = intent.target.selectors or {"resource_id": intent.target.resource_id}
    ctx = DynamicContextInput(request_id="r1", audience=AudienceRef(type="service", id="payments"),
        scope_capabilities=(intent.action.capability,), now=datetime.now(timezone.utc), facts={},
        parameter_constraints=dict(intent.action.constraints or intent.action.parameters), resource_selectors=(dict(sel),))
    try:
        PCCBVerifier(signer=s).verify(intent, pccb, ctx); res["V2_forged_proof"] = "ACCEPTED"
    except Exception as e:
        res["V2_forged_proof"] = f"REFUSED {getattr(e,'refusal_code',type(e).__name__)}"
else:
    res["V2_forged_proof"] = "n/a (signer refused)"
# V3: ActenonGate.local_dev constructs and executes the forged refund?
try:
    g = ActenonGate.local_dev(audience="service:payments")
    out = g.protect(forged["action"], forged["proof"], lambda **k: {"refunded": True})
    res["V3_gate_local_dev"] = f"CONSTRUCTED; forged refund outcome={out.outcome}"
except Exception as e:
    res["V3_gate_local_dev"] = f"REFUSED {type(e).__name__}"
# V4: Permit's signer resolution with no key configured
try:
    os.environ["HOME"] = tempfile.mkdtemp()
    for k in ("ACTENON_ED25519_KEY_FILE", "ACTENON_SIGNING_KEY"): os.environ.pop(k, None)
    from actenon_permit.ed25519_signer import resolve_signer
    ps = resolve_signer()
    res["V4_permit_resolve_signer"] = f"{type(ps).__name__} alg={ps.algorithm}" + (" (PUBLIC secret)" if getattr(ps, "secret", None) == LOCAL_PROOF_SECRET else "")
except Exception as e:
    res["V4_permit_resolve_signer"] = f"REFUSED {type(e).__name__}: {str(e)[:60]}"
# V5: actenon-mcp --demo
mcp = os.path.join(os.path.dirname(sys.executable), "actenon-mcp")
try:
    p = subprocess.run([mcp, "--demo"], input=b"", capture_output=True, timeout=20)
    err = p.stderr.decode()
    res["V5_mcp_demo"] = "REFUSED" if "refused" in err else ("STARTED (DEMO MODE)" if "DEMO" in err.upper() else f"exit={p.returncode} {err[-80:]!r}")
except Exception as e:
    res["V5_mcp_demo"] = f"ERR {type(e).__name__}"
print(json.dumps(res))
