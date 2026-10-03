"""H1 issuer: mint ONE single-use Ed25519 PCCB for one action, write it to disk.

Production-style configuration: ACTENON_ENV=production, Ed25519 signer
(harness Ed25519Signer over `cryptography`), no HMAC anywhere.
"""
import json, sys, os, actenon
from actenon.gate import ActenonGate
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ed25519_harness import Ed25519Signer, Ed25519Verifier

out = sys.argv[1]
assert "site-packages" in actenon.__file__, actenon.__file__
signer = Ed25519Signer()
jwk = {"kid": signer.key_id, "x": signer.x}
gate = ActenonGate(verifier=Ed25519Verifier(signer.x, signer.key_id), signer=signer,
                   audience="service:payments", issuer="service:issuer",
                   capabilities=("payments.refund",))
action = gate.build_action("refund", "payments.refund", {"amount": 100, "currency": "EUR"},
                           target_type="charge", target_id="ch_1", tenant_id="t1", requester_id="agent-1")
proof = gate.mint_proof(action)
json.dump({"jwk": jwk, "action": action, "proof": proof.to_dict(),
           "kernel_file": actenon.__file__, "ACTENON_ENV": os.environ.get("ACTENON_ENV")}, open(out, "w"), indent=1, default=str)
print("minted", proof.pccb_id)
