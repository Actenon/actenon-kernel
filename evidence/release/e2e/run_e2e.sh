#!/usr/bin/env bash
# E2E from built/installed packages only. Usage: run_e2e.sh <venv-python> <outdir>
# Authority (Permit) and edge (Kernel) run as separate processes; the edge has
# two "workers" and a restart, sharing one durable ACTENON_REPLAY_DB.
set -u
PY=$1; OUT=$2; HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf "$OUT"; mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"
unset ACTENON_ENV ACTENON_PRODUCTION ACTENON_SIGNING_KEY ACTENON_LOCAL_HMAC_SECRET ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY
export HOME="$W/home"; mkdir -p "$HOME"
export ACTENON_ENV=production
echo "## versions: $($PY -c "import importlib.metadata as m;print({p:m.version(p) for p in ('actenon-kernel','actenon-permit','actenon-protocol')})")"
$PY "$HERE/authority.py" keygen "$W/permit-ed25519.json" permit-e2e-key >/dev/null
export ACTENON_ED25519_KEY_FILE="$W/permit-ed25519.json"
JWK="$W/permit-ed25519.json.pub.jwk"
export ACTENON_REPLAY_DB="$W/edge-replay.sqlite3"
edge() { $PY "$HERE/edge.py" "$@" 2>>"$OUT/stderr.txt"; }
check() { echo "RESULT $1: $2"; }

echo "### E0 Permit grant with a glob scope (payments.*) -> Kernel edge"
E2E_SCOPE='payments.*' $PY "$HERE/authority.py" mint "$W/p0.json" 2>>"$OUT/stderr.txt"; : > "$W/ledger0.txt"
r=$(edge "$W/p0.json" "$JWK" "$W/ledger0.txt" workerA); echo "  $r"
echo "$r" | grep -q '"outcomes": \["executed"\]' && check E0 PASS || check E0 "FAIL (a Permit-minted proof for a glob-scoped grant is refused by the kernel edge)"
echo "### E1 happy path: Permit decides+mints (Ed25519) -> Kernel edge verifies -> executes once -> Receipt"
$PY "$HERE/authority.py" mint "$W/p1.json" 2>>"$OUT/stderr.txt"
: > "$W/ledger1.txt"
r=$(edge "$W/p1.json" "$JWK" "$W/ledger1.txt" workerA --receipt-out "$OUT/receipt-E1.json"); echo "  $r"
echo "$r" | grep -q '"outcomes": \["executed"\]' && [ -s "$OUT/receipt-E1.json" ] && check E1 PASS || check E1 FAIL
echo "### E2 replay across two workers and a restart (shared durable replay store)"
r=$(edge "$W/p1.json" "$JWK" "$W/ledger1.txt" workerB); echo "  $r"
r2=$(edge "$W/p1.json" "$JWK" "$W/ledger1.txt" workerA-restarted); echo "  $r2"
n=$(wc -l < "$W/ledger1.txt"); echo "  side effects for one proof: $n"
[ "$n" = 1 ] && echo "$r$r2" | grep -q DUPLICATE_REPLAY && check E2 PASS || check E2 FAIL
echo "### E3 duplicated execution: 16 concurrent presentations of a fresh proof in one worker + 1 in another"
$PY "$HERE/authority.py" mint "$W/p3.json" >/dev/null 2>>"$OUT/stderr.txt"; : > "$W/ledger3.txt"
r=$(edge "$W/p3.json" "$JWK" "$W/ledger3.txt" workerA --threads 16); r2=$(edge "$W/p3.json" "$JWK" "$W/ledger3.txt" workerB --threads 4)
n=$(wc -l < "$W/ledger3.txt"); echo "  side effects: $n"; [ "$n" = 1 ] && check E3 PASS || check E3 FAIL
echo "### E4 wrong audience"
$PY "$HERE/authority.py" mint "$W/p4.json" >/dev/null 2>>"$OUT/stderr.txt"; : > "$W/ledger4.txt"
r=$(edge "$W/p4.json" "$JWK" "$W/ledger4.txt" workerA --audience service:ledger-edge); echo "  $r"
[ ! -s "$W/ledger4.txt" ] && echo "$r" | grep -q -E '"(AUDIENCE_MISMATCH|PROOF_INVALID)"' && check E4 PASS || check E4 FAIL
echo "### E5 altered parameters (amount 2500 -> 999999 after minting)"
r=$(edge "$W/p4.json" "$JWK" "$W/ledger4.txt" workerA --mutate-amount 999999); echo "  $r"
[ ! -s "$W/ledger4.txt" ] && echo "$r" | grep -q -E '"(ACTION_MISMATCH|ACTION_HASH_MISMATCH)"' && check E5 PASS || check E5 FAIL
echo "### E6 forged proof: attacker's own Ed25519 key with the issuer's kid"
$PY "$HERE/authority.py" keygen "$W/attacker.json" permit-e2e-key >/dev/null
ACTENON_ED25519_KEY_FILE="$W/attacker.json" $PY "$HERE/authority.py" mint "$W/p6.json" >/dev/null 2>>"$OUT/stderr.txt"
r=$(edge "$W/p6.json" "$JWK" "$W/ledger4.txt" workerA); echo "  $r"
[ ! -s "$W/ledger4.txt" ] && echo "$r" | grep -q -E '"(PROOF_INVALID|SIGNATURE_INVALID)"' && check E6 PASS || check E6 FAIL
echo "### E6b forged proof signed with the PUBLIC development HMAC secret"
ACTENON_ENV=development $PY -W ignore -c "
import json,sys
from actenon.proof.signers.local import build_local_proof_signer
from actenon.proof.canonical import canonicalize_bytes
from actenon.models.contracts import PCCB
d=json.load(open('$W/p4.json')); p=PCCB.from_dict(d['pccb']); s=build_local_proof_signer()
d['pccb']['signature']=s.sign(canonicalize_bytes(p.unsigned_payload())).to_dict(); json.dump(d,open('$W/p6b.json','w'))" 2>>"$OUT/stderr.txt"
r=$(edge "$W/p6b.json" "$JWK" "$W/ledger4.txt" workerA); echo "  $r"
[ ! -s "$W/ledger4.txt" ] && echo "$r" | grep -q -E '"(PROOF_INVALID|SIGNATURE_INVALID)"' && check E6b PASS || check E6b FAIL
echo "### E7 expired proof (grant/proof window 3s, presented after 5s)"
$PY "$HERE/authority.py" mint-short "$W/p7.json" >/dev/null 2>>"$OUT/stderr.txt"; sleep 5
r=$(edge "$W/p7.json" "$JWK" "$W/ledger4.txt" workerA); echo "  $r"
[ ! -s "$W/ledger4.txt" ] && echo "$r" | grep -q '"PROOF_EXPIRED"' && check E7 PASS || check E7 FAIL
echo "### E8 revoked authority"
$PY "$HERE/authority.py" revoke-then-decide "$W/p8.json" 2>>"$OUT/stderr.txt"
$PY -c "import json;d=json.load(open('$W/p8.json'));json.dump(d['before_revocation'],open('$W/p8pre.json','w'));print('  after revocation: Permit outcome',d['after_revocation'])"
grep -q '"pccb_minted": false' "$W/p8.json" && check E8a "PASS (Permit refuses to mint after revocation)" || check E8a FAIL
r=$(edge "$W/p8pre.json" "$JWK" "$W/ledger4.txt" workerA); echo "  proof minted BEFORE revocation, presented AFTER: $r"
echo "$r" | grep -q -E '"(AUTHORITY_REVOKED|PROOF_REVOKED|GRANT_REVOKED)"' && check E8b "PASS (edge refuses as revoked)" || check E8b "FAIL (edge executes a proof whose authority was revoked: no revocation_checker in ActenonGate)"
: > "$W/ledger4.txt"
echo "### E9 missing production replay configuration (no ACTENON_REPLAY_DB)"
r=$(env -u ACTENON_REPLAY_DB $PY "$HERE/edge.py" "$W/p3.json" "$JWK" "$W/ledger9.txt" workerA 2>>"$OUT/stderr.txt"); echo "  $r"
echo "$r" | grep -q '"started": false' && check E9 PASS || check E9 "FAIL (edge started with per-process replay state)"
r=$(env -u ACTENON_REPLAY_DB ACTENON_ENV= $PY "$HERE/edge.py" "$W/p3.json" "$JWK" "$W/ledger9.txt" workerA 2>>"$OUT/stderr.txt"); echo "  ACTENON_ENV empty: $r"
echo "$r" | grep -q '"started": false' && check E9b PASS || check E9b "FAIL (edge started with per-process replay state, ACTENON_ENV empty)"
echo "### E10 missing / invalid production signing configuration"
r=$(env -u ACTENON_ED25519_KEY_FILE ACTENON_ENV= $PY "$HERE/authority.py" mint "$W/p10.json" 2>>"$OUT/stderr.txt"); echo "  no key, ACTENON_ENV empty: $r"
echo "$r" | grep -q 'alg= HS256' && check E10a "FAIL (Permit minted an HMAC proof with no signing configuration)" || check E10a "PASS (no proof minted without signing configuration)"
r=$(env -u ACTENON_ED25519_KEY_FILE ACTENON_ENV=prd $PY "$HERE/authority.py" mint "$W/p10b.json" 2>>"$OUT/stderr.txt"); echo "  no key, ACTENON_ENV=prd: $r"
echo "$r" | grep -q 'alg= HS256' && check E10b "FAIL (Permit minted with the public HMAC secret under ACTENON_ENV=prd)" || check E10b "PASS"
echo '{"not":"a key"}' > "$W/bad.json"
r=$(ACTENON_ED25519_KEY_FILE="$W/bad.json" $PY "$HERE/authority.py" mint "$W/p10c.json" 2>>"$OUT/stderr.txt"); echo "  invalid key file: $r"
echo "$r" | grep -q 'alg= ' && ! echo "$r" | grep -q 'alg= None' && check E10c "FAIL (minted with an invalid key file)" || check E10c "PASS (invalid key -> no proof)"
r=$(ACTENON_ENV= $PY -W ignore -c "
from actenon.gate import ActenonGate
from actenon.proof.signers.local import build_local_proof_signer
try:
    s=build_local_proof_signer(); print('edge verifier with public secret CONSTRUCTED')
except Exception as e: print('REFUSED', type(e).__name__)" 2>>"$OUT/stderr.txt"); echo "  edge rooted in public dev secret, ACTENON_ENV empty: $r"
echo "$r" | grep -q REFUSED && check E10d PASS || check E10d FAIL
cp "$W"/p1.json "$OUT/proof-E1.json" 2>/dev/null; true
