#!/usr/bin/env bash
# Phase-2 E2E from BUILT ARTEFACTS ONLY.
# usage: run_e2e.sh <venv-python> <ts-sdk-project-dir> <outdir>
# Authority = actenon-permit 2.0.0rc1 wheel; Python edge = actenon-kernel 1.3.0rc1 wheel (ActenonGate);
# TS edge = @actenon/verifier-sdk 0.2.0 tarball (verifyJSON + Ed25519Verifier). Each runs in its own
# process. Python edges are separate "workers" sharing one durable ACTENON_REPLAY_DB; restarts are new
# processes. Every RESULT line is PASS or FAIL against an exact expectation.
set -u
PY=$1; export TS_SDK_PROJECT=$2; OUT=$3; HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"
unset ACTENON_ENV ACTENON_PRODUCTION ACTENON_SIGNING_KEY ACTENON_SIGNING_KEY_FILE ACTENON_LOCAL_HMAC_SECRET ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY ACTENON_UNSAFE_ALLOW_UNDECLARED_CAPABILITIES
export HOME="$W/home"; mkdir -p "$HOME"
export ACTENON_ENV=production
export E2E_STATE_DB="$W/permit-state.db"
# Permit 2.0 refuses to sign grants without a configured key outside development intent.
export ACTENON_SIGNING_KEY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
echo "## versions: $($PY -c "import importlib.metadata as m;print({p:m.version(p) for p in ('actenon-kernel','actenon-permit','actenon-protocol')})") ts=$(node -p "require('$TS_SDK_PROJECT/node_modules/@actenon/verifier-sdk/package.json').version") node=$(node --version)"
$PY "$HERE/authority.py" keygen "$W/permit-ed25519.json" permit-e2e-key >/dev/null
export ACTENON_ED25519_KEY_FILE="$W/permit-ed25519.json"
JWK="$W/permit-ed25519.json.pub.jwk"
export ACTENON_REPLAY_DB="$W/edge-replay.sqlite3"
FAILS=0
auth() { $PY "$HERE/authority.py" "$@" 2>>"$OUT/stderr.txt"; }
py_edge() { $PY "$HERE/edge.py" "$@" 2>>"$OUT/stderr.txt"; }
ts_edge() { node --no-warnings "$HERE/ts_edge.mjs" "$@" 2>>"$OUT/stderr.txt"; }
gid() { $PY -c "import json,sys;print(json.load(open(sys.argv[1]))['grant_id'])" "$1"; }
result() { if [ "$2" = PASS ]; then echo "RESULT $1: PASS${3:+ ($3)}"; else echo "RESULT $1: FAIL${3:+ ($3)}"; FAILS=$((FAILS+1)); fi; }
has() { printf '%s' "$1" | grep -q -- "$2"; }
minted() { [ -s "$1" ] && $PY -c "import json,sys;sys.exit(0 if json.load(open(sys.argv[1])).get('pccb') else 1)" "$1"; }
lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
STATE="--revocation-db $E2E_STATE_DB"

echo "### E0 glob-scoped grant (payments.*) -> exact-capability proof -> both edges"
auth mint "$W/p0.json" --scope 'payments.*'; : > "$W/l0"
r=$(py_edge "$W/p0.json" "$JWK" "$W/l0" py-A $STATE); echo "  $r"; t=$(ts_edge "$W/p0.json" "$JWK" ts $STATE); echo "  $t"
has "$r" '"outcomes": \["executed"\]' && has "$t" '"outcome":"verified"' && [ "$(lines "$W/l0")" = 1 ] && result E0 PASS || result E0 FAIL

echo "### E1 happy path: Permit (EdDSA) -> kernel edge executes once + Receipt; TS edge verifies the same proof (S4)"
auth mint "$W/p1.json"; : > "$W/l1"
r=$(py_edge "$W/p1.json" "$JWK" "$W/l1" py-A $STATE --receipt-out "$OUT/receipt-E1.json"); echo "  $r"
t=$(ts_edge "$W/p1.json" "$JWK" ts $STATE); echo "  $t"
has "$r" '"outcomes": \["executed"\]' && has "$r" '"downgrades": \[\]' && [ -s "$OUT/receipt-E1.json" ] && has "$t" '"outcome":"verified"' && result E1 PASS || result E1 FAIL

echo "### E2 replay: second worker, then a restarted worker (shared durable replay store)"
r=$(py_edge "$W/p1.json" "$JWK" "$W/l1" py-B $STATE); echo "  $r"; r2=$(py_edge "$W/p1.json" "$JWK" "$W/l1" py-A-restarted $STATE); echo "  $r2"
echo "  side effects for one proof: $(lines "$W/l1")"
[ "$(lines "$W/l1")" = 1 ] && has "$r" DUPLICATE_REPLAY && has "$r2" DUPLICATE_REPLAY && result E2 PASS || result E2 FAIL

echo "### E3 duplicated execution: 16 concurrent presentations in one worker + 4 in another"
auth mint "$W/p3.json" >/dev/null; : > "$W/l3"
py_edge "$W/p3.json" "$JWK" "$W/l3" py-A $STATE --threads 16 >/dev/null & py_edge "$W/p3.json" "$JWK" "$W/l3" py-B $STATE --threads 4 >/dev/null; wait
echo "  side effects: $(lines "$W/l3")"; [ "$(lines "$W/l3")" = 1 ] && result E3 PASS || result E3 FAIL

auth mint "$W/p4.json" >/dev/null; : > "$W/l4"
echo "### E4 wrong audience"
r=$(py_edge "$W/p4.json" "$JWK" "$W/l4" py-A $STATE --audience service:ledger-edge); echo "  $r"
t=$(ts_edge "$W/p4.json" "$JWK" ts $STATE --audience-id ledger-edge); echo "  $t"
[ "$(lines "$W/l4")" = 0 ] && has "$r" '"AUDIENCE_MISMATCH"' && has "$t" '"reason_code":"AUDIENCE_MISMATCH"' && result E4 PASS || result E4 FAIL

echo "### E5 parameter mutation after minting (amount 2500 -> 999999)"
r=$(py_edge "$W/p4.json" "$JWK" "$W/l4" py-A $STATE --mutate-amount 999999); echo "  $r"
t=$(ts_edge "$W/p4.json" "$JWK" ts $STATE --mutate-amount 999999); echo "  $t"
[ "$(lines "$W/l4")" = 0 ] && has "$r" '"refused"' && has "$t" '"outcome":"refused"' && result E5 PASS "codes: py=$(printf '%s' "$r" | grep -o '"reasons": \[[^]]*\]') ts=$(printf '%s' "$t" | grep -o '"reason_code":"[^"]*"')" || result E5 FAIL

echo "### E5b edge declares another capability (payments.read)"
r=$(py_edge "$W/p4.json" "$JWK" "$W/l4" py-A $STATE --capabilities payments.read); echo "  $r"
t=$(ts_edge "$W/p4.json" "$JWK" ts $STATE --capabilities payments.read); echo "  $t"
[ "$(lines "$W/l4")" = 0 ] && has "$r" '"SCOPE_CAPABILITY_MISMATCH"' && has "$t" '"reason_code":"SCOPE_CAPABILITY_MISMATCH"' && result E5b PASS || result E5b FAIL

echo "### E5c edge relies on a parameter constraint the proof was not issued under"
r=$(py_edge "$W/p4.json" "$JWK" "$W/l4" py-A $STATE --param-constraints '{"currency":"EUR"}'); echo "  $r"
t=$(ts_edge "$W/p4.json" "$JWK" ts $STATE --param-constraints '{"currency":"EUR"}'); echo "  $t"
[ "$(lines "$W/l4")" = 0 ] && has "$r" '"PARAMETER_MISMATCH"' && has "$t" '"reason_code":"PARAMETER_MISMATCH"' && result E5c PASS || result E5c FAIL

echo "### E5d edge resource selectors: a non-matching selector refuses, a matching one executes"
r=$(py_edge "$W/p4.json" "$JWK" "$W/l4" py-A $STATE --resource-selectors '[{"resource_id":"ch_other"}]'); echo "  $r"
t=$(ts_edge "$W/p4.json" "$JWK" ts $STATE --resource-selectors '[{"resource_id":"ch_other"}]'); echo "  $t"
r2=$(py_edge "$W/p4.json" "$JWK" "$W/l4" py-A $STATE --resource-selectors '[{"resource_id":"ch_e2e_1"}]'); echo "  matching: $r2"
[ "$(lines "$W/l4")" = 1 ] && has "$r" '"TARGET_MISMATCH"' && has "$t" '"reason_code":"TARGET_MISMATCH"' && has "$r2" '"executed"' && result E5d PASS || result E5d FAIL
: > "$W/l4"

echo "### E6 forged proof: attacker's own Ed25519 key with the issuer's kid"
auth keygen "$W/attacker.json" permit-e2e-key >/dev/null
ACTENON_ED25519_KEY_FILE="$W/attacker.json" auth mint "$W/p6.json" >/dev/null
r=$(py_edge "$W/p6.json" "$JWK" "$W/l4" py-A $STATE); echo "  $r"; t=$(ts_edge "$W/p6.json" "$JWK" ts $STATE); echo "  $t"
[ "$(lines "$W/l4")" = 0 ] && has "$r" '"PROOF_INVALID"' && has "$t" '"reason_code":"SIGNATURE_INVALID"' && result E6 PASS || result E6 FAIL

echo "### E6b forged proof signed with the PUBLIC development HMAC secret"
ACTENON_ENV=development $PY -W ignore -c "
import json
from actenon.proof.signers.local import build_local_proof_signer
from actenon.proof.canonical import canonicalize_bytes
from actenon.models.contracts import PCCB
d=json.load(open('$W/p4.json')); p=PCCB.from_dict(d['pccb']); s=build_local_proof_signer()
d['pccb']['signature']=s.sign(canonicalize_bytes(p.unsigned_payload())).to_dict(); json.dump(d,open('$W/p6b.json','w'))" 2>>"$OUT/stderr.txt"
r=$(py_edge "$W/p6b.json" "$JWK" "$W/l4" py-A $STATE); echo "  $r"; t=$(ts_edge "$W/p6b.json" "$JWK" ts $STATE); echo "  $t"
[ "$(lines "$W/l4")" = 0 ] && has "$r" '"PROOF_INVALID"' && has "$t" '"reason_code":"SIGNATURE_INVALID"' && result E6b PASS || result E6b FAIL

echo "### E7 expired proof (grant/proof window 3s, presented after 5s)"
auth mint "$W/p7.json" --ttl 3 >/dev/null; sleep 5
r=$(py_edge "$W/p7.json" "$JWK" "$W/l4" py-A $STATE); echo "  $r"; t=$(ts_edge "$W/p7.json" "$JWK" ts $STATE); echo "  $t"
[ "$(lines "$W/l4")" = 0 ] && has "$r" '"PROOF_EXPIRED"' && has "$t" '"reason_code":"PROOF_EXPIRED"' && result E7 PASS || result E7 FAIL

echo "### E8 revocation (protocol 13 E5): proof minted, THEN the grant is revoked in Permit's store"
auth mint "$W/p8.json" >/dev/null; G8=$(gid "$W/p8.json")
auth revoke "$G8"
d=$(auth decide "$W/p8-after.json" "$G8"); echo "  Permit decides again after revocation: $d"
has "$d" '"pccb_minted": false' && result E8a PASS "Permit refuses to mint" || result E8a FAIL
: > "$W/l8"
r=$(py_edge "$W/p8.json" "$JWK" "$W/l8" py-A $STATE); echo "  $r"; t=$(ts_edge "$W/p8.json" "$JWK" ts $STATE); echo "  $t"
[ "$(lines "$W/l8")" = 0 ] && has "$r" '"AUTHORITY_REVOKED"' && has "$t" '"reason_code":"AUTHORITY_REVOKED"' && result E8b PASS "edges refuse a proof whose grant was revoked after minting" || result E8b FAIL

echo "### E8c delegated grant: the PARENT is revoked after the child's proof is minted"
auth mint "$W/p8c.json" --parent-scope 'payments.*' >/dev/null
P8=$($PY -c "import json;print(json.load(open('$W/p8c.json'))['parent_grant_id'])"); auth revoke "$P8" >/dev/null
r=$(py_edge "$W/p8c.json" "$JWK" "$W/l8" py-A $STATE); echo "  $r"; t=$(ts_edge "$W/p8c.json" "$JWK" ts $STATE); echo "  $t"
[ "$(lines "$W/l8")" = 0 ] && has "$r" '"AUTHORITY_REVOKED"' && has "$t" '"reason_code":"AUTHORITY_REVOKED"' && result E8c PASS || result E8c FAIL

echo "### E8d edge with NO revocation source, valid unrevoked proof"
auth mint "$W/p8d.json" >/dev/null
r=$(py_edge "$W/p8d.json" "$JWK" "$W/l8" py-A); echo "  $r"; t=$(ts_edge "$W/p8d.json" "$JWK" ts); echo "  $t"
[ "$(lines "$W/l8")" = 0 ] && has "$r" '"AUTHORITY_REVOKED"' && has "$t" '"reason_code":"AUTHORITY_REVOKED"' && result E8d PASS "fail closed" || result E8d FAIL

echo "### E8e revocation source that does not know the grant (wrong/empty store)"
r=$(py_edge "$W/p8d.json" "$JWK" "$W/l8" py-A --revocation-db "$W/empty-state.db"); echo "  $r"
t=$(ts_edge "$W/p8d.json" "$JWK" ts --revocation-db "$W/empty-state.db"); echo "  $t"
[ "$(lines "$W/l8")" = 0 ] && has "$r" '"AUTHORITY_REVOKED"' && has "$t" '"reason_code":"AUTHORITY_REVOKED"' && result E8e PASS "fail closed" || result E8e FAIL

echo "### E9 missing production configuration"
r=$(env -u ACTENON_REPLAY_DB $PY "$HERE/edge.py" "$W/p8d.json" "$JWK" "$W/l9" py-A $STATE 2>>"$OUT/stderr.txt"); echo "  no ACTENON_REPLAY_DB: $r"
has "$r" '"started": false' && result E9 PASS || result E9 FAIL
r=$(env -u ACTENON_REPLAY_DB ACTENON_ENV= $PY "$HERE/edge.py" "$W/p8d.json" "$JWK" "$W/l9" py-A $STATE 2>>"$OUT/stderr.txt"); echo "  no ACTENON_REPLAY_DB, ACTENON_ENV empty: $r"
has "$r" '"started": false' && result E9b PASS || result E9b FAIL
r=$(py_edge "$W/p8d.json" "$JWK" "$W/l9" py-A $STATE --capabilities ''); echo "  no declared capabilities: $r"
has "$r" '"started": false' && has "$r" capabilities && result E9c PASS || result E9c FAIL
[ "$(lines "$W/l9")" = 0 ] || result E9-side-effects FAIL

echo "### E10 missing / invalid production signing configuration"
r=$(env -u ACTENON_ED25519_KEY_FILE -u ACTENON_SIGNING_KEY ACTENON_ENV= $PY "$HERE/authority.py" mint "$W/p10.json" 2>&1 | tail -1); echo "  no key, ACTENON_ENV empty: ${r:0:200}"
! minted "$W/p10.json" && result E10a PASS "no proof minted" || result E10a FAIL
r=$(env -u ACTENON_ED25519_KEY_FILE -u ACTENON_SIGNING_KEY ACTENON_ENV=prd $PY "$HERE/authority.py" mint "$W/p10b.json" 2>&1 | tail -1); echo "  no key, ACTENON_ENV=prd: ${r:0:200}"
! minted "$W/p10b.json" && result E10b PASS || result E10b FAIL
r=$(env -u ACTENON_ED25519_KEY_FILE $PY "$HERE/authority.py" mint "$W/p10e.json" 2>&1 | tail -1); echo "  only the Ed25519 proof key absent (grant HMAC key set): ${r:0:200}"
! minted "$W/p10e.json" && result E10e PASS "no proof minted; the grant key is not used as a proof key" || result E10e FAIL
echo '{"not":"a key"}' > "$W/bad.json"
r=$(ACTENON_ED25519_KEY_FILE="$W/bad.json" $PY "$HERE/authority.py" mint "$W/p10c.json" 2>&1 | tail -1); echo "  invalid key file: ${r:0:200}"
! minted "$W/p10c.json" && result E10c PASS || result E10c FAIL
r=$(ACTENON_ENV= $PY -W ignore -c "
from actenon.proof.signers.local import build_local_proof_signer
try:
    build_local_proof_signer(); print('edge verifier with public secret CONSTRUCTED')
except Exception as e: print('REFUSED', type(e).__name__)" 2>>"$OUT/stderr.txt"); echo "  verifier rooted in the public dev secret, ACTENON_ENV empty: $r"
has "$r" REFUSED && result E10d PASS || result E10d FAIL

cp "$W/p1.json" "$OUT/proof-E1.json"
echo "## TOTAL FAILS: $FAILS"
