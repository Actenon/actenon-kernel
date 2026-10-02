#!/usr/bin/env bash
# H2 reproduction. Usage: run_h2.sh <python-of-clean-venv> <outfile.jsonl>
PY=$1; OUT=$2; HERE=$(cd "$(dirname "$0")" && pwd); W=$(mktemp -d); cd "$W"
unset ACTENON_PRODUCTION ACTENON_CI_RELEASE ACTENON_RELEASE_BUILD ACTENON_LOCAL_HMAC_SECRET
$PY "$HERE/h2_attacker_forge.py" "$W/forged.json" 2>/dev/null
: > "$OUT"
( unset ACTENON_ENV; $PY "$HERE/h2_victim_probe.py" "$W/forged.json" 2>/dev/null >> "$OUT" )
for e in "" dev development local test demo prod production PRODUCTION " production " staging ci release prd live prod-eu production-eu Prod_EU uat preprod qa sandbox perf; do
  ACTENON_ENV="$e" $PY "$HERE/h2_victim_probe.py" "$W/forged.json" 2>/dev/null >> "$OUT"
done
$PY - "$OUT" <<'PYEOF'
import json,sys
rows=[json.loads(l) for l in open(sys.argv[1])]
keys=[k for k in rows[0] if k!="ACTENON_ENV"]
print("| ACTENON_ENV | "+" | ".join(keys)+" |"); print("|"+"---|"*(len(keys)+1))
for r in rows: print(f"| `{r['ACTENON_ENV']!r}` | "+" | ".join(r[k] for k in keys)+" |")
PYEOF
