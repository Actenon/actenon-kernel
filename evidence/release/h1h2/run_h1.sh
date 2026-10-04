#!/usr/bin/env bash
# H1 reproduction. Usage: run_h1.sh <python-of-clean-venv> <outdir> <ACTENON_ENV value | __unset__>
# Each worker is a separate OS process (= a separate gunicorn/uvicorn worker or a restart).
set -u
PY=$1; OUT=$2; ENVV=$3; HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"   # cwd outside any source tree
if [ "$ENVV" = "__unset__" ]; then unset ACTENON_ENV; else export ACTENON_ENV="$ENVV"; fi
unset ACTENON_REPLAY_DB ACTENON_PRODUCTION
echo "## ACTENON_ENV=${ACTENON_ENV-<unset>}  versions: $($PY -c "import importlib.metadata as m;print({p:m.version(p) for p in ('actenon-kernel','actenon-protocol')})")"
run() { "$PY" "$@" 2>"$OUT/stderr.$RANDOM.txt"; rc=$?; [ $rc -ne 0 ] && echo "   (exit $rc) $(tail -1 "$(ls -t "$OUT"/stderr.*.txt | head -1)")"; return 0; }
echo "### scenario A: default replay store (nothing configured)"
run "$HERE/h1_issuer.py" "$OUT/proof-A.json"
: > "$OUT/ledger-A.txt"
run "$HERE/h1_worker.py" "$OUT/proof-A.json" "$OUT/ledger-A.txt" workerA 2
run "$HERE/h1_worker.py" "$OUT/proof-A.json" "$OUT/ledger-A.txt" workerB 1
run "$HERE/h1_worker.py" "$OUT/proof-A.json" "$OUT/ledger-A.txt" workerA-restarted 1
echo "RESULT A: side effects executed for ONE single-use proof = $(wc -l < "$OUT/ledger-A.txt")"
echo "### scenario B (control): ACTENON_REPLAY_DB = one shared durable file"
export ACTENON_REPLAY_DB="$W/shared-replay.sqlite3"
run "$HERE/h1_issuer.py" "$OUT/proof-B.json"
: > "$OUT/ledger-B.txt"
run "$HERE/h1_worker.py" "$OUT/proof-B.json" "$OUT/ledger-B.txt" workerA 2
run "$HERE/h1_worker.py" "$OUT/proof-B.json" "$OUT/ledger-B.txt" workerB 1
run "$HERE/h1_worker.py" "$OUT/proof-B.json" "$OUT/ledger-B.txt" workerA-restarted 1
echo "RESULT B: side effects executed for ONE single-use proof = $(wc -l < "$OUT/ledger-B.txt")"
