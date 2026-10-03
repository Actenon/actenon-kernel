#!/usr/bin/env bash
# Single use through PostgresReplayStore against a real PostgreSQL 16 server (built kernel wheel).
# usage: run_pg.sh <venv-python> <dsn> <outdir>
set -u
PY=$1; DSN=$2; OUT=$3; HERE=$(cd "$(dirname "$0")" && pwd); H1=$HERE/../h1h2
mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"; export ACTENON_ENV=production; unset ACTENON_REPLAY_DB
echo "## $($PY -c "import importlib.metadata as m;print({p:m.version(p) for p in ('actenon-kernel','psycopg')})") server=$(psql "$DSN" -Atc 'show server_version')"
ACTENON_REPLAY_DB="$W/issuer.sqlite3" $PY "$H1/h1_issuer.py" "$W/proof.json" >/dev/null
: > "$W/ledger"
for w in A B C D; do $PY "$HERE/pg_worker.py" "$W/proof.json" "$DSN" "$W/ledger" worker$w 8 & done; wait
echo "  4 worker processes x 8 concurrent presentations: side effects = $(wc -l < "$W/ledger")"
r=$($PY "$HERE/pg_worker.py" "$W/proof.json" "$DSN" "$W/ledger" workerA-restarted 1); echo "  restarted worker: $r"
n=$(wc -l < "$W/ledger"); [ "$n" = 1 ] && echo "$r" | grep -q DUPLICATE_REPLAY && echo "RESULT PG1: PASS (exactly one execution)" || echo "RESULT PG1: FAIL ($n executions)"
ACTENON_REPLAY_DB="$W/issuer2.sqlite3" $PY "$H1/h1_issuer.py" "$W/proof2.json" >/dev/null
r=$($PY "$HERE/pg_worker.py" "$W/proof2.json" "postgresql://postgres@/actenon_e2e?host=/nonexistent&port=1" "$W/ledger2" unreachable 1); echo "  unreachable database: $r"
[ ! -s "$W/ledger2" ] && ! echo "$r" | grep -q '"executed"' && echo "RESULT PG2: PASS (fail closed, no execution)" || echo "RESULT PG2: FAIL"
psql "$DSN" -Atc "select status, count(*) from action_consumption group by status" | sed 's/^/  db: /'
if [ -n "${PG_CTL_STOP:-}" ]; then
  ACTENON_REPLAY_DB="$W/issuer3.sqlite3" $PY "$H1/h1_issuer.py" "$W/proof3.json" >/dev/null
  PG_WAIT_FILE="$W/go" $PY "$HERE/pg_worker.py" "$W/proof3.json" "$DSN" "$W/ledger3" outage 1 > "$W/outage.out" &
  until grep -q constructed "$W/outage.out" 2>/dev/null; do sleep 0.2; done
  eval "$PG_CTL_STOP"; touch "$W/go"; wait
  echo "  database stopped after the edge started: $(tail -1 "$W/outage.out")"
  [ ! -s "$W/ledger3" ] && grep -q '"refused"' "$W/outage.out" && echo "RESULT PG3: PASS (fail closed mid-operation)" || echo "RESULT PG3: FAIL"
  eval "$PG_CTL_START"
fi
