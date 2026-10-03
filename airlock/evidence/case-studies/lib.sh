# Shared helpers for the external-agent case studies (sourced by each run.sh).
# Requires: AIRLOCK (path to the airlock CLI), PY (python for the stand-ins), STANDIN (tests/standin.py), OUT (evidence dir).
set -euo pipefail
now() { python3 -c 'import time; print(time.time())'; }
elapsed() { python3 -c "print(round($2 - $1, 1))"; }
start_standin() {  # name, extra args... ; writes $OUT/<name>.port and .pid
  local name=$1; shift
  "$PY" "$STANDIN" --log "$OUT/upstream-$name.jsonl" "$@" > "$OUT/.$name.port" 2> "$OUT/.$name.err" &
  echo $! > "$OUT/.$name.pid"
  for _ in $(seq 50); do [ -s "$OUT/.$name.port" ] && break; sleep 0.1; done
  cat "$OUT/.$name.port"
}
stop_standins() { for p in "$OUT"/.*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; rm -f "$p"; done; }
scrub() {  # make logs portable: replace machine-specific paths
  sed -E -e "s#$WORK#<work>#g" -e "s#/tmp/claude-[^/ ]*/[^ ]*/scratchpad#<scratch>#g" -e "s#/tmp/claude-[0-9]+/[^ ]*#<scratch>#g" -e "s#$HOME#<home>#g" "$@"
}
