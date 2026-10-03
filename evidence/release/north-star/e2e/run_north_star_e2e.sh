#!/usr/bin/env bash
# North-star FULL E2E driver: consumers built ONLY from the release artefacts (served by the rehearsal
# registry, exactly as in fresh-consumer/), then run_full_e2e.sh twice: replay on SQLite (the phase-2
# configuration) and replay on a real PostgreSQL 16 server.
#   run_north_star_e2e.sh ARTEFACT_DIR OUT_DIR
set -euo pipefail
REL=$(cd "${1:?ARTEFACT_DIR}" && pwd); OUT=$(mkdir -p "${2:?OUT_DIR}" && cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd); FC="$HERE/../fresh-consumer"
W=$(mktemp -d "${TMPDIR:-/tmp}/actenon-e2e.XXXXXX"); case "$W" in /home/user/*) exit 2;; esac
PORT=${PORT:-18766}; REG=http://127.0.0.1:$PORT; PGPORT=${PGPORT:-5545}
# The server runs as the postgres user, which cannot traverse a root-only TMPDIR: own directory under /tmp.
PG=$(mktemp -d /tmp/actenon-e2e-pg.XXXXXX); chmod 755 "$PG"
python3 "$FC/local_registry.py" "$REL" "$PORT" 2> "$OUT/registry-access.log" & REGPID=$!
cleanup() {
  su postgres -s /bin/bash -c "/usr/lib/postgresql/16/bin/pg_ctl -D '$PG/data' -m fast stop" >/dev/null 2>&1 || true
  kill "$REGPID" 2>/dev/null || true; rm -rf "${W:?}" "${PG:?}"
}
trap cleanup EXIT
for _ in $(seq 50); do curl -fs "$REG/cargo/index/config.json" >/dev/null 2>&1 && break; sleep 0.1; done
mkdir -p "$W/home" "$W/tmp"
cenv() {
  env -i PATH=/usr/local/go/bin:/root/.cargo/bin:/opt/node22/bin:/usr/local/bin:/usr/bin:/bin \
    HOME="$W/home" TMPDIR="$W/tmp" LANG=C.UTF-8 \
    HTTPS_PROXY="${HTTPS_PROXY:-}" https_proxy="${https_proxy:-}" NO_PROXY="${NO_PROXY:-}" no_proxy="${no_proxy:-}" \
    SSL_CERT_FILE="${SSL_CERT_FILE:-}" PIP_CERT="${PIP_CERT:-}" REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-}" \
    NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-}" CARGO_HTTP_CAINFO="${CARGO_HTTP_CAINFO:-}" \
    npm_config_https_proxy="${npm_config_https_proxy:-}" npm_config_noproxy="${npm_config_noproxy:-}" \
    npm_config_cache="$W/npm-cache" PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GOPATH="$W/gopath" GOCACHE="$W/gocache" GOTOOLCHAIN=local GOFLAGS=-mod=mod \
    GOPROXY="file://$REL/goproxy,https://proxy.golang.org" GONOSUMDB=github.com/Actenon/sdk-go \
    CARGO_HOME="$W/cargo-home" RUSTUP_HOME=/root/.rustup CARGO_TERM_COLOR=never "$@"
}
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/driver.log"; }

log "consumers from $REL ($(head -c 300 "$REL/SOURCE_COMMITS" | tr '\n' ' '))"
cenv /usr/bin/python3.12 -m venv "$W/py"
cenv "$W/py/bin/pip" install -q --extra-index-url "$REG/pypi/simple" --trusted-host 127.0.0.1 \
  actenon-permit "actenon-kernel[postgres]" actenon-protocol >> "$OUT/driver.log" 2>&1
cenv "$W/py/bin/python" -I -c 'import importlib.metadata as m; print({d: m.version(d) for d in ("actenon-kernel","actenon-permit","actenon-protocol","psycopg")})' | tee -a "$OUT/driver.log"
mkdir -p "$W/ts"; ( cd "$W/ts" && cenv npm init -y >/dev/null && echo "@actenon:registry=$REG/npm/" > .npmrc \
  && cenv npm install --no-audit --no-fund @actenon/verifier-sdk ) >> "$OUT/driver.log" 2>&1
cp -r "$HERE/go_edge" "$W/go_edge"; ( cd "$W/go_edge" && cenv go mod init example.com/goedge \
  && cenv go get github.com/Actenon/sdk-go@v1.1.0 modernc.org/sqlite@v1.38.2 && cenv go build -o go_edge . \
  && cenv go list -m github.com/Actenon/sdk-go ) >> "$OUT/driver.log" 2>&1
cp -r "$HERE/rust_edge" "$W/rust_edge"; mkdir -p "$W/rust_edge/.cargo"; cat > "$W/rust_edge/.cargo/config.toml" <<CFG
[registries.actenon-rehearsal]
index = "sparse+$REG/cargo/index/"
[patch.crates-io]
actenon-verifier-sdk = { version = "=0.2.0", registry = "actenon-rehearsal" }
CFG
( cd "$W/rust_edge" && cenv cargo build -q --release ) >> "$OUT/driver.log" 2>&1
grep -A2 'name = "actenon-verifier-sdk"' "$W/rust_edge/Cargo.lock" | tee -a "$OUT/driver.log"
export GO_EDGE="$W/go_edge/go_edge" RUST_EDGE="$W/rust_edge/target/release/rust-edge"

chown postgres:postgres "$PG"
su postgres -s /bin/bash -c "/usr/lib/postgresql/16/bin/initdb -D '$PG/data' -A trust -U postgres >/dev/null && /usr/lib/postgresql/16/bin/pg_ctl -D '$PG/data' -o \"-p $PGPORT -k $PG -c listen_addresses=''\" -l '$PG/log' start >/dev/null"
DSN="host=$PG port=$PGPORT user=postgres dbname=postgres"; log "PostgreSQL $(psql "$DSN" -Atc 'show server_version') at $PG:$PGPORT"

RC=0
for mode in sqlite postgres; do
  log "== run_full_e2e.sh, replay store: $mode"
  extra=(); [ "$mode" = postgres ] && extra=(E2E_REPLAY_DSN="$DSN")
  cenv "${extra[@]}" GO_EDGE="$GO_EDGE" RUST_EDGE="$RUST_EDGE" bash "$HERE/run_full_e2e.sh" "$W/py/bin/python" "$W/ts" "$OUT/out-$mode" > "$OUT/e2e-$mode.txt" 2>&1 || true
  grep -E '^RESULT|TOTAL' "$OUT/e2e-$mode.txt" | tee -a "$OUT/driver.log"
  grep -q '^## TOTAL FAILS: 0$' "$OUT/e2e-$mode.txt" || RC=1
done
psql "$DSN" -Atc "select status, count(*) from action_consumption group by status order by 1" | sed 's/^/postgres action_consumption: /' | tee -a "$OUT/driver.log"
exit $RC
