#!/usr/bin/env bash
# OLD-PUBLISHED CONTROL. Installs what the PUBLIC registries serve today with each ecosystem's normal tool
# (no rehearsal registry, no source tree) and runs the CURRENT release vectors against it. Every family is
# expected to FAIL; a pass here would mean the current vectors cannot tell the fixed release from the old one.
#
#   run_published_controls.sh REHEARSAL_ARTEFACT_DIR OUT_DIR PROTOCOL_TAG_ARCHIVE
#
# The current vectors come from the rehearsal actenon-kernel wheel (installed, so its vectors sit under
# site-packages) and the protocol release tag archive -- never from a checkout.
set -euo pipefail
REL=$(cd "${1:?REHEARSAL_ARTEFACT_DIR}" && pwd); OUT=$(mkdir -p "${2:?OUT_DIR}" && cd "$2" && pwd)
ARCHIVE=$(cd "$(dirname "${3:?PROTOCOL_TAG_ARCHIVE}")" && pwd)/$(basename "$3")
HERE=$(cd "$(dirname "$0")" && pwd); FC="$HERE/../fresh-consumer"; DIFF=$(cd "$HERE/../../differential" && pwd)
NSDIFF=$(cd "$HERE/../differential" && pwd); DIFF2=$(cd "$HERE/../../phase2/differential" && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/actenon-controls.XXXXXX"); case "$W" in /home/user/*) exit 2;; esac
trap 'rm -rf "${W:?}"' EXIT
LOG="$OUT/controls.log"; : > "$LOG"; RES="$OUT/controls.tsv"; printf 'family\tartefact\tobserved\tdetail\n' > "$RES"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
row() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RES"; log "CONTROL $1 $2: $3 ($4)"; }
mkdir -p "$W/home" "$W/tmp"
cenv() {
  env -i PATH=/usr/local/go/bin:/root/.cargo/bin:/opt/node22/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin \
    HOME="$W/home" TMPDIR="$W/tmp" LANG=C.UTF-8 \
    HTTPS_PROXY="${HTTPS_PROXY:-}" https_proxy="${https_proxy:-}" NO_PROXY="${NO_PROXY:-}" no_proxy="${no_proxy:-}" \
    SSL_CERT_FILE="${SSL_CERT_FILE:-}" PIP_CERT="${PIP_CERT:-}" REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-}" \
    NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-}" CARGO_HTTP_CAINFO="${CARGO_HTTP_CAINFO:-}" \
    npm_config_https_proxy="${npm_config_https_proxy:-}" npm_config_noproxy="${npm_config_noproxy:-}" \
    npm_config_cache="$W/npm-cache" PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GOPATH="$W/gopath" GOCACHE="$W/gocache" GOTOOLCHAIN=local GOFLAGS=-mod=mod \
    CARGO_HOME="$W/cargo-home" RUSTUP_HOME=/root/.rustup CARGO_TERM_COLOR=never "$@"
}

# Current vectors: the rehearsal kernel wheel, installed without dependencies (data only is used).
cenv /usr/bin/python3.12 -m venv "$W/vec"; cenv "$W/vec/bin/pip" install -q --no-deps "$REL"/pypi/actenon_kernel-*.whl >> "$LOG" 2>&1
VSITE=$(ls -d "$W"/vec/lib/python3.12/site-packages); VECTORS="$VSITE/actenon/conformance/vectors/verifier_sdk_v1"
log "current vectors: $VECTORS ($(cenv "$W/vec/bin/python" -c 'import importlib.metadata as m;print("actenon-kernel", m.version("actenon-kernel"))'))"
mkdir -p "$W/ptag" && tar -xzf "$ARCHIVE" -C "$W/ptag" --strip-components=1

# 1. Python: actenon-kernel from PyPI (what `pip install actenon-kernel` gives today).
cenv /usr/bin/python3.12 -m venv "$W/py"; cenv "$W/py/bin/pip" install -q actenon-kernel pytest >> "$LOG" 2>&1
KV=$(cenv "$W/py/bin/python" -c 'import importlib.metadata as m;print(m.version("actenon-kernel"))'); log "PyPI actenon-kernel resolved to $KV"
mkdir -p "$W/pyt/vectors" && cp "$VSITE/actenon/conformance/test_verifier_sdk_conformance.py" "$W/pyt/" && cp -r "$VECTORS" "$W/pyt/vectors/"
( cd "$W/pyt" && cenv ACTENON_ENV=test "$W/py/bin/python" -I -m pytest -q -p no:cacheprovider test_verifier_sdk_conformance.py ) > "$OUT/python-kernel-$KV-current-vectors.txt" 2>&1 \
  && row python "actenon-kernel $KV (PyPI)" PASS "current verifier vectors" \
  || row python "actenon-kernel $KV (PyPI)" FAIL "current verifier vectors: $(tail -1 "$OUT/python-kernel-$KV-current-vectors.txt")"
for c in "diff:$DIFF/corpus" "diffadd:$DIFF/corpus-addendum-precision" "difftsg:$NSDIFF/corpus-addendum-timestamp-grammar"; do
  ( cd "$W/pyt" && cenv ACTENON_ENV=test "$W/py/bin/python" -I "$DIFF/runner_py.py" "${c#*:}" "$OUT/${c%%:*}-python-kernel-$KV-published.jsonl" "python-kernel-$KV-published" ) >> "$LOG" 2>&1 || true
done

# 2. TypeScript: @actenon/verifier-sdk from npmjs.
mkdir -p "$W/ts"; ( cd "$W/ts" && cenv npm init -y >/dev/null && cenv npm install --no-audit --no-fund @actenon/verifier-sdk ) > "$OUT/ts-verifier-sdk-install.txt" 2>&1 \
  && { ( cd "$W/ts" && cenv node "$FC/harness/ts/check_ts_vectors.mjs" "$W/ts" "$VECTORS" ) > "$OUT/ts-verifier-sdk-current-vectors.txt" 2>&1 \
       && row ts "@actenon/verifier-sdk (npm)" PASS "current vectors" || row ts "@actenon/verifier-sdk (npm)" FAIL "current vectors"; } \
  || row ts "@actenon/verifier-sdk (npm)" FAIL "not installable: $(grep -m1 -o 'E404.*' "$OUT/ts-verifier-sdk-install.txt" || tail -1 "$OUT/ts-verifier-sdk-install.txt")"
for spec in "@actenon/protocol-types:canonicalizeJson" "@actenon/sdk:verifyGrantToken"; do
  name=${spec%%:*}; exp=${spec#*:}; d="$W/imp-$(printf '%s' "$name" | tr -c 'a-z0-9' '-')"; mkdir -p "$d"  # npm init needs a valid package name
  ( cd "$d" && cenv npm init -y >/dev/null && cenv npm install --no-audit --no-fund "$name" >/dev/null \
    && cenv node -e 'const p=require("./node_modules/'"$name"'/package.json");console.log(p.name,p.version)' \
    && cenv node --input-type=module -e "const m = await import('$name'); if (!('$exp' in m)) throw new Error('missing export $exp'); console.log('import OK')" ) > "$OUT/import-${name//\//-}.txt" 2>&1 \
    && row ts "$name $(head -1 "$OUT/import-${name//\//-}.txt" | cut -d' ' -f2) (npm)" PASS "plain-node import exposes $exp" \
    || row ts "$name $(head -1 "$OUT/import-${name//\//-}.txt" | cut -d' ' -f2) (npm)" FAIL "plain-node import: $(grep -m1 -E 'Error|ERR_' "$OUT/import-${name//\//-}.txt" | cut -c1-160)"
done

# 3. Go: github.com/Actenon/sdk-go@latest through proxy.golang.org (checksum database on).
mkdir -p "$W/go"; ( cd "$W/go" && cenv go mod init example.com/control && cenv go get github.com/Actenon/sdk-go@latest ) >> "$LOG" 2>&1
GV=$(cd "$W/go" && cenv go list -m -f '{{.Version}}' github.com/Actenon/sdk-go); log "proxy.golang.org sdk-go@latest = $GV"
cp "$FC"/harness/go/*_test.go "$W/go/"
( cd "$W/go" && cenv ACTENON_VECTORS="$VECTORS" go test -count=1 ./... ) > "$OUT/go-sdk-$GV-current-vectors.txt" 2>&1 \
  && row go "sdk-go $GV (proxy.golang.org)" PASS "current vectors via public API" \
  || row go "sdk-go $GV (proxy.golang.org)" FAIL "current vectors via public API: $(grep -m1 -E 'undefined|FAIL|cannot' "$OUT/go-sdk-$GV-current-vectors.txt" | cut -c1-160)"
# Same corpora through the frozen differential runner, which compiles against v1.0.0's API (no ed25519 tag).
R="$W/go-runner"; mkdir -p "$R"; cp "$DIFF"/runner_go/*.go "$R/"
( cd "$R" && cenv go mod init example.com/runner && cenv go get "github.com/Actenon/sdk-go@$GV" && cenv go build -o runner . \
  && for c in "diff:$DIFF/corpus" "diffadd:$DIFF/corpus-addendum-precision" "difftsg:$NSDIFF/corpus-addendum-timestamp-grammar"; do ./runner "${c#*:}" "$OUT/${c%%:*}-go-sdk-$GV-published.jsonl" "go-sdk-$GV-published"; done ) >> "$LOG" 2>&1 || log "go differential runner against $GV did not complete"

# 4. Rust: actenon-verifier-sdk from crates.io.
mkdir -p "$W/rs/src"; printf '[package]\nname = "control"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nactenon-verifier-sdk = "0.2"\n' > "$W/rs/Cargo.toml"; echo 'fn main() {}' > "$W/rs/src/main.rs"
( cd "$W/rs" && cenv cargo generate-lockfile ) > "$OUT/rust-crate-resolve.txt" 2>&1 \
  && row rust "actenon-verifier-sdk (crates.io)" PASS "resolved" \
  || row rust "actenon-verifier-sdk (crates.io)" FAIL "not resolvable: $(grep -m1 -E 'error|no matching' "$OUT/rust-crate-resolve.txt" | cut -c1-160)"

# 5. Protocol: actenon-protocol from PyPI against the release tag's runner and vectors (outside a checkout).
cenv /usr/bin/python3.12 -m venv "$W/pp"; cenv "$W/pp/bin/pip" install -q "actenon-protocol[conformance,types]" >> "$LOG" 2>&1
PV=$(cenv "$W/pp/bin/python" -c 'import importlib.metadata as m;print(m.version("actenon-protocol"))')
( cd "$W" && cenv "$W/pp/bin/python" -I -c "
import sys, runpy, actenon_protocol
sys.argv = ['runner.py']
runpy.run_path('$W/ptag/conformance/runner.py', run_name='__main__')" ) > "$OUT/protocol-$PV-current-runner.txt" 2>&1 \
  && row python "actenon-protocol $PV (PyPI)" PASS "release-tag conformance runner" \
  || row python "actenon-protocol $PV (PyPI)" FAIL "release-tag conformance runner: $(grep -m1 -E 'Error|FAIL|Failed' "$OUT/protocol-$PV-current-runner.txt" | cut -c1-160)"

# 5b. Control v2 (run 1 showed the in-archive runner is non-discriminating: 1.4.0 changes no wire format and the
# archive carries schemas/). 1.4.0's actual change: the standalone runner works outside a checkout, from the
# installed package's schemas alone. Copy runner.py + vectors (no schemas/) and run it against PyPI's package.
mkdir -p "$W/standalone/conformance" && cp "$W/ptag/conformance/runner.py" "$W/standalone/conformance/" && cp -r "$W/ptag/conformance/vectors" "$W/standalone/conformance/"
( cd "$W/standalone" && cenv "$W/pp/bin/python" -I conformance/runner.py ) > "$OUT/protocol-$PV-standalone-runner.txt" 2>&1 \
  && row python "actenon-protocol $PV (PyPI) [control v2]" PASS "standalone runner, installed schemas only" \
  || row python "actenon-protocol $PV (PyPI) [control v2]" FAIL "standalone runner, installed schemas only: $(grep -m1 -E 'Error|KeyError' "$OUT/protocol-$PV-standalone-runner.txt" | cut -c1-160)"

# Row 5 (in-archive runner) is NOT a discriminating control (see runs/rehearsal-2-controls-run1/README.md):
# it is reported, and excluded from the expected-failure accounting.
FAILS=$(awk -F'\t' 'NR>1 && $3=="FAIL"' "$RES" | wc -l); PASSES=$(awk -F'\t' 'NR>1 && $3=="PASS" && $4 != "release-tag conformance runner"' "$RES" | wc -l)
log "controls: $FAILS expected failures observed, $PASSES unexpected passes"
exit $((PASSES > 0))
