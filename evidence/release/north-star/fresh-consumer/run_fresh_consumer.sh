#!/usr/bin/env bash
# FRESH-CONSUMER-TEST (release rehearsal). A consumer with no Actenon source tree installs the release
# artefacts with its normal package manager and runs the public API, the conformance vectors, the frozen
# differential corpus and the documented quickstarts.
#
#   run_fresh_consumer.sh ARTEFACT_DIR OUT_DIR PROTOCOL_TAG_ARCHIVE
#
# ARTEFACT_DIR          output of rehearsal/build_release_artefacts.sh (pypi/ npm/ crates/ goproxy/ SHA256SUMS)
# PROTOCOL_TAG_ARCHIVE  tar.gz of the protocol release tag (what GitHub serves at /archive/refs/tags/vX.tar.gz);
#                       used ONLY for the protocol's conformance vectors, which no package ships.
#
# Isolation: every consumer command runs under `env -i` with the toolchain PATH, a fresh HOME and fresh
# pip/npm/Go/Cargo caches, and only the network plumbing of this machine (proxy + CA bundle). The artefacts
# are served by local_registry.py over the registries' own protocols; everything else comes from the public
# registries. No consumer path is under /home/user (where the Actenon checkouts live): each run asserts the
# installed module/package/crate locations and that the source tree is absent from module resolution.
set -euo pipefail
REL=$(cd "${1:?ARTEFACT_DIR}" && pwd); OUT=$(mkdir -p "${2:?OUT_DIR}" && cd "$2" && pwd); ARCHIVE=$(cd "$(dirname "${3:?PROTOCOL_TAG_ARCHIVE}")" && pwd)/$(basename "$3")
HERE=$(cd "$(dirname "$0")" && pwd); DIFF=$(cd "$HERE/../../differential" && pwd); DIFF2=$(cd "$HERE/../../phase2/differential" && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/actenon-fresh-consumer.XXXXXX"); case "$W" in /home/user/*) echo "work dir must be outside the checkouts"; exit 2;; esac
PORT=${PORT:-18765}; REG=http://127.0.0.1:$PORT
EXP_KERNEL=1.3.0 EXP_PERMIT=2.0.0 EXP_PROTOCOL=1.4.0 EXP_VSDK=0.2.0 EXP_TSSDK=2.0.0 EXP_PTYPES=1.4.0 EXP_GO=v1.1.0 EXP_CRATE=0.2.0
LOG="$OUT/fresh-consumer.log"; : > "$LOG"; RESULTS="$OUT/results.tsv"; printf 'step\tresult\n' > "$RESULTS"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
record() { printf '%s\t%s\n' "$1" "$2" >> "$RESULTS"; log "RESULT $1: $2"; }
python3 "$HERE/local_registry.py" "$REL" "$PORT" 2> "$OUT/registry-access.log" & REGPID=$!
cleanup() { kill "$REGPID" 2>/dev/null || true; rm -rf "${W:?}"; }
trap cleanup EXIT
for _ in $(seq 50); do curl -fs "$REG/cargo/index/config.json" >/dev/null 2>&1 && break; sleep 0.1; done

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
    GOPROXY="file://$REL/goproxy,https://proxy.golang.org" GONOSUMDB=github.com/Actenon/sdk-go \
    CARGO_HOME="$W/cargo-home" RUSTUP_HOME=/root/.rustup CARGO_TERM_COLOR=never \
    "$@"
}
sha() { sha256sum "$1" | cut -d' ' -f1; }
NSDIFF=$(cd "$HERE/../differential" && pwd)
CORPORA="diff:$DIFF/corpus diffadd:$DIFF/corpus-addendum-precision difftsg:$NSDIFF/corpus-addendum-timestamp-grammar"
# run_corpora IMPL_STEM LABEL CMD... : CMD CORPUS OUT.jsonl LABEL for every frozen corpus
run_corpora() { local stem=$1 label=$2; shift 2; local c; for c in $CORPORA; do "$@" "${c#*:}" "$OUT/${c%%:*}-$stem.jsonl" "$label" || return 1; done; }
log "artefacts: $REL"; log "work dir: $W"; cp "$REL/SHA256SUMS" "$OUT/ARTEFACT-SHA256SUMS"; cp "$REL/SOURCE_COMMITS" "$OUT/" 2>/dev/null || true
log "protocol tag archive: $ARCHIVE sha256=$(sha "$ARCHIVE")"

# ---------------------------------------------------------------- Python (each supported interpreter)
py_consumer() {
  local py=$1 label=$2
  local d="$W/py-$label"; mkdir -p "$d/cwd"
  # actenon-permit declares Requires-Python >=3.11; on older interpreters it is not installable by design.
  local permit=actenon-permit; [ "$label" = py310 ] && permit=""
  log "== python $label ($py)"
  cenv "$py" -m venv "$d/venv"
  ( cd "$d/cwd" && cenv "$d/venv/bin/pip" install -q --report "$d/pip-report.json" \
      --extra-index-url "$REG/pypi/simple" --trusted-host 127.0.0.1 \
      $permit actenon-kernel "actenon-protocol[conformance,types]" pytest ) >> "$LOG" 2>&1
  cp "$d/pip-report.json" "$OUT/pip-report-$label.json"
  # Provenance: each Actenon distribution came from the rehearsal registry, at the expected version, with the digest in SHA256SUMS.
  python3 - "$d/pip-report.json" "$REL/SHA256SUMS" "$REG" "$permit" <<'EOF' | tee -a "$LOG"
import json, sys
report, sums, reg = json.load(open(sys.argv[1])), {}, sys.argv[3]
for line in open(sys.argv[2]):
    h, f = line.split(); sums[f.split("/")[-1]] = h
want = {"actenon-kernel": "1.3.0", "actenon-permit": "2.0.0", "actenon-protocol": "1.4.0"}
if not sys.argv[4]: del want["actenon-permit"]
seen = {}
for item in report["install"]:
    name, ver = item["metadata"]["name"], item["metadata"]["version"]
    if name in want:
        url = item["download_info"]["url"]; h = item["download_info"]["archive_info"]["hashes"]["sha256"]
        ok = ver == want[name] and url.startswith(reg) and sums.get(url.split("/")[-1]) == h
        print(f"{'OK  ' if ok else 'FAIL'} {name} {ver} from {url} sha256={h}"); seen[name] = ok
missing = set(want) - set(seen)
if missing or not all(seen.values()): print("FAIL provenance", missing); sys.exit(1)
EOF
  # Shadowing guard: modules resolve to this venv, and no /home/user path is importable.
  ( cd "$d/cwd" && cenv "$d/venv/bin/python" -I -c '
import sys, importlib, importlib.metadata as m
venv = sys.prefix
mods = [importlib.import_module(n) for n in ("actenon", "actenon_protocol")]
try:
    mods.append(importlib.import_module("actenon_permit"))
except ModuleNotFoundError:
    assert sys.version_info < (3, 11)
for mod in mods:
    assert mod.__file__.startswith(venv) and "site-packages" in mod.__file__, mod.__file__
assert not [p for p in sys.path if p.startswith("/home/user")], sys.path
print("resolved:", {d.metadata["Name"]: d.version for d in m.distributions() if d.metadata["Name"].startswith("actenon")}, "python", sys.version.split()[0])
' ) | tee -a "$LOG"
  SITE=$(cenv "$d/venv/bin/python" -I -c 'import actenon,os;print(os.path.dirname(os.path.dirname(actenon.__file__)))')
  # 1. Kernel conformance suite shipped in the wheel, run from site-packages.
  ( cd "$d/cwd" && cenv ACTENON_ENV=test "$d/venv/bin/python" -I -m pytest -q -p no:cacheprovider --rootdir "$d/cwd" --pyargs actenon.conformance ) > "$OUT/py-$label-kernel-conformance.txt" 2>&1 \
    && record "python-$label kernel conformance (shipped suite)" PASS || record "python-$label kernel conformance (shipped suite)" FAIL
  tail -1 "$OUT/py-$label-kernel-conformance.txt" | tee -a "$LOG"
  # 2. The scanner CLI on a consequential call (registry is package data: regression of phase-2 counterexample).
  mkdir -p "$d/cwd/scan" && printf 'def refund(amount):\n    return stripe.Refund.create(amount=amount)\n' > "$d/cwd/scan/app.py"
  ( cd "$d/cwd" && cenv "$d/venv/bin/actenon-kernel" scan repo --path scan ) > "$OUT/py-$label-scan.txt" 2>&1 || true
  grep -q '^Overall status: EXECUTION_GAP_PRESENT' "$OUT/py-$label-scan.txt" && ! grep -q '^ERROR:' "$OUT/py-$label-scan.txt" \
    && record "python-$label actenon-kernel scan" PASS || record "python-$label actenon-kernel scan" FAIL
  # 3. Protocol conformance: installed actenon_protocol against the release tag's hash-locked vectors.
  local pa="$W/protocol-tag"; [ -d "$pa" ] || { mkdir -p "$pa" && tar -xzf "$ARCHIVE" -C "$pa" --strip-components=1; }
  # vectors.sha256 lists paths relative to conformance/vectors/ (as scripts/check_vector_lock.py reads it).
  ( cd "$pa/conformance/vectors" && sha256sum -c --strict ../vectors.sha256 | tail -3 && echo "$(wc -l < ../vectors.sha256) files hash-locked" ) > "$OUT/protocol-vectors-sha256-check.txt" 2>&1 \
    && record "protocol tag vectors match vectors.sha256" PASS || record "protocol tag vectors match vectors.sha256" FAIL
  ( cd "$d/cwd" && cenv "$d/venv/bin/python" -I -c "
import sys, runpy, actenon_protocol
assert 'site-packages' in actenon_protocol.__file__, actenon_protocol.__file__
sys.argv = ['runner.py']
runpy.run_path('$pa/conformance/runner.py', run_name='__main__')" ) > "$OUT/py-$label-protocol-runner.txt" 2>&1 \
    && grep -q 'Actenon-compatible v1.4.0' "$OUT/py-$label-protocol-runner.txt" \
    && record "python-$label protocol conformance runner (Actenon-compatible v1.4.0)" PASS || record "python-$label protocol conformance runner" FAIL
  ( cd "$d/cwd" && cenv "$d/venv/bin/python" -I -m actenon_protocol.conformance_canonicalisation --vectors "$pa/conformance/vectors/canonicalisation" ) \
    > "$OUT/py-$label-protocol-canonicalisation.txt" 2>&1 \
    && record "python-$label protocol canonicalisation vectors" PASS || record "python-$label protocol canonicalisation vectors" FAIL
  # 4. Permit: the README quickstart exactly as PyPI renders it (from the installed METADATA), and the CLI demo.
  if [ -z "$permit" ]; then record "python-$label permit steps" "N/A (actenon-permit Requires-Python >=3.11)"; else
  cenv "$d/venv/bin/python" -I -c '
import importlib.metadata as m, re
desc = m.metadata("actenon-permit").get_payload()
blocks = re.findall(r"```python\n(.*?)```", desc, re.S)
open("'"$d"'/permit_quickstart.py", "w").write(blocks[0])'
  cp "$d/permit_quickstart.py" "$OUT/permit-readme-quickstart-block1.py"
  ( cd "$d/cwd" && cenv "$d/venv/bin/python" -I "$d/permit_quickstart.py" ) > "$OUT/py-$label-permit-quickstart.txt" 2>&1 \
    && grep -q 'succeeded  final' "$OUT/py-$label-permit-quickstart.txt" \
    && record "python-$label permit README quickstart" PASS || record "python-$label permit README quickstart" FAIL
  ( cd "$d/cwd" && cenv "$d/venv/bin/actenon" demo ) > "$OUT/py-$label-permit-demo.txt" 2>&1 \
    && record "python-$label 'actenon demo'" PASS || record "python-$label 'actenon demo'" FAIL
  fi
  # 5. Frozen differential corpora through the installed kernel.
  ( cd "$d/cwd" && run_corpora "python-kernel-$label" "python-kernel-$EXP_KERNEL-$label" cenv ACTENON_ENV=test "$d/venv/bin/python" -I "$DIFF/runner_py.py" ) >> "$LOG" 2>&1 \
    && record "python-$label differential corpus run" PASS || record "python-$label differential corpus run" FAIL
  echo "$SITE" > "$W/site-$label"
}
py_consumer /root/.local/bin/python3.10 py310
py_consumer /usr/bin/python3.11 py311
py_consumer /usr/bin/python3.12 py312
SITE=$(cat "$W/site-py312"); VECTORS="$SITE/actenon/conformance/vectors/verifier_sdk_v1"; LOCK="$SITE/conformance/vector-lock.json"
log "vectors for other languages: $VECTORS (installed kernel wheel), lock: $LOCK sha256=$(sha "$LOCK")"

# ---------------------------------------------------------------- TypeScript (npm)
log "== typescript"
T="$W/ts"; mkdir -p "$T"
( cd "$T" && cenv npm init -y >/dev/null && echo "@actenon:registry=$REG/npm/" > .npmrc \
  && cenv npm install --no-audit --no-fund @actenon/verifier-sdk @actenon/sdk @actenon/protocol-types ) >> "$LOG" 2>&1
cp "$T/package-lock.json" "$OUT/npm-package-lock.json"
python3 - "$T" "$REL" "$REG" <<'EOF' | tee -a "$LOG"
import base64, hashlib, json, sys, pathlib
T, REL, reg = map(str, sys.argv[1:4]); lock = json.load(open(f"{T}/package-lock.json"))
want = {"@actenon/verifier-sdk": "0.2.0", "@actenon/sdk": "2.0.0", "@actenon/protocol-types": "1.4.0"}
art = {}
for t in pathlib.Path(REL, "npm").glob("*.tgz"):
    art["sha512-" + base64.b64encode(hashlib.sha512(t.read_bytes()).digest()).decode()] = t.name
bad = 0
for name, ver in want.items():
    e = lock["packages"].get(f"node_modules/{name}", {})
    ok = e.get("version") == ver and e.get("resolved", "").startswith(reg) and e.get("integrity") in art
    installed = json.load(open(f"{T}/node_modules/{name}/package.json"))["version"]
    ok = ok and installed == ver
    print(f"{'OK  ' if ok else 'FAIL'} {name} {e.get('version')} from {e.get('resolved')} = {art.get(e.get('integrity'))}"); bad += not ok
sys.exit(1 if bad else 0)
EOF
( cd "$T" && cenv node --input-type=module -e '
for (const [name, exps] of Object.entries({
  "@actenon/protocol-types": ["canonicalizeJson","canonicalizeBytes","CanonicalisationError","RefusalCode","refusalToDisclosedCode","resolveAlias","PROTOCOL_VERSION","isValidIdentifier","ExecutionMode","ExecutionOutcome"],
  "@actenon/sdk": ["Actenon","ExecutionRefusedError","canonicalizeJson","canonicalizeStrictJson","verifyResourceReceipt","encodeGrantToken","verifyGrantToken"],
  "@actenon/verifier-sdk": ["VerifierSDK","Ed25519Verifier","HmacSha256Verifier","buildLocalProofVerifier"] })) {
  const url = import.meta.resolve(name); if (!url.includes("/node_modules/")) throw new Error("not installed: " + url);
  const m = await import(name); const missing = exps.filter((k) => !(k in m));
  if (missing.length) throw new Error(name + " missing " + missing); console.log("import OK", name, url);
}' ) > "$OUT/ts-imports.txt" 2>&1 && record "typescript plain-node imports of all three packages" PASS || record "typescript plain-node imports" FAIL
( cd "$T" && cenv node "$HERE/harness/ts/check_ts_vectors.mjs" "$T" "$VECTORS" ) > "$OUT/ts-verifier-vectors.txt" 2>&1 \
  && record "typescript @actenon/verifier-sdk kernel vectors (cases+timestamps+edge+revocation)" PASS || record "typescript verifier vectors" FAIL
tail -1 "$OUT/ts-verifier-vectors.txt" | tee -a "$LOG"
cp "$HERE/harness/ts/protocol_canonicalisation.ts" "$T/"
( cd "$T" && cenv node --experimental-strip-types --no-warnings protocol_canonicalisation.ts "$W/protocol-tag/conformance/vectors/canonicalisation" ) > "$OUT/ts-protocol-canonicalisation.txt" 2>&1 \
  && record "typescript @actenon/protocol-types canonicalisation vectors" PASS || record "typescript protocol canonicalisation" FAIL
tail -2 "$OUT/ts-protocol-canonicalisation.txt" | tee -a "$LOG"
cp "$DIFF2/runner_ts_strict_eddsa.mjs" "$T/"
( cd "$T" && run_corpora ts-verifier-sdk "ts-verifier-sdk-$EXP_VSDK" cenv node runner_ts_strict_eddsa.mjs ) >> "$LOG" 2>&1 \
  && record "typescript differential corpus run" PASS || record "typescript differential corpus run" FAIL

# ---------------------------------------------------------------- Go (module proxy)
log "== go"
G="$W/go"; mkdir -p "$G"
( cd "$G" && cenv go mod init example.com/freshconsumer && cenv go get github.com/Actenon/sdk-go@v1.1.0 ) >> "$LOG" 2>&1
GOMOD_DIR=$(cd "$G" && cenv go list -m -f '{{.Dir}}' github.com/Actenon/sdk-go); GOMOD_VER=$(cd "$G" && cenv go list -m -f '{{.Version}}' github.com/Actenon/sdk-go)
ZIP="$W/gopath/pkg/mod/cache/download/github.com/!actenon/sdk-go/@v/v1.1.0.zip"
log "go module $GOMOD_VER at $GOMOD_DIR; downloaded zip sha256=$(sha "$ZIP") (artefact $(sha "$REL/goproxy/github.com/!actenon/sdk-go/@v/v1.1.0.zip"))"
[ "$GOMOD_VER" = "$EXP_GO" ] && [ "$(sha "$ZIP")" = "$(sha "$REL/goproxy/github.com/!actenon/sdk-go/@v/v1.1.0.zip")" ] && case "$GOMOD_DIR" in "$W"/gopath/pkg/mod/*) true;; *) false;; esac \
  && record "go module provenance (v1.1.0 zip digest = artefact, module cache path)" PASS || record "go module provenance" FAIL
grep 'Actenon/sdk-go' "$G/go.sum" | tee -a "$LOG" > "$OUT/go.sum.sdk-go"
cp "$HERE"/harness/go/*_test.go "$G/"
( cd "$G" && cenv ACTENON_VECTORS="$VECTORS" go test -count=1 -v ./... ) > "$OUT/go-consumer-vectors.txt" 2>&1 \
  && record "go consumer: kernel vectors from installed wheel via public API" PASS || record "go consumer vectors" FAIL
grep -E '^(ok|FAIL|---)' "$OUT/go-consumer-vectors.txt" | tail -5 | tee -a "$LOG"
( cd "$G" && cenv ACTENON_KERNEL_VECTOR_LOCK="$LOCK" go test -count=1 github.com/Actenon/sdk-go/... ) > "$OUT/go-module-own-tests.txt" 2>&1 \
  && record "go module's own test suite from the module cache (lock = installed wheel)" PASS || record "go module own tests" FAIL
tail -3 "$OUT/go-module-own-tests.txt" | tee -a "$LOG"
for variant in strict usenumber; do
  R="$W/go-runner-$variant"; mkdir -p "$R"
  src="$DIFF/runner_go"; [ $variant = usenumber ] && src="$DIFF2/runner_go_usenumber"
  cp "$src"/*.go "$R/"
  ( cd "$R" && cenv go mod init example.com/runner && cenv go get github.com/Actenon/sdk-go@v1.1.0 && cenv go build -tags ed25519 -o runner . \
    && run_corpora "go-sdk-$variant" "go-sdk-$EXP_GO-$variant" ./runner ) >> "$LOG" 2>&1 \
    && record "go differential corpus run ($variant)" PASS || record "go differential corpus run ($variant)" FAIL
done

# ---------------------------------------------------------------- Rust (sparse registry)
log "== rust"
cargo_cfg() { mkdir -p "$1/.cargo"; cat > "$1/.cargo/config.toml" <<EOF
# Rehearsal only: resolve actenon-verifier-sdk from the rehearsal registry instead of crates.io.
# The consumer's Cargo.toml is the documented one (actenon-verifier-sdk = "0.2").
[registries.actenon-rehearsal]
index = "sparse+$REG/cargo/index/"
[patch.crates-io]
actenon-verifier-sdk = { version = "=$EXP_CRATE", registry = "actenon-rehearsal" }
EOF
}
RC="$W/rust"; cp -r "$HERE/harness/rust" "$RC"; cargo_cfg "$RC"
( cd "$RC" && cenv cargo generate-lockfile && cenv cargo metadata --format-version 1 > "$W/rust-metadata.json" ) >> "$LOG" 2>&1
python3 - "$W/rust-metadata.json" "$RC/Cargo.lock" "$REL/crates/actenon-verifier-sdk-$EXP_CRATE.crate" "$W/cargo-home" <<'EOF' | tee -a "$LOG"
import hashlib, json, sys, tomllib
meta, lock = json.load(open(sys.argv[1])), tomllib.load(open(sys.argv[2], "rb"))
art = hashlib.sha256(open(sys.argv[3], "rb").read()).hexdigest()
pkg = next(p for p in meta["packages"] if p["name"] == "actenon-verifier-sdk")
lk = next(p for p in lock["package"] if p["name"] == "actenon-verifier-sdk")
ok = pkg["version"] == "0.2.0" and pkg["manifest_path"].startswith(sys.argv[4]) and lk["checksum"] == art and "127.0.0.1" in lk["source"]
print(f"{'OK  ' if ok else 'FAIL'} actenon-verifier-sdk {pkg['version']} source={lk['source']} checksum={lk['checksum']} artefact={art} manifest={pkg['manifest_path']}")
sys.exit(0 if ok else 1)
EOF
[ "${PIPESTATUS[0]}" = 0 ] && record "rust crate provenance (Cargo.lock checksum = artefact, registry source)" PASS || record "rust crate provenance" FAIL
cp "$RC/Cargo.lock" "$OUT/rust-consumer-Cargo.lock"
( cd "$RC" && cenv ACTENON_VECTORS="$VECTORS" cargo test -q && cenv ACTENON_VECTORS="$VECTORS" cargo run -q ) > "$OUT/rust-consumer-vectors.txt" 2>&1 \
  && record "rust consumer: kernel vectors from installed wheel via public API" PASS || record "rust consumer vectors" FAIL
tail -4 "$OUT/rust-consumer-vectors.txt" | tee -a "$LOG"
CSRC=$(ls -d "$W"/cargo-home/registry/src/*/actenon-verifier-sdk-$EXP_CRATE); cp -r "$CSRC" "$W/crate-src"
( cd "$W/crate-src" && cenv ACTENON_KERNEL_VECTOR_LOCK="$LOCK" cargo test --locked -q ) > "$OUT/rust-crate-own-tests.txt" 2>&1 \
  && record "rust crate's own test suite from the downloaded .crate (lock = installed wheel)" PASS || record "rust crate own tests" FAIL
RR="$W/rust-runner"; mkdir -p "$RR/src"; cp "$DIFF/runner_rust/src/main.rs" "$RR/src/"; cargo_cfg "$RR"
cat > "$RR/Cargo.toml" <<EOF
[package]
name = "diff-runner"
version = "0.0.0"
edition = "2021"
publish = false
[dependencies]
actenon-verifier-sdk = "0.2"
serde_json = "1"
time = { version = "0.3", features = ["formatting", "parsing"] }
# The runner gates its Ed25519 path on this feature (as runner_go uses -tags ed25519); 0.2.0 has Ed25519Verifier.
[features]
ed25519 = []
EOF
( cd "$RR" && cenv cargo build -q --release --features ed25519 && run_corpora rust-sdk "rust-sdk-$EXP_CRATE" ./target/release/diff-runner ) >> "$LOG" 2>&1 \
  && record "rust differential corpus run" PASS || record "rust differential corpus run" FAIL

# ---------------------------------------------------------------- source-tree absence (whole run)
if grep -rl '/home/user/' "$W/gopath/pkg/mod/cache/download" "$W/cargo-home/registry/index" "$T/package-lock.json" 2>/dev/null | head -1 | grep -q .; then
  record "no /home/user source path in any resolver state" FAIL
else record "no /home/user source path in any resolver state" PASS; fi
log "registry requests served: $(wc -l < "$OUT/registry-access.log")"
FAILS=$(awk -F'\t' 'NR>1 && $2!="PASS" && $2 !~ /^N\/A/' "$RESULTS" | wc -l)
log "fresh-consumer steps: $(($(wc -l < "$RESULTS")-1)), failures: $FAILS"
exit $((FAILS > 0))
