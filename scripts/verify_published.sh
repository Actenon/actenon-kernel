#!/usr/bin/env bash
# Check a PUBLISHED artefact against THIS checkout's conformance vectors.
# usage: scripts/verify_published.sh python|ts|go|rust [SOURCE]
#   SOURCE (optional) overrides the registry: a wheel path (python), a .tgz (ts),
#   a module version (go, default: latest), a .crate path (rust).
# Runs in a temp dir with a fresh environment. Exit 0 only if the artefact passes.
set -euo pipefail
mode=${1:?python|ts|go|rust}; src=${2:-}
here=$(cd "$(dirname "$0")/.." && pwd); tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
vectors="$here/actenon/conformance/vectors/verifier_sdk_v1"
case "$mode" in
python)
  python3 -m venv "$tmp/venv"; "$tmp/venv/bin/pip" -q install --upgrade pip
  "$tmp/venv/bin/pip" -q install pytest "${src:-actenon-kernel}"
  mkdir -p "$tmp/t/vectors" && cp "$here/actenon/conformance/test_verifier_sdk_conformance.py" "$tmp/t/" && cp -r "$vectors" "$tmp/t/vectors/"
  cd "$tmp/t"
  "$tmp/venv/bin/python" -c 'import actenon, importlib.metadata as m; assert "site-packages" in actenon.__file__; print("actenon-kernel", m.version("actenon-kernel"))'
  ACTENON_ENV=test "$tmp/venv/bin/python" -m pytest -q -p no:cacheprovider test_verifier_sdk_conformance.py
  mkdir -p scan && printf 'def refund(amount):\n    return stripe.Refund.create(amount=amount)\n' > scan/app.py
  set +e; "$tmp/venv/bin/actenon-kernel" scan repo --path scan > scan.txt 2>&1; set -e
  grep -q '^Overall status: EXECUTION_GAP_PRESENT' scan.txt && ! grep -q '^ERROR:' scan.txt || { cat scan.txt; echo "FAIL: actenon-kernel scan from the installed wheel"; exit 1; }
  ;;
ts)
  cd "$tmp" && npm init -y >/dev/null && npm install --no-audit --no-fund "${src:-@actenon/verifier-sdk@latest}" >/dev/null
  node "$here/scripts/check_published_ts_verifier.mjs" "$tmp"
  ;;
go)
  cd "$tmp" && printf 'module verifypublished\n\ngo 1.22\n' > go.mod
  GOFLAGS=-mod=mod go get "github.com/Actenon/sdk-go@${src:-latest}"
  go list -m github.com/Actenon/sdk-go
  ACTENON_KERNEL_VECTOR_LOCK="$here/conformance/vector-lock.json" go test -count=1 github.com/Actenon/sdk-go/verifier
  ;;
rust)
  crate=$src
  if [ -z "$crate" ]; then
    version=$(curl -fsSL -A "actenon-verify-published" https://crates.io/api/v1/crates/actenon-verifier-sdk | python3 -c 'import json,sys;print(json.load(sys.stdin)["crate"]["max_version"])') \
      || { echo "FAIL: actenon-verifier-sdk is not published on crates.io"; exit 1; }
    curl -fsSL -A "actenon-verify-published" -o "$tmp/sdk.crate" "https://crates.io/api/v1/crates/actenon-verifier-sdk/$version/download"; crate="$tmp/sdk.crate"
  fi
  mkdir -p "$tmp/c" && tar -xzf "$crate" -C "$tmp/c" && cd "$tmp/c"/*/
  ACTENON_KERNEL_VECTOR_LOCK="$here/conformance/vector-lock.json" cargo test --locked --all-targets -q
  ;;
*) echo "unknown mode $mode"; exit 2 ;;
esac
echo "PASS: published $mode artefact${src:+ ($src)} conforms to this checkout's vectors"
