#!/usr/bin/env bash
# (copied to artefacts-78efcf1/ from evidence/release/phase2/artefacts/build.sh) Build every phase-2 candidate artefact from an exact commit, in a clean
# export (git archive: tracked files only), with fresh virtualenvs and empty
# package caches. Usage: build.sh <outdir> <workdir>
# Repos are read from local clones; commits are fixed below.
set -euo pipefail
OUT=${1:?outdir}; WORK=${2:?workdir}
KERNEL_REPO=/home/user/actenon-kernel;  KERNEL_COMMIT=78efcf173d6e658eee8de4ea5732f551c6822f3f
PERMIT_REPO=/home/user/actenon-permit;  PERMIT_COMMIT=30c1d4f
SDKGO_REPO=/home/user/sdk-go;           SDKGO_COMMIT=67615be
SDKRS_REPO=/home/user/sdk-rust;         SDKRS_COMMIT=7f10d50
mkdir -p "$OUT"; rm -rf "${WORK:?}"; mkdir -p "$WORK"
export_src(){ mkdir -p "$WORK/$2"; git -C "$1" archive --format=tar "$3" | tar -x -C "$WORK/$2"; }
full(){ git -C "$1" rev-parse "$2"; }
: > "$OUT/SOURCE_COMMITS"
for pair in "actenon-kernel $KERNEL_REPO $KERNEL_COMMIT" "actenon-permit $PERMIT_REPO $PERMIT_COMMIT" \
            "sdk-go $SDKGO_REPO $SDKGO_COMMIT" "sdk-rust $SDKRS_REPO $SDKRS_COMMIT"; do
  set -- $pair; echo "$1 $(full "$2" "$3")" >> "$OUT/SOURCE_COMMITS"
done

echo "== actenon-kernel wheel + sdist"
export_src "$KERNEL_REPO" kernel "$KERNEL_COMMIT"
python3 -m venv "$WORK/venv-build"; "$WORK/venv-build/bin/pip" -q install --upgrade pip build
"$WORK/venv-build/bin/python" -m build --outdir "$OUT" "$WORK/kernel" >/dev/null

echo "== @actenon/verifier-sdk tarball"
( cd "$WORK/kernel/sdk/typescript" && npm ci --no-audit --no-fund >/dev/null && npm pack --pack-destination "$OUT" >/dev/null )

echo "== actenon-permit wheel + sdist"
export_src "$PERMIT_REPO" permit "$PERMIT_COMMIT"
"$WORK/venv-build/bin/python" -m build --outdir "$OUT" "$WORK/permit" >/dev/null

echo "== @actenon/sdk tarball"
( cd "$WORK/permit/ts-sdk" && bun install --frozen-lockfile >/dev/null && npm pack --pack-destination "$OUT" >/dev/null )

echo "== sdk-go module zip (go mod download of the exact commit)"
( export GOPATH="$WORK/gopath" GOMODCACHE="$WORK/gopath/pkg/mod" GOCACHE="$WORK/gocache" GOPROXY=direct GONOSUMDB='github.com/Actenon/*' GOFLAGS=-modcacherw
  info=$(go mod download -json "github.com/Actenon/sdk-go@$(full "$SDKGO_REPO" "$SDKGO_COMMIT")")
  zip=$(printf '%s' "$info" | python3 -c 'import json,sys;print(json.load(sys.stdin)["Zip"])')
  ver=$(printf '%s' "$info" | python3 -c 'import json,sys;print(json.load(sys.stdin)["Version"])')
  cp "$zip" "$OUT/sdk-go-$ver.zip" )

echo "== sdk-rust crate (cargo package at the exact commit)"
git clone -q "$SDKRS_REPO" "$WORK/sdk-rust" && git -C "$WORK/sdk-rust" checkout -q "$SDKRS_COMMIT"
( cd "$WORK/sdk-rust" && CARGO_TARGET_DIR="$WORK/rust-target" cargo package --locked -q )
for c in "$WORK"/rust-target/package/*.crate; do cp "$c" "$OUT/$(basename "${c%.crate}")-$(git -C "$WORK/sdk-rust" rev-parse --short HEAD).crate"; done

( cd "$OUT" && sha256sum -- *.whl *.tar.gz *.tgz *.zip *.crate > SHA256SUMS )
cat "$OUT/SHA256SUMS"
