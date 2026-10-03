#!/usr/bin/env bash
# Build every RELEASE-VERSIONED artefact from exact commits (git archive exports;
# fresh venvs; frozen JS lockfiles). usage: build_release_artefacts.sh OUT WORK
# The only non-committed input is the Permit 2.0.0 release-preparation patch
# (permit-release-prep-v4.patch; v1 missed three stale README/CHANGELOG lines, v2 and v3 predate the kernel pin moves to 8c5c25e and b1b175d), which cannot be committed before actenon-kernel
# 1.3.0 exists on PyPI (its uv.lock must be regenerated against PyPI then).
set -euo pipefail
OUT=${1:?out}; WORK=${2:?work}; HERE=$(cd "$(dirname "$0")" && pwd)
# Rehearsal 1 used PROTOCOL=ed8904d KERNEL=088f9e3 SDKGO=2139da9 SDKRS=384cc00 PERMIT=e348c18 + permit-release-prep-v1.patch.
PROTOCOL=${PROTOCOL:-e988c4d}; KERNEL=${KERNEL:-185e0fd}; SDKGO=${SDKGO:-0198ef5}; SDKRS=${SDKRS:-c149ab6}; PERMIT=${PERMIT:-a0d2b8d}
PERMIT_PATCH=${PERMIT_PATCH:-permit-release-prep-v4.patch}
GOMODZIP=${GOMODZIP:?path to gomodzip binary}
rm -rf "${WORK:?}"; mkdir -p "$WORK" "$OUT/pypi" "$OUT/npm" "$OUT/goproxy" "$OUT/crates"
x() { mkdir -p "$WORK/$2"; git -C "/home/user/$1" archive --format=tar "$3" | tar -x -C "$WORK/$2"; echo "$1 $(git -C "/home/user/$1" rev-parse "$3")" >> "$OUT/SOURCE_COMMITS"; }
: > "$OUT/SOURCE_COMMITS"
python3 -m venv "$WORK/vb"; "$WORK/vb/bin/pip" -q install --upgrade pip build
pybuild() { (cd "$WORK/$1" && SOURCE_DATE_EPOCH=$2 "$WORK/vb/bin/python" -m build -q --outdir "$OUT/pypi" . >/dev/null); }
epoch() { git -C "/home/user/$1" log -1 --format=%ct "$2"; }

x actenon-protocol protocol $PROTOCOL
pybuild protocol "$(epoch actenon-protocol $PROTOCOL)"
(cd "$WORK/protocol/typescript" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null && npm pack --pack-destination "$OUT/npm" >/dev/null)

x actenon-kernel kernel $KERNEL
pybuild kernel "$(epoch actenon-kernel $KERNEL)"
(cd "$WORK/kernel/sdk/typescript" && npm ci --no-audit --no-fund >/dev/null && npm pack --pack-destination "$OUT/npm" >/dev/null)

x sdk-go sdkgo $SDKGO
"$GOMODZIP" github.com/Actenon/sdk-go v1.1.0 "$WORK/sdkgo" "$OUT/goproxy" >/dev/null

git clone -q /home/user/sdk-rust "$WORK/sdkrs" && git -C "$WORK/sdkrs" checkout -q $SDKRS
echo "sdk-rust $(git -C "$WORK/sdkrs" rev-parse HEAD)" >> "$OUT/SOURCE_COMMITS"
(cd "$WORK/sdkrs" && CARGO_TARGET_DIR="$WORK/rt" cargo package --locked -q && cp "$WORK"/rt/package/*.crate "$OUT/crates/")

x actenon-permit permit $PERMIT
(cd "$WORK/permit" && patch -p1 -s < "$HERE/$PERMIT_PATCH")
pybuild permit "$(epoch actenon-permit $PERMIT)"
(cd "$WORK/permit/ts-sdk" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null && npm pack --pack-destination "$OUT/npm" >/dev/null)

(cd "$OUT" && find pypi npm goproxy crates -type f | sort | xargs sha256sum > SHA256SUMS)
cat "$OUT/SHA256SUMS"
