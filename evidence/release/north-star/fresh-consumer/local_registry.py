#!/usr/bin/env python3
"""Rehearsal registry: serves the release artefacts in ARTEFACT_DIR over the wire protocols the
real registries speak, so a consumer installs them with its normal tool and an unmodified
dependency declaration.

  pip    PEP 503 simple index      http://127.0.0.1:PORT/pypi/simple/<name>/
  npm    packument + tarball       http://127.0.0.1:PORT/npm/<@scope%2fname>
  cargo  sparse index + download   sparse+http://127.0.0.1:PORT/cargo/index/
  (Go needs no server: GOPROXY=file://ARTEFACT_DIR/goproxy)

Only the artefacts in ARTEFACT_DIR are served; every other package is a 404 here, so the
consumer resolves it from the public registry. Nothing is built or rewritten: each served file
is the artefact byte-for-byte and its digest is the one in ARTEFACT_DIR/SHA256SUMS.

usage: local_registry.py ARTEFACT_DIR PORT
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import tarfile
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(sys.argv[1]).resolve()
PORT = int(sys.argv[2])
BASE = f"http://127.0.0.1:{PORT}"
CRATES_IO = "https://github.com/rust-lang/crates.io-index"


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_files() -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for f in sorted((ROOT / "pypi").iterdir()):
        dist = f.name.split("-")[0]
        out.setdefault(norm(dist), []).append(f)
    return out


def npm_packuments() -> dict[str, dict]:
    docs: dict[str, dict] = {}
    for t in sorted((ROOT / "npm").glob("*.tgz")):
        raw = t.read_bytes()
        with tarfile.open(t) as tf:
            pj = json.loads(tf.extractfile("package/package.json").read())
        doc = docs.setdefault(pj["name"], {"name": pj["name"], "dist-tags": {}, "versions": {}})
        doc["versions"][pj["version"]] = dict(pj, dist={
            "tarball": f"{BASE}/npm/-/{t.name}",
            "shasum": hashlib.sha1(raw).hexdigest(),
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode(),
        })
        doc["dist-tags"]["latest"] = pj["version"]
    return docs


def cargo_index() -> dict[str, tuple[str, Path]]:
    """index path -> (index line, .crate file)"""
    out: dict[str, tuple[str, Path]] = {}
    for c in sorted((ROOT / "crates").glob("*.crate")):
        with tarfile.open(c) as tf:
            toml_member = next(m for m in tf.getmembers() if m.name.count("/") == 1 and m.name.endswith("/Cargo.toml"))
            ct = tomllib.loads(tf.extractfile(toml_member).read().decode())
        pkg = ct["package"]
        deps = []
        for kind, key in (("normal", "dependencies"), ("dev", "dev-dependencies"), ("build", "build-dependencies")):
            tables = [(None, ct.get(key, {}))] + [(t, v.get(key, {})) for t, v in ct.get("target", {}).items()]
            for target, table in tables:
                for name, spec in table.items():
                    spec = {"version": spec} if isinstance(spec, str) else spec
                    entry = {
                        "name": spec.get("package", name), "req": spec.get("version", "*"),
                        "features": spec.get("features", []), "optional": spec.get("optional", False),
                        "default_features": spec.get("default-features", spec.get("default_features", True)),
                        "target": target, "kind": kind, "registry": CRATES_IO,
                    }
                    if "package" in spec:
                        entry["package"] = spec["package"]
                        entry["name"] = name
                    deps.append(entry)
        line = json.dumps({
            "name": pkg["name"], "vers": pkg["version"], "deps": deps,
            "cksum": hashlib.sha256(c.read_bytes()).hexdigest(),
            "features": ct.get("features", {}), "yanked": False,
            "rust_version": pkg.get("rust-version"),
        }, separators=(",", ":"))
        n = pkg["name"].lower()
        path = {1: f"1/{n}", 2: f"2/{n}", 3: f"3/{n[0]}/{n}"}.get(len(n), f"{n[:2]}/{n[2:4]}/{n}")
        prev = out.get(path, ("", c))[0]
        out[path] = ((prev + "\n" if prev else "") + line, c)
    return out


PYPI, NPM, CARGO = pypi_files(), npm_packuments(), cargo_index()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # one line per request on stderr, for the evidence log
        sys.stderr.write("registry %s %s\n" % (self.command, self.path))

    def send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        p = unquote(self.path.split("?")[0])
        if p.startswith("/pypi/simple/"):
            name = norm(p[len("/pypi/simple/"):].strip("/"))
            files = PYPI.get(name)
            if not files:
                return self.send(404, b"not here", "text/plain")
            links = "".join(
                f'<a href="{BASE}/pypi/files/{f.name}#sha256={hashlib.sha256(f.read_bytes()).hexdigest()}">{f.name}</a><br/>'
                for f in files)
            return self.send(200, f"<!DOCTYPE html><html><body>{links}</body></html>".encode(), "text/html")
        if p.startswith("/pypi/files/"):
            f = ROOT / "pypi" / Path(p).name
            return self.send(200, f.read_bytes(), "application/octet-stream") if f.is_file() else self.send(404, b"", "text/plain")
        if p.startswith("/npm/-/"):
            f = ROOT / "npm" / Path(p).name
            return self.send(200, f.read_bytes(), "application/octet-stream") if f.is_file() else self.send(404, b"", "text/plain")
        if p.startswith("/npm/"):
            doc = NPM.get(p[len("/npm/"):])
            return self.send(200, json.dumps(doc).encode(), "application/json") if doc else self.send(404, b"{}", "application/json")
        if p == "/cargo/index/config.json":
            cfg = {"dl": f"{BASE}/cargo/dl/{{crate}}/{{version}}/download", "api": None}
            return self.send(200, json.dumps(cfg).encode(), "application/json")
        if p.startswith("/cargo/index/"):
            hit = CARGO.get(p[len("/cargo/index/"):])
            return self.send(200, hit[0].encode() + b"\n", "text/plain") if hit else self.send(404, b"", "text/plain")
        if p.startswith("/cargo/dl/"):
            _, _, _, crate, version, _ = p.split("/")
            f = ROOT / "crates" / f"{crate}-{version}.crate"
            return self.send(200, f.read_bytes(), "application/octet-stream") if f.is_file() else self.send(404, b"", "text/plain")
        return self.send(404, b"", "text/plain")


if __name__ == "__main__":
    sys.stderr.write(f"rehearsal registry on {BASE}: pypi={sorted(PYPI)} npm={sorted(NPM)} cargo={sorted(CARGO)}\n")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
