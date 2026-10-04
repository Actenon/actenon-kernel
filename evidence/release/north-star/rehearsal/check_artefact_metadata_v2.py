"""ARTEFACT-METADATA-CHECK v2 (criteria fixed after v1's two documented defects; see
ARTEFACT-METADATA-CHECK-v1-DEFECTS.md). v2.1 adds one criterion: the kernel wheel declares Conformance 1.1.0.
usage: check_artefact_metadata_v2.py ARTEFACT_DIR"""
import glob, json, sys, tarfile, tomllib, zipfile
from pathlib import Path
REL = Path(sys.argv[1]); ok = True
def check(c, m):
    global ok; print(("PASS " if c else "FAIL ") + m); ok &= bool(c)
for w in sorted(REL.glob("pypi/*.whl")):
    z = zipfile.ZipFile(w); names = z.namelist()
    meta = z.read([n for n in names if n.endswith(".dist-info/METADATA")][0]).decode().splitlines()
    rd = [l for l in meta if l.startswith("Requires-Dist")]; ver = [l for l in meta if l.startswith("Version:")][0]
    check(not any(" @ " in l or "file:" in l for l in rd), f"{w.name}: no direct references in Requires-Dist")
    check(not any(n.startswith(("tests/", "evidence/")) for n in names), f"{w.name}: no tests/ or evidence/ at wheel root")
    if "kernel" in w.name:
        check(ver == "Version: 1.3.0", "kernel 1.3.0")
        check("actenon/scanner_capability_registry.v1.json" in names, "kernel ships scanner registry")
        check("actenon/conformance/vectors/verifier_sdk_v1/edge_binding_cases.json" in names, "kernel ships edge-binding vectors")
        check(any("actenon-protocol<2,>=1.1.0" in l for l in rd), "kernel requires actenon-protocol>=1.1.0,<2")
        check(b'CONFORMANCE_VERSION = "1.1.0"' in z.read("actenon/conformance/version.py"), "kernel declares Conformance 1.1.0")
        check(json.loads(z.read("conformance/vector-lock.json"))["conformance_version"] == "1.1.0", "kernel vector lock is Conformance 1.1.0")
    if "protocol" in w.name:
        check(ver == "Version: 1.4.0", "protocol 1.4.0")
        check(all(f"actenon_protocol/data/{s}" in names for s in ("execution_result.v1.json", "boundary_manifest.v1.json")), "protocol ships every schema")
    if "permit" in w.name:
        check(ver == "Version: 2.0.0", "permit 2.0.0")
        check(any("actenon-kernel[asymmetric]<2,>=1.3.0" in l for l in rd), "permit requires actenon-kernel[asymmetric]>=1.3.0,<2")
for t in sorted(REL.glob("npm/*.tgz")):
    tf = tarfile.open(t); pj = json.loads(tf.extractfile("package/package.json").read())
    exp = {"@actenon/protocol-types": "1.4.0", "@actenon/verifier-sdk": "0.2.0", "@actenon/sdk": "2.0.0"}[pj["name"]]
    check(pj["version"] == exp, f"{pj['name']} {exp}")
    allv = list((pj.get("dependencies") or {}).values()) + list((pj.get("peerDependencies") or {}).values())
    check(not any(str(v).startswith(("file:", "git", "link:", "workspace:")) for v in allv), f"{pj['name']}: registry-resolvable deps")
    check(any(n.startswith("package/dist/") for n in tf.getnames()), f"{pj['name']}: ships dist/")
tf = tarfile.open(REL / "crates/actenon-verifier-sdk-0.2.0.crate")
ct = tomllib.loads(tf.extractfile("actenon-verifier-sdk-0.2.0/Cargo.toml").read().decode())
check(ct["package"]["version"] == "0.2.0", "crate 0.2.0")
tabs = [ct.get(k, {}) for k in ("dependencies", "dev-dependencies", "build-dependencies")] + [v.get(k, {}) for v in ct.get("target", {}).values() for k in ("dependencies", "dev-dependencies", "build-dependencies")]
bad = [(n, d) for tab in tabs for n, d in tab.items() if isinstance(d, dict) and ("git" in d or "path" in d)]
check(not bad, f"crate dependency tables have no git/path sources {bad}")
lock = json.loads(tf.extractfile("actenon-verifier-sdk-0.2.0/fixtures/kernel_vector_lock.json").read())
check(lock["conformance_version"] == "1.1.0", "crate vendors the Conformance 1.1.0 kernel lock")
z = zipfile.ZipFile(REL / "goproxy/github.com/!actenon/sdk-go/@v/v1.1.0.zip"); n = z.namelist()
check(all(x.startswith("github.com/Actenon/sdk-go@v1.1.0/") for x in n), "go zip entries use module@version prefix (spec)")
check(json.loads(z.read("github.com/Actenon/sdk-go@v1.1.0/fixtures/kernel_vector_lock.json"))["conformance_version"] == "1.1.0", "go module vendors the Conformance 1.1.0 kernel lock")
check(z.read("github.com/Actenon/sdk-go@v1.1.0/go.mod") == (REL / "goproxy/github.com/!actenon/sdk-go/@v/v1.1.0.mod").read_bytes(), ".mod equals go.mod inside zip")
print("ALL PASS" if ok else "FAILURES PRESENT"); sys.exit(0 if ok else 1)
