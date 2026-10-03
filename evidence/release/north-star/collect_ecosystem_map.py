"""Collect ECOSYSTEM-MAP.json from local clones and public registries (read-only).
usage: python3 collect_ecosystem_map.py OUT.json"""
import json, subprocess, sys, urllib.request
from pathlib import Path
import yaml

def sh(args, cwd=None):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    return r.stdout.strip()

def http_json(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "actenon-north-star-map"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        return {"_error": str(exc)}

REPOS = {
    "actenon-protocol": {"path": "/home/user/actenon-protocol", "candidate": "45b7753", "intended": "1.4.0",
        "dists": {"pypi": ["actenon-protocol"], "npm": ["@actenon/protocol-types", "@actenon/protocol"]},
        "actenon_deps": [], "runtime_role": "wire contract: canonicalisation, refusal catalogue, schemas, protocol docs (13 edge binding)",
        "release_role": "step 1 (parallel with kernel)", "gate_critical": ["G1", "G2", "G4"]},
    "actenon-kernel": {"path": "/home/user/actenon-kernel", "candidate": "142364f", "code_commit": "6d6c630", "intended": "1.3.0 (+ @actenon/verifier-sdk 0.2.0)",
        "dists": {"pypi": ["actenon-kernel"], "npm": ["@actenon/verifier-sdk"], "mcp_registry": ["io.github.Actenon/kernel"]},
        "actenon_deps": ["actenon-protocol>=1.1.0,<2"], "runtime_role": "reference verifier + protected executor (single use, replay store, edge binding, revocation); TS verifier SDK",
        "release_role": "step 2 — security floor for everything downstream", "gate_critical": ["G1", "G2", "G3", "G4", "G5", "G6"]},
    "sdk-go": {"path": "/home/user/sdk-go", "candidate": "e3649cd", "intended": "v1.1.0",
        "dists": {"go": ["github.com/Actenon/sdk-go"]}, "actenon_deps": ["vendored kernel vectors (fixtures/KERNEL_PIN)"],
        "runtime_role": "Go verifier SDK (verify only; integrator enforces single use)", "release_role": "step 3 (after kernel release)", "gate_critical": ["G1", "G2", "G4", "G5"]},
    "sdk-rust": {"path": "/home/user/sdk-rust", "candidate": "0a16a84", "intended": "0.2.0",
        "dists": {"crates": ["actenon-verifier-sdk"]}, "actenon_deps": ["vendored kernel vectors (fixtures/KERNEL_PIN)"],
        "runtime_role": "Rust verifier SDK (verify only)", "release_role": "step 3 (after kernel release)", "gate_critical": ["G1", "G2", "G4", "G5"]},
    "actenon-permit": {"path": "/home/user/actenon-permit", "candidate": "a5467ab", "intended": "2.0.0 (+ @actenon/sdk 2.0.0)",
        "dists": {"pypi": ["actenon-permit"], "npm": ["@actenon/sdk"]}, "actenon_deps": ["actenon-kernel[asymmetric]>=1.3.0rc1,<2", "actenon-protocol>=1.1.0,<2"],
        "runtime_role": "authority broker: grants, PDP, Ed25519 proof minting, gateway, revocation source", "release_role": "step 4 (after kernel on PyPI)", "gate_critical": ["G1", "G2", "G3", "G4", "G6"]},
    "blastradius": {"path": "/home/user/blastradius", "candidate": "d7f60a6", "intended": "0.5.0",
        "dists": {"pypi": ["actenon-blastradius"]}, "actenon_deps": [],
        "runtime_role": "independent shell-command guard (no Actenon runtime dependency)", "release_role": "step 5 (independent)", "gate_critical": ["G2 (own CI)"]},
    ".github": {"path": "/home/user/dotgithub", "candidate": None, "intended": None, "dists": {}, "actenon_deps": [],
        "runtime_role": "org profile / community health files", "release_role": "none (documentation claims only)", "gate_critical": ["G4 (public claims)"]},
}

def workflows(path):
    out = []
    for f in sorted(Path(path, ".github/workflows").glob("*.y*ml")):
        try:
            d = yaml.safe_load(f.read_text())
        except Exception as exc:
            out.append({"file": f.name, "error": str(exc)}); continue
        on = d.get(True, d.get("on"))
        triggers = list(on) if isinstance(on, dict) else ([on] if isinstance(on, str) else on)
        jobs = {}
        for jid, j in (d.get("jobs") or {}).items():
            jobs[jid] = {"name": j.get("name", jid), "needs": j.get("needs"), "if": j.get("if"),
                         "environment": j.get("environment"), "matrix": (j.get("strategy") or {}).get("matrix")}
        text = f.read_text()
        publishes = any(k in text for k in ("pypa/gh-action-pypi-publish", "npm publish", "cargo publish", "twine upload", "mcp-publisher", "publish-mcp"))
        out.append({"file": f.name, "name": d.get("name"), "triggers": triggers,
                    "trigger_detail": on if isinstance(on, dict) else None, "jobs": jobs, "publishes": publishes,
                    "workflow_run_gate": "workflow_run" in (triggers or [])})
    return out

def registry(dists):
    res = {}
    for name in dists.get("pypi", []):
        d = http_json(f"https://pypi.org/pypi/{name}/json")
        res[f"pypi:{name}"] = d.get("info", {}).get("version") if "_error" not in d else d["_error"]
    for name in dists.get("npm", []):
        d = http_json(f"https://registry.npmjs.org/{name.replace('/', '%2f')}")
        res[f"npm:{name}"] = (d.get("dist-tags") or {}).get("latest") if "_error" not in d else "not published (" + d["_error"] + ")"
    for name in dists.get("go", []):
        d = http_json(f"https://proxy.golang.org/{name.replace('Actenon', '!actenon')}/@latest")
        res[f"go:{name}"] = d.get("Version") if "_error" not in d else d["_error"]
    for name in dists.get("crates", []):
        d = http_json(f"https://crates.io/api/v1/crates/{name}")
        res[f"crates:{name}"] = (d.get("crate") or {}).get("max_version") if "_error" not in d else "not published (" + d["_error"] + ")"
    return res

result = {"generated_by": "collect_ecosystem_map.py", "repos": {}}
for name, meta in REPOS.items():
    p = meta["path"]
    cand = meta.get("candidate")
    entry = dict(meta)
    entry.update({
        "remote": sh(["git", "remote", "get-url", "origin"], p),
        "branch": sh(["git", "rev-parse", "--abbrev-ref", "HEAD"], p),
        "head": sh(["git", "rev-parse", "HEAD"], p),
        "candidate_full": sh(["git", "rev-parse", "--verify", "--quiet", f"{cand}^{{commit}}"], p) if cand else None,
        "candidate_on_remote_branches": sh(["git", "branch", "-r", "--contains", cand], p).split() if cand else [],
        "origin_main": sh(["git", "rev-parse", "origin/main"], p),
        "dirty_tracked_files": len([l for l in sh(["git", "status", "--porcelain"], p).splitlines() if not l.startswith("??")]),
        "latest_tags": sh(["git", "tag", "--sort=-creatordate"], p).splitlines()[:5],
        "workflows": workflows(p),
        "published": registry(meta["dists"]),
    })
    result["repos"][name] = entry
result["out_of_scope"] = {
    "actenon-scan": "CI-time dependency only (kernel/permit/protocol/sdk-go run actenon-scan.yml); dev-only dep on actenon-protocol; NOT modified (standing instruction from phase 1)",
    "actenon-cloud": "private, optional managed control plane; not a dependency of any public component; no private data recorded here",
}
Path(sys.argv[1]).write_text(json.dumps(result, indent=2, sort_keys=False) + "\n")
print("repos:", ", ".join(result["repos"]))
